// Package alert monitors traffic counters against configured thresholds and emits
// warnings, stats summaries, and bandwidth-map metric updates at configurable intervals.
package alert

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"hotspotd/internal/account"
	"hotspotd/internal/classify"
	"hotspotd/internal/config"
	"hotspotd/internal/identity"
	"hotspotd/internal/sniffer"
)

// Monitor watches traffic counters and emits alerts/stats.
type Monitor struct {
	accountant *account.Accountant
	classifier *classify.Classifier
	identity   *identity.Resolver
	sniffer    *sniffer.Sniffer
	cfg        *config.Config
}

// NewMonitor creates a new alert monitor.
func NewMonitor(
	accountant *account.Accountant,
	classifier *classify.Classifier,
	identity *identity.Resolver,
	sniffer *sniffer.Sniffer,
	cfg *config.Config,
) *Monitor {
	return &Monitor{
		accountant: accountant,
		classifier: classifier,
		identity:   identity,
		sniffer:    sniffer,
		cfg:        cfg,
	}
}

// Start begins the monitoring loop. Blocks until ctx is cancelled.
func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.AlertThresholds.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.evaluate()
		}
	}
}

// evaluate runs one cycle of threshold comparison, alerting, and stats emission.
func (m *Monitor) evaluate() {
	counters := m.accountant.GetCounters()
	snapshot := m.classifier.Snapshot()
	snifferStats := m.sniffer.GetStats()

	// Check thresholds and emit warnings.
	m.checkThresholds(counters, snapshot)

	// Emit network-wide visibility summary.
	m.emitStatsSummary(counters, snifferStats)

	// Emit bandwidth-map metric update.
	m.emitMetricUpdate(counters)
}

// checkThresholds compares counters against configured thresholds.
func (m *Monitor) checkThresholds(counters map[account.BucketKey]account.Counter, snapshot map[string]classify.AppInfo) {
	policyMap := m.cfg.ClientPolicyMap()

	for key, counter := range counters {
		// Skip low-confidence unless aggressive mode is enabled.
		if !m.cfg.Aggressive {
			// Check if the app has any high-confidence classification.
			hasHighConfidence := false
			for _, info := range snapshot {
				if info.App == key.App && info.Confidence == classify.ConfidenceHigh {
					hasHighConfidence = true
					break
				}
			}
			if !hasHighConfidence {
				continue
			}
		}

		// Check per-client policy overrides.
		threshold := m.cfg.AlertThresholds
		if policy, ok := policyMap[key.ClientIP]; ok {
			if policy.Exempt {
				continue
			}
			if policy.AlertThreshold != nil {
				threshold = *policy.AlertThreshold
			}
		}

		// Compare against thresholds.
		if counter.Bytes > threshold.BytesPerInterval || counter.Packets > threshold.PacketsPerInterval {
			deviceStr := m.identity.FormatDevice(key.ClientIP)
			log.Printf("⚠️  [WARNING] Client %s is heavily consuming data on App: %s "+
				"(Bytes: %s, Packets: %d)",
				deviceStr, key.App,
				formatBytes(counter.Bytes), counter.Packets)
		}
	}
}

// emitStatsSummary prints the network-wide visibility summary.
func (m *Monitor) emitStatsSummary(counters map[account.BucketKey]account.Counter, snifferStats sniffer.Stats) {
	var classifiedBytes int64
	for _, c := range counters {
		classifiedBytes += c.Bytes
	}

	totalAccountedBytes := m.accountant.GetTotalBytes()

	// Estimate unclassified as DoH events + unknown.
	// Since we can't count exact unclassified bytes (they're not in our rules),
	// we report the DoH event count as a proxy for unobservable traffic.
	dohEvents := snifferStats.DoHEventsSeen

	var classifiedPct float64
	if totalAccountedBytes > 0 {
		classifiedPct = float64(classifiedBytes) / float64(totalAccountedBytes) * 100
	} else if len(counters) > 0 {
		classifiedPct = 100.0
	}
	unclassifiedPct := 100.0 - classifiedPct

	log.Printf("[STATS] %.0f%% of traffic classified, %.0f%% unclassified (DoH events: %d, unknown/shared-CDN)",
		classifiedPct, unclassifiedPct, dohEvents)
}

// emitMetricUpdate prints the bandwidth-map table.
func (m *Monitor) emitMetricUpdate(counters map[account.BucketKey]account.Counter) {
	if len(counters) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString("┌─────────────────────────────────────────────────────────────────────┐\n")
	sb.WriteString("│                        [METRIC UPDATE]                              │\n")
	sb.WriteString("├──────────────────┬──────────────────┬──────────────┬─────────────────┤\n")
	sb.WriteString("│ Client           │ App              │ Bytes        │ Tag             │\n")
	sb.WriteString("├──────────────────┬──────────────────┬──────────────┬─────────────────┤\n")

	for key, counter := range counters {
		clientStr := key.ClientIP
		if name, ok := m.identity.Resolve(key.ClientIP); ok {
			clientStr = name
		}
		// Tag: "foreground" for all classified traffic.
		// NOTE: We cannot distinguish foreground vs background without DPI or
		// per-app socket tracking. All DNS-classified traffic is tagged as
		// foreground. This is a known limitation documented in README.md.
		tag := "foreground"

		sb.WriteString(fmt.Sprintf("│ %-16s │ %-16s │ %12s │ %-15s │\n",
			truncate(clientStr, 16),
			truncate(key.App, 16),
			formatBytes(counter.Bytes),
			tag))
	}

	sb.WriteString("└──────────────────┴──────────────────┴──────────────┴─────────────────┘\n")

	log.Print(sb.String())
}

// formatBytes returns a human-readable byte count.
func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// truncate shortens a string to maxLen, adding "…" if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 1 {
		return "…"
	}
	return s[:maxLen-1] + "…"
}
