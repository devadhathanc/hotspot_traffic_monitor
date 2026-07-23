// Package alert monitors traffic counters against configured thresholds and emits
// warnings, stats summaries, and bandwidth-map metric updates at configurable intervals.
package alert

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"hotspotd/internal/account"
	"hotspotd/internal/classify"
	"hotspotd/internal/config"
	"hotspotd/internal/identity"
	"hotspotd/internal/sniffer"
	"hotspotd/internal/usage"
)

// Monitor watches traffic counters and emits alerts/stats.
type Monitor struct {
	accountant *account.Accountant
	classifier *classify.Classifier
	identity   *identity.Resolver
	sniffer    *sniffer.Sniffer
	cfg        *config.Config
	tracker    *usage.Tracker

	// Track last generation to only reprint table when new domains appear.
	lastDomainGen int64
}

// NewMonitor creates a new alert monitor.
func NewMonitor(
	accountant *account.Accountant,
	classifier *classify.Classifier,
	identity *identity.Resolver,
	sniffer *sniffer.Sniffer,
	cfg *config.Config,
	tracker *usage.Tracker,
) *Monitor {
	return &Monitor{
		accountant: accountant,
		classifier: classifier,
		identity:   identity,
		sniffer:    sniffer,
		cfg:        cfg,
		tracker:    tracker,
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

// evaluate runs one cycle of threshold comparison, alerting, and table display.
func (m *Monitor) evaluate() {
	counters := m.accountant.GetCounters()
	snapshot := m.classifier.Snapshot()

	// Update bandwidth counters.
	m.tracker.Update()

	// Check thresholds and emit warnings.
	m.checkThresholds(counters, snapshot)

	// Only reprint when new domains appear.
	gen := m.sniffer.DomainGeneration()
	if gen != m.lastDomainGen {
		m.lastDomainGen = gen
		m.printTable()
	}
}

// checkThresholds compares counters against configured thresholds.
func (m *Monitor) checkThresholds(counters map[account.BucketKey]account.Counter, snapshot map[string]classify.AppInfo) {
	policyMap := m.cfg.ClientPolicyMap()

	for key, counter := range counters {
		if !m.cfg.Aggressive {
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

		threshold := m.cfg.AlertThresholds
		if policy, ok := policyMap[key.ClientIP]; ok {
			if policy.Exempt {
				continue
			}
			if policy.AlertThreshold != nil {
				threshold = *policy.AlertThreshold
			}
		}

		if counter.Bytes > threshold.BytesPerInterval || counter.Packets > threshold.PacketsPerInterval {
			deviceStr := m.identity.FormatDevice(key.ClientIP)
			log.Printf("⚠️  [WARNING] Client %s heavy on %s (Bytes: %s, Packets: %d)",
				deviceStr, key.App, formatBytes(counter.Bytes), counter.Packets)
		}
	}
}

// printTable prints all DNS domains seen, grouped by app name.
func (m *Monitor) printTable() {
	domains := m.sniffer.GetDomains()
	if len(domains) == 0 {
		return
	}

	// Group by app name. Unclassified go under "Others".
	groups := make(map[string][]sniffer.DomainRecord)
	for _, d := range domains {
		app := d.App
		if app == "" {
			app = "Others"
		}
		groups[app] = append(groups[app], d)
	}

	// Sort each group by last seen (most recent first).
	for _, recs := range groups {
		sort.Slice(recs, func(i, j int) bool {
			return recs[i].LastSeen.After(recs[j].LastSeen)
		})
	}

	// Build sorted app list: named apps first (sorted), "Others" last.
	appOrder := make([]string, 0, len(groups))
	for app := range groups {
		if app != "Others" {
			appOrder = append(appOrder, app)
		}
	}
	sort.Strings(appOrder)
	if _, ok := groups["Others"]; ok {
		appOrder = append(appOrder, "Others")
	}

	// Every row uses exactly this format so all columns align:
	//   | %-8s | %-31s | %-40s | %-8s |
	rowFmt := "| %-8s | %-31s | %-40s | %-8s |\n"
	sep := "+----------+---------------------------------+------------------------------------------+----------+"

	var sb strings.Builder
	sb.WriteString("\n" + sep + "\n")
	sb.WriteString(fmt.Sprintf(rowFmt, "App", "Domain", "Resolved IPs", "LastSeen"))
	sb.WriteString(sep + "\n")

	for _, app := range appOrder {
		recs := groups[app]
		for i, d := range recs {
			appCol := ""
			if i == 0 {
				appCol = app
			}
			ipStr := strings.Join(d.IPs, ", ")
			sb.WriteString(fmt.Sprintf(rowFmt,
				trunc(appCol, 8),
				trunc(d.Domain, 31),
				trunc(ipStr, 40),
				d.LastSeen.Format("15:04:05")))
		}
		sb.WriteString(sep + "\n")
	}

	// Footer: usage stats in same column format.
	stats := m.sniffer.GetStats()
	u := m.tracker.GetUsage()
	dur := fmt.Sprintf("%dm%ds", int(u.Duration.Minutes()), int(u.Duration.Seconds())%60)

	sb.WriteString(fmt.Sprintf(rowFmt,
		fmt.Sprintf("%d dom", len(domains)),
		fmt.Sprintf("Down: %s", usage.FormatBytes(u.Download)),
		fmt.Sprintf("Up: %s  |  Total: %s", usage.FormatBytes(u.Upload), usage.FormatBytes(u.Download+u.Upload)),
		dur))
	sb.WriteString(fmt.Sprintf(rowFmt,
		"",
		fmt.Sprintf("Queries: %d", stats.DNSQueriesSeen),
		fmt.Sprintf("Responses: %d", stats.DNSResponsesSeen),
		""))
	sb.WriteString(sep + "\n")

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

// trunc shortens a string to maxLen.
func trunc(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
