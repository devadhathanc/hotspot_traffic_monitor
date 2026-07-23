// Package account manages traffic accounting by dynamically inserting nftables/iptables
// rules for classified IPs and polling their counters at configurable intervals.
//
// Design: Rather than summing raw packets in userspace (which is expensive and lossy),
// we leverage the kernel's built-in packet/byte counters on firewall rules. We insert
// marking rules for each known classified IP, then periodically read the counters from
// `nft list ruleset -j` or `iptables -L -v -n -x`.
package account

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"hotspotd/internal/classify"
)

// Counter holds traffic counters for a client+app bucket.
type Counter struct {
	Bytes   int64
	Packets int64
}

// BucketKey identifies a traffic bucket: client IP + app name.
type BucketKey struct {
	ClientIP string
	App      string
}

// Accountant manages traffic accounting rules and counter polling.
type Accountant struct {
	mu sync.RWMutex
	// counters maps BucketKey → accumulated Counter.
	counters map[BucketKey]Counter
	// managedRules tracks which IP rules we've inserted, to avoid duplicates.
	managedRules map[string]bool // keyed by destination IP

	classifier *classify.Classifier
	iface      string
	subnet     string
	interval   time.Duration
	backend    string // "nftables" or "iptables"

	// chainName is the custom chain we create for accounting rules.
	chainName string
	// tableName for nftables.
	tableName string

	// chainReady is false if the firewall chain setup failed (e.g. on macOS).
	// When false, we skip all rule insertion/polling silently.
	chainReady bool
}

// NewAccountant creates a new traffic accountant.
func NewAccountant(classifier *classify.Classifier, iface, subnet string, interval time.Duration, backend string) *Accountant {
	return &Accountant{
		counters:     make(map[BucketKey]Counter),
		managedRules: make(map[string]bool),
		classifier:   classifier,
		iface:        iface,
		subnet:       subnet,
		interval:     interval,
		backend:      backend,
		chainName:    "HOTSPOTD_ACCT",
		tableName:    "hotspotd",
	}
}

// Start begins the accounting loop. Blocks until ctx is cancelled.
func (a *Accountant) Start(ctx context.Context) error {
	// Set up the accounting chain.
	if err := a.setupChain(); err != nil {
		log.Printf("[WARN] Accounting disabled — firewall tools not available (expected on macOS): %v", err)
		a.chainReady = false
	} else {
		a.chainReady = true
	}

	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if a.chainReady {
				a.cleanup()
			}
			return nil
		case <-ticker.C:
			if a.chainReady {
				a.syncRules()
				a.pollCounters()
			}
		}
	}
}

// GetCounters returns a snapshot of all traffic counters.
func (a *Accountant) GetCounters() map[BucketKey]Counter {
	a.mu.RLock()
	defer a.mu.RUnlock()

	snap := make(map[BucketKey]Counter, len(a.counters))
	for k, v := range a.counters {
		snap[k] = v
	}
	return snap
}

// GetTotalBytes returns the total accounted bytes across all buckets.
func (a *Accountant) GetTotalBytes() int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var total int64
	for _, c := range a.counters {
		total += c.Bytes
	}
	return total
}

// syncRules ensures accounting rules exist for all currently classified IPs.
func (a *Accountant) syncRules() {
	snapshot := a.classifier.Snapshot()

	for destIP, info := range snapshot {
		if a.managedRules[destIP] {
			continue // Rule already exists.
		}

		if err := a.insertRule(destIP, info.App); err != nil {
			log.Printf("[WARN] Failed to insert accounting rule for %s (%s): %v", destIP, info.App, err)
			continue
		}
		a.managedRules[destIP] = true
	}
}

// pollCounters reads current counters from the firewall backend.
func (a *Accountant) pollCounters() {
	switch a.backend {
	case "nftables":
		a.pollNftables()
	default:
		a.pollIptables()
	}
}

// setupChain creates the accounting chain in the firewall.
func (a *Accountant) setupChain() error {
	switch a.backend {
	case "nftables":
		return a.setupNftablesChain()
	default:
		return a.setupIptablesChain()
	}
}

// setupNftablesChain creates the nftables table and chain.
func (a *Accountant) setupNftablesChain() error {
	// Create table.
	if err := a.runCmd("nft", "add", "table", "ip", a.tableName); err != nil {
		return fmt.Errorf("creating nftables table: %w", err)
	}
	// Create chain hooked to forward path for accounting.
	chainCmd := fmt.Sprintf("add chain ip %s %s { type filter hook forward priority 0 ; policy accept ; }", a.tableName, a.chainName)
	if err := a.runCmd("nft", strings.Fields(chainCmd)...); err != nil {
		return fmt.Errorf("creating nftables chain: %w", err)
	}
	return nil
}

// setupIptablesChain creates the iptables accounting chain.
func (a *Accountant) setupIptablesChain() error {
	// Create chain (ignore error if already exists).
	_ = a.runCmd("iptables", "-N", a.chainName)
	// Insert jump from FORWARD to our chain.
	_ = a.runCmd("iptables", "-I", "FORWARD", "-j", a.chainName)
	return nil
}

// insertRule adds an accounting rule for a destination IP.
func (a *Accountant) insertRule(destIP, app string) error {
	comment := fmt.Sprintf("hotspotd:%s:%s", destIP, app)

	switch a.backend {
	case "nftables":
		rule := fmt.Sprintf("add rule ip %s %s ip daddr %s counter comment \"%s\"",
			a.tableName, a.chainName, destIP, comment)
		return a.runCmd("nft", strings.Fields(rule)...)
	default:
		return a.runCmd("iptables", "-A", a.chainName,
			"-d", destIP, "-j", "ACCEPT",
			"-m", "comment", "--comment", comment)
	}
}

// pollNftables reads counters from nft list ruleset -j.
func (a *Accountant) pollNftables() {
	output, err := exec.Command("nft", "-j", "list", "chain", "ip", a.tableName, a.chainName).Output()
	if err != nil {
		return
	}

	// Parse JSON output to extract counters per rule.
	var result struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, raw := range result.Nftables {
		var item map[string]json.RawMessage
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		ruleRaw, ok := item["rule"]
		if !ok {
			continue
		}
		a.parseNftablesRule(ruleRaw)
	}
}

// parseNftablesRule extracts counter values from a single nftables rule JSON.
func (a *Accountant) parseNftablesRule(ruleRaw json.RawMessage) {
	var rule struct {
		Expr []json.RawMessage `json:"expr"`
		Comment string         `json:"comment"`
	}
	if err := json.Unmarshal(ruleRaw, &rule); err != nil {
		return
	}

	if !strings.HasPrefix(rule.Comment, "hotspotd:") {
		return
	}

	// Parse comment: "hotspotd:<destIP>:<app>"
	parts := strings.SplitN(rule.Comment, ":", 3)
	if len(parts) != 3 {
		return
	}
	destIP := parts[1]
	app := parts[2]

	// Find counter in expressions.
	for _, exprRaw := range rule.Expr {
		var expr map[string]json.RawMessage
		if err := json.Unmarshal(exprRaw, &expr); err != nil {
			continue
		}
		counterRaw, ok := expr["counter"]
		if !ok {
			continue
		}
		var counter struct {
			Bytes   int64 `json:"bytes"`
			Packets int64 `json:"packets"`
		}
		if err := json.Unmarshal(counterRaw, &counter); err != nil {
			continue
		}

		// We currently account at the destination IP level, not per-client.
		// Per-client accounting would require per-source-IP rules, which is more complex.
		// For now, all clients' traffic to this app is aggregated.
		// TODO: Extend to per-client rules if needed.
		key := BucketKey{ClientIP: "all", App: app}
		// Use the subnet info to create per-client rules in the future.
		_ = destIP
		a.counters[key] = Counter{
			Bytes:   counter.Bytes,
			Packets: counter.Packets,
		}
	}
}

// pollIptables reads counters from iptables -L -v -n -x.
func (a *Accountant) pollIptables() {
	output, err := exec.Command("iptables", "-L", a.chainName, "-v", "-n", "-x").Output()
	if err != nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Parse iptables output line by line.
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "hotspotd:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// iptables -L -v -n -x format:
		// pkts bytes target prot opt in out source destination <extras>
		var packets, bytes int64
		fmt.Sscanf(fields[0], "%d", &packets)
		fmt.Sscanf(fields[1], "%d", &bytes)

		// Extract comment to find app name.
		commentIdx := strings.Index(line, "hotspotd:")
		if commentIdx < 0 {
			continue
		}
		comment := line[commentIdx:]
		parts := strings.SplitN(comment, ":", 3)
		if len(parts) != 3 {
			continue
		}
		app := strings.TrimSpace(parts[2])

		key := BucketKey{ClientIP: "all", App: app}
		a.counters[key] = Counter{
			Bytes:   bytes,
			Packets: packets,
		}
	}
}

// cleanup removes the accounting chain on shutdown.
func (a *Accountant) cleanup() {
	log.Printf("[SYSTEM] Cleaning up accounting rules...")
	switch a.backend {
	case "nftables":
		_ = a.runCmd("nft", "flush", "chain", "ip", a.tableName, a.chainName)
		_ = a.runCmd("nft", "delete", "chain", "ip", a.tableName, a.chainName)
		_ = a.runCmd("nft", "delete", "table", "ip", a.tableName)
	default:
		_ = a.runCmd("iptables", "-D", "FORWARD", "-j", a.chainName)
		_ = a.runCmd("iptables", "-F", a.chainName)
		_ = a.runCmd("iptables", "-X", a.chainName)
	}
}

// runCmd executes a command and returns any error.
func (a *Accountant) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), string(output), err)
	}
	return nil
}
