//go:build linux

package enforce

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// LinuxEnforcer implements rate-limiting on Linux using tc HTB/TBF qdiscs
// and iptables/nftables classification rules.
type LinuxEnforcer struct {
	iface   string
	backend string // "nftables" or "iptables"
}

// NewLinuxEnforcer creates a Linux-specific enforcer.
func NewLinuxEnforcer(iface, backend string) *LinuxEnforcer {
	return &LinuxEnforcer{
		iface:   iface,
		backend: backend,
	}
}

// NewPlatformEnforcer creates the appropriate enforcer for the current platform.
func NewPlatformEnforcer(iface, backend string) Enforcer {
	return NewLinuxEnforcer(iface, backend)
}

// Ensure LinuxEnforcer implements Enforcer at compile time.
var _ Enforcer = (*LinuxEnforcer)(nil)

// SetupQdisc creates the root HTB qdisc on the interface.
func (e *LinuxEnforcer) SetupQdisc() error {
	// Delete existing qdisc first (ignore error if none exists).
	_ = e.execCmd("tc", "qdisc", "del", "dev", e.iface, "root")

	// Create root HTB qdisc.
	if err := e.execCmd("tc", "qdisc", "add", "dev", e.iface, "root", "handle", "1:", "htb", "default", "99"); err != nil {
		return fmt.Errorf("creating root HTB qdisc: %w", err)
	}

	// Create default class with high bandwidth (uncapped).
	if err := e.execCmd("tc", "class", "add", "dev", e.iface, "parent", "1:", "classid", "1:99",
		"htb", "rate", "1000mbit", "ceil", "1000mbit"); err != nil {
		return fmt.Errorf("creating default class: %w", err)
	}

	log.Printf("🔒 [FIREWALL] Root HTB qdisc created on %s", e.iface)
	return nil
}

// TeardownQdisc removes the root qdisc, which removes all child classes and filters.
func (e *LinuxEnforcer) TeardownQdisc() error {
	return e.execCmd("tc", "qdisc", "del", "dev", e.iface, "root")
}

// ApplyRateLimit creates a tc class and filter to throttle traffic.
func (e *LinuxEnforcer) ApplyRateLimit(targetGuestIP, destIPOrCIDR string, speedKbit int, app string) error {
	// Generate a unique class handle based on IP hash.
	// Using a simple incrementing handle — the Registry manages uniqueness.
	handle := ipToHandle(targetGuestIP, destIPOrCIDR)

	rate := fmt.Sprintf("%dkbit", speedKbit)
	ceil := rate // Ceil = rate for hard cap.

	// Create HTB class for this throttle.
	if err := e.execCmd("tc", "class", "add", "dev", e.iface,
		"parent", "1:", "classid", handle,
		"htb", "rate", rate, "ceil", ceil); err != nil {
		return fmt.Errorf("creating tc class %s: %w", handle, err)
	}

	// Add a TBF qdisc under the class for burst control.
	if err := e.execCmd("tc", "qdisc", "add", "dev", e.iface,
		"parent", handle, "handle", subHandle(handle),
		"tbf", "rate", rate, "burst", "32kbit", "latency", "400ms"); err != nil {
		// Non-fatal — HTB class still works without TBF.
		log.Printf("[WARN] Failed to add TBF under %s: (continuing without burst control)", handle)
	}

	// Create iptables/nftables mark rule to steer traffic into the throttled class.
	mark := handleToMark(handle)
	if err := e.addMarkRule(targetGuestIP, destIPOrCIDR, mark, app); err != nil {
		return fmt.Errorf("creating mark rule: %w", err)
	}

	// Create tc filter to match the mark and direct to our class.
	if err := e.execCmd("tc", "filter", "add", "dev", e.iface,
		"parent", "1:", "protocol", "ip", "prio", "1",
		"handle", mark, "fw", "classid", handle); err != nil {
		return fmt.Errorf("creating tc filter: %w", err)
	}

	return nil
}

// RemoveRateLimit removes the tc class and associated rules.
func (e *LinuxEnforcer) RemoveRateLimit(entry RuleEntry) error {
	handle := ipToHandle(entry.TargetGuestIP, entry.DestIPOrCIDR)
	mark := handleToMark(handle)

	// Remove tc filter.
	_ = e.execCmd("tc", "filter", "del", "dev", e.iface,
		"parent", "1:", "protocol", "ip", "prio", "1",
		"handle", mark, "fw", "classid", handle)

	// Remove tc class.
	_ = e.execCmd("tc", "class", "del", "dev", e.iface, "classid", handle)

	// Remove firewall mark rule.
	e.removeMarkRule(entry.TargetGuestIP, entry.DestIPOrCIDR, mark, entry.App)

	return nil
}

// addMarkRule creates an iptables/nftables rule to mark matching packets.
func (e *LinuxEnforcer) addMarkRule(srcIP, dstIP, mark, app string) error {
	comment := fmt.Sprintf("hotspotd-enforce:%s:%s", dstIP, app)

	switch e.backend {
	case "nftables":
		rule := fmt.Sprintf("add rule ip hotspotd HOTSPOTD_ENFORCE ip saddr %s ip daddr %s meta mark set %s comment \"%s\"",
			srcIP, dstIP, mark, comment)
		return e.execCmd("nft", strings.Fields(rule)...)
	default:
		return e.execCmd("iptables", "-t", "mangle", "-A", "FORWARD",
			"-s", srcIP, "-d", dstIP,
			"-j", "MARK", "--set-mark", mark,
			"-m", "comment", "--comment", comment)
	}
}

// removeMarkRule removes the firewall mark rule.
func (e *LinuxEnforcer) removeMarkRule(srcIP, dstIP, mark, app string) {
	comment := fmt.Sprintf("hotspotd-enforce:%s:%s", dstIP, app)

	switch e.backend {
	case "nftables":
		// nftables rule deletion by handle requires listing first — best effort.
		log.Printf("[ENFORCE] Removing nftables mark rule for %s→%s (best-effort)", srcIP, dstIP)
		_ = e.execCmd("nft", "flush", "chain", "ip", "hotspotd", "HOTSPOTD_ENFORCE")
	default:
		_ = e.execCmd("iptables", "-t", "mangle", "-D", "FORWARD",
			"-s", srcIP, "-d", dstIP,
			"-j", "MARK", "--set-mark", mark,
			"-m", "comment", "--comment", comment)
	}
}

// execCmd runs a command and logs it in the spec-required format.
func (e *LinuxEnforcer) execCmd(name string, args ...string) error {
	cmdStr := name + " " + strings.Join(args, " ")
	log.Printf("🔒 [FIREWALL] Executing OS Command: %s", cmdStr)

	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s: %s: %w", cmdStr, strings.TrimSpace(string(output)), err)
	}
	return nil
}

// ipToHandle generates a deterministic tc class handle from IP strings.
// Uses a simple hash to map to the 1:10-1:9999 range.
func ipToHandle(srcIP, dstIP string) string {
	h := 0
	for _, c := range srcIP + dstIP {
		h = (h*31 + int(c)) & 0xFFFF
	}
	// Ensure handle is in valid range (10-9999) and avoid 0 and 99 (default).
	h = (h % 9989) + 10
	if h == 99 {
		h = 100
	}
	return fmt.Sprintf("1:%d", h)
}

// subHandle derives a child handle for TBF qdiscs.
func subHandle(classHandle string) string {
	// Extract the minor number and use it as the major for the leaf qdisc.
	var minor int
	fmt.Sscanf(classHandle, "1:%d", &minor)
	return fmt.Sprintf("%d:", minor)
}

// handleToMark converts a tc handle to an iptables mark value.
func handleToMark(handle string) string {
	var minor int
	fmt.Sscanf(handle, "1:%d", &minor)
	return fmt.Sprintf("0x%x", minor)
}
