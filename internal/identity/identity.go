// Package identity resolves IP addresses to device names using DHCP leases,
// ARP table, and (best-effort) mDNS/NetBIOS observations.
package identity

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DeviceInfo holds resolved device identity information.
type DeviceInfo struct {
	Name     string
	MAC      string
	IP       string
	Source   string // "dhcp", "arp", "mdns"
	LastSeen time.Time
}

// Resolver resolves IP addresses to device names.
type Resolver struct {
	mu sync.RWMutex
	// macCache is keyed by MAC address (stable across DHCP renewals).
	macCache map[string]DeviceInfo
	// ipToMAC maps current IP→MAC for reverse lookups.
	ipToMAC map[string]string

	dhcpLeaseFile string
}

// NewResolver creates a new identity resolver.
func NewResolver(dhcpLeaseFile string) *Resolver {
	r := &Resolver{
		macCache:      make(map[string]DeviceInfo),
		ipToMAC:       make(map[string]string),
		dhcpLeaseFile: dhcpLeaseFile,
	}

	// Initial population.
	r.refresh()
	return r
}

// Start begins periodic IP→MAC re-resolution. Blocks until ctx is cancelled.
func (r *Resolver) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refresh()
		}
	}
}

// Resolve returns the device name for a given IP address.
func (r *Resolver) Resolve(ip string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mac, ok := r.ipToMAC[ip]
	if !ok {
		return "", false
	}
	info, ok := r.macCache[mac]
	if !ok || info.Name == "" {
		return "", false
	}
	return info.Name, true
}

// refresh re-reads DHCP leases and ARP table to update the cache.
func (r *Resolver) refresh() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Parse DHCP lease file (highest priority).
	r.parseDHCPLeases()

	// 2. Parse ARP table for IP→MAC mappings.
	r.parseARPTable()
}

// parseDHCPLeases reads the dnsmasq lease file.
// Format: <expiry> <MAC> <IP> <hostname> <client-id>
func (r *Resolver) parseDHCPLeases() {
	if r.dhcpLeaseFile == "" {
		return
	}

	f, err := os.Open(r.dhcpLeaseFile)
	if err != nil {
		// Not an error on non-dnsmasq systems.
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// fields[0] = expiry timestamp
		mac := strings.ToLower(fields[1])
		ip := fields[2]
		hostname := fields[3]

		if hostname == "*" {
			hostname = "" // dnsmasq uses * for unknown hostnames.
		}

		r.ipToMAC[ip] = mac
		// DHCP source is highest priority — always overwrite.
		r.macCache[mac] = DeviceInfo{
			Name:     hostname,
			MAC:      mac,
			IP:       ip,
			Source:   "dhcp",
			LastSeen: time.Now(),
		}
	}
}

// parseARPTable runs `ip neigh` to get current ARP entries.
// Fallback: `arp -a` on systems without `ip` command.
func (r *Resolver) parseARPTable() {
	output, err := exec.Command("ip", "neigh").Output()
	if err != nil {
		// Fallback to arp -a (macOS, older Linux).
		output, err = exec.Command("arp", "-a").Output()
		if err != nil {
			return
		}
		r.parseARPFallback(string(output))
		return
	}

	// Parse `ip neigh` output.
	// Format: <IP> dev <iface> lladdr <MAC> <state>
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ip := fields[0]
		// Find "lladdr" field.
		macIdx := -1
		for i, f := range fields {
			if f == "lladdr" && i+1 < len(fields) {
				macIdx = i + 1
				break
			}
		}
		if macIdx < 0 {
			continue
		}
		mac := strings.ToLower(fields[macIdx])

		r.ipToMAC[ip] = mac
		// Only set if not already known from DHCP (lower priority).
		if _, exists := r.macCache[mac]; !exists {
			r.macCache[mac] = DeviceInfo{
				MAC:      mac,
				IP:       ip,
				Source:   "arp",
				LastSeen: time.Now(),
			}
		} else {
			// Update IP mapping but keep existing name.
			info := r.macCache[mac]
			info.IP = ip
			info.LastSeen = time.Now()
			r.macCache[mac] = info
		}
	}
}

// parseARPFallback parses `arp -a` output (macOS/BSD format).
// Format: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
func (r *Resolver) parseARPFallback(output string) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Extract IP from parentheses.
		lparen := strings.Index(line, "(")
		rparen := strings.Index(line, ")")
		if lparen < 0 || rparen < 0 || rparen <= lparen {
			continue
		}
		ip := line[lparen+1 : rparen]

		// Find "at" followed by MAC.
		parts := strings.Fields(line[rparen+1:])
		if len(parts) < 2 || parts[0] != "at" {
			continue
		}
		mac := strings.ToLower(parts[1])
		if mac == "(incomplete)" {
			continue
		}

		r.ipToMAC[ip] = mac
		if _, exists := r.macCache[mac]; !exists {
			r.macCache[mac] = DeviceInfo{
				MAC:      mac,
				IP:       ip,
				Source:   "arp",
				LastSeen: time.Now(),
			}
		}
	}
}

// FormatDevice returns a human-readable string for a device IP.
// If the device name is known, returns "IP (name)"; otherwise just "IP".
func (r *Resolver) FormatDevice(ip string) string {
	name, ok := r.Resolve(ip)
	if ok && name != "" {
		return fmt.Sprintf("%s (%s)", ip, name)
	}
	return ip
}
