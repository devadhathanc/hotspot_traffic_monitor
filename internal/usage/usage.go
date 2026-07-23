// Package usage tracks interface-level bandwidth usage by reading system counters.
package usage

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// InterfaceStats holds the cumulative byte counters for an interface.
type InterfaceStats struct {
	InBytes  int64
	OutBytes int64
}

// Tracker monitors bandwidth usage on a network interface.
type Tracker struct {
	iface string

	mu       sync.Mutex
	baseline InterfaceStats // counters at start
	current  InterfaceStats // latest counters
	started  time.Time
}

// NewTracker creates a new bandwidth tracker for the given interface.
func NewTracker(iface string) *Tracker {
	t := &Tracker{
		iface:   iface,
		started: time.Now(),
	}
	// Read initial baseline.
	if stats, err := readInterfaceStats(iface); err == nil {
		t.baseline = stats
		t.current = stats
	}
	return t
}

// Update reads the latest counters from the system.
func (t *Tracker) Update() {
	stats, err := readInterfaceStats(t.iface)
	if err != nil {
		return
	}
	t.mu.Lock()
	t.current = stats
	t.mu.Unlock()
}

// Usage returns the bytes downloaded and uploaded since tracking started.
type Usage struct {
	Download int64
	Upload   int64
	Duration time.Duration
}

// GetUsage returns bandwidth usage since tracker started.
func (t *Tracker) GetUsage() Usage {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Usage{
		Download: t.current.InBytes - t.baseline.InBytes,
		Upload:   t.current.OutBytes - t.baseline.OutBytes,
		Duration: time.Since(t.started),
	}
}

// FormatBytes returns a human-readable byte count.
func FormatBytes(b int64) string {
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

// readInterfaceStats reads byte counters using netstat -bI <iface>.
func readInterfaceStats(iface string) (InterfaceStats, error) {
	out, err := exec.Command("netstat", "-bI", iface).Output()
	if err != nil {
		return InterfaceStats{}, fmt.Errorf("netstat: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) < 11 || fields[0] != iface {
			continue
		}
		// netstat -bI format on macOS:
		// Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Colls
		ibytes, err1 := strconv.ParseInt(fields[6], 10, 64)
		obytes, err2 := strconv.ParseInt(fields[9], 10, 64)
		if err1 == nil && err2 == nil {
			return InterfaceStats{InBytes: ibytes, OutBytes: obytes}, nil
		}
	}

	return InterfaceStats{}, fmt.Errorf("interface %s not found in netstat output", iface)
}
