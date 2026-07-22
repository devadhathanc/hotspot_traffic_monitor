// Package enforce manages rate-limiting of guest traffic using OS-level traffic control
// (Linux tc/iptables/nftables, Windows NetQoS). It maintains a registry of all applied rules
// for reliable teardown on shutdown or --reset.
//
// Firewall interaction design: We shell out to tc/nft/iptables CLI tools via os/exec rather
// than using the github.com/google/nftables Go library. Rationale:
// - CLI tools are more reliable across kernel versions.
// - Every command is logged for auditability.
// - Easier to debug and reproduce manually.
// - The nftables Go library uses raw netlink which is fragile.
package enforce

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// RuleEntry represents a single applied rate-limit rule in the registry.
type RuleEntry struct {
	TargetGuestIP string
	DestIPOrCIDR  string
	SpeedKbit     int
	TCHandle      string // tc class/filter handle for teardown
	App           string
	AppliedAt     time.Time
	ExpiresAt     time.Time
}

// Enforcer is the platform-independent interface for rate-limiting.
type Enforcer interface {
	// ApplyRateLimit throttles traffic from targetGuestIP to destIPOrCIDR
	// at the given speed in kbit/s.
	ApplyRateLimit(targetGuestIP, destIPOrCIDR string, speedKbit int, app string) error

	// RemoveRateLimit removes a specific rate-limit rule.
	RemoveRateLimit(entry RuleEntry) error

	// SetupQdisc sets up the root qdisc on the interface. Called once at startup.
	SetupQdisc() error

	// TeardownQdisc removes the root qdisc. Called on shutdown/reset.
	TeardownQdisc() error
}

// Registry manages the in-memory registry of all applied rules.
// This is the source of truth for teardown.
type Registry struct {
	mu      sync.Mutex
	rules   []RuleEntry
	enforcer Enforcer

	// Safety rails from config.
	minKbitFloor      int
	autoExpireDuration time.Duration
	aggressive         bool

	// Counter for unique tc class handles.
	handleCounter int
}

// NewRegistry creates a new rule registry with the given enforcer and safety rails.
func NewRegistry(enforcer Enforcer, minKbitFloor int, autoExpireDuration time.Duration, aggressive bool) *Registry {
	return &Registry{
		rules:              make([]RuleEntry, 0),
		enforcer:           enforcer,
		minKbitFloor:       minKbitFloor,
		autoExpireDuration: autoExpireDuration,
		aggressive:         aggressive,
		handleCounter:      10, // Start at 1:10 to leave room for root classes.
	}
}

// ApplyRateLimit creates a rate-limit rule with safety checks.
func (r *Registry) ApplyRateLimit(targetGuestIP, destIPOrCIDR string, speedKbit int, app string, confidenceHigh bool) error {
	// Safety rail: never enforce on low-confidence unless aggressive mode.
	if !confidenceHigh && !r.aggressive {
		log.Printf("[ENFORCE] Skipping rate-limit for %s→%s (%s): low confidence, aggressive mode disabled",
			targetGuestIP, destIPOrCIDR, app)
		return nil
	}

	// Safety rail: enforce minimum floor.
	if speedKbit < r.minKbitFloor {
		log.Printf("[ENFORCE] Clamping speed from %d to %d kbit (minimum floor)",
			speedKbit, r.minKbitFloor)
		speedKbit = r.minKbitFloor
	}

	// Check if a rule already exists for this target+destination.
	r.mu.Lock()
	for _, existing := range r.rules {
		if existing.TargetGuestIP == targetGuestIP && existing.DestIPOrCIDR == destIPOrCIDR {
			r.mu.Unlock()
			log.Printf("[ENFORCE] Rate-limit already active for %s→%s (%s), skipping",
				targetGuestIP, destIPOrCIDR, app)
			return nil
		}
	}
	r.mu.Unlock()

	// Apply the rate limit via the platform enforcer.
	if err := r.enforcer.ApplyRateLimit(targetGuestIP, destIPOrCIDR, speedKbit, app); err != nil {
		return fmt.Errorf("applying rate limit: %w", err)
	}

	// Register the rule.
	now := time.Now()
	entry := RuleEntry{
		TargetGuestIP: targetGuestIP,
		DestIPOrCIDR:  destIPOrCIDR,
		SpeedKbit:     speedKbit,
		App:           app,
		AppliedAt:     now,
		ExpiresAt:     now.Add(r.autoExpireDuration),
	}

	r.mu.Lock()
	r.handleCounter++
	entry.TCHandle = fmt.Sprintf("1:%d", r.handleCounter)
	r.rules = append(r.rules, entry)
	r.mu.Unlock()

	log.Printf("🔒 [ENFORCE] Rate-limit applied: %s→%s (%s) at %d kbit, expires %s",
		targetGuestIP, destIPOrCIDR, app, speedKbit,
		entry.ExpiresAt.Format(time.RFC3339))

	return nil
}

// ExpireRules checks for and removes expired rules.
// Returns the list of expired entries for re-evaluation by the alert module.
func (r *Registry) ExpireRules() []RuleEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	var expired []RuleEntry
	var active []RuleEntry

	for _, entry := range r.rules {
		if now.After(entry.ExpiresAt) {
			// Remove the rule.
			if err := r.enforcer.RemoveRateLimit(entry); err != nil {
				log.Printf("[WARN] Failed to remove expired rule for %s→%s: %v",
					entry.TargetGuestIP, entry.DestIPOrCIDR, err)
			} else {
				log.Printf("🔓 [ENFORCE] Rate-limit expired and removed: %s→%s (%s)",
					entry.TargetGuestIP, entry.DestIPOrCIDR, entry.App)
			}
			expired = append(expired, entry)
		} else {
			active = append(active, entry)
		}
	}

	r.rules = active
	return expired
}

// Reset removes ALL applied rules. Called on --reset and graceful shutdown.
func (r *Registry) Reset(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	log.Printf("[ENFORCE] Resetting all rate-limit rules (%d entries)...", len(r.rules))

	var lastErr error
	for _, entry := range r.rules {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := r.enforcer.RemoveRateLimit(entry); err != nil {
			log.Printf("[WARN] Failed to remove rule for %s→%s: %v",
				entry.TargetGuestIP, entry.DestIPOrCIDR, err)
			lastErr = err
		} else {
			log.Printf("🔓 [ENFORCE] Removed rate-limit: %s→%s (%s)",
				entry.TargetGuestIP, entry.DestIPOrCIDR, entry.App)
		}
	}

	// Tear down root qdisc.
	if err := r.enforcer.TeardownQdisc(); err != nil {
		log.Printf("[WARN] Failed to teardown root qdisc: %v", err)
		if lastErr == nil {
			lastErr = err
		}
	}

	r.rules = r.rules[:0]

	if lastErr != nil {
		return fmt.Errorf("reset completed with errors: %w", lastErr)
	}

	log.Printf("[ENFORCE] Reset complete — all rules removed.")
	return nil
}

// GetRules returns a snapshot of all active rules.
func (r *Registry) GetRules() []RuleEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	snap := make([]RuleEntry, len(r.rules))
	copy(snap, r.rules)
	return snap
}

// StartExpiryLoop runs a goroutine that periodically checks for expired rules.
// Blocks until ctx is cancelled.
func (r *Registry) StartExpiryLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.ExpireRules()
		}
	}
}

// NextHandle returns a unique tc class handle string.
func (r *Registry) NextHandle() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handleCounter++
	return fmt.Sprintf("1:%d", r.handleCounter)
}
