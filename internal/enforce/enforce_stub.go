//go:build !linux && !windows

package enforce

import (
	"fmt"
	"log"
)

// StubEnforcer is a no-op enforcer for unsupported platforms (macOS, etc.).
// This allows the project to compile and run on development machines.
// Actual enforcement only works on Linux (primary) and Windows (best-effort).
type StubEnforcer struct {
	iface string
}

// NewPlatformEnforcer creates the appropriate enforcer for the current platform.
// On unsupported platforms, returns a stub that logs warnings.
func NewPlatformEnforcer(iface, backend string) Enforcer {
	log.Printf("⚠️  [WARNING] Rate-limit enforcement is not supported on this platform. " +
		"Using stub enforcer (commands will be logged but not executed). " +
		"Deploy on Linux for actual enforcement.")
	return &StubEnforcer{iface: iface}
}

func (e *StubEnforcer) SetupQdisc() error {
	log.Printf("[STUB] SetupQdisc on %s (no-op on this platform)", e.iface)
	return nil
}

func (e *StubEnforcer) TeardownQdisc() error {
	log.Printf("[STUB] TeardownQdisc on %s (no-op on this platform)", e.iface)
	return nil
}

func (e *StubEnforcer) ApplyRateLimit(targetGuestIP, destIPOrCIDR string, speedKbit int, app string) error {
	log.Printf("[STUB] 🔒 Would apply rate-limit: %s→%s (%s) at %d kbit (no-op on this platform)",
		targetGuestIP, destIPOrCIDR, app, speedKbit)
	return nil
}

func (e *StubEnforcer) RemoveRateLimit(entry RuleEntry) error {
	log.Printf("[STUB] 🔓 Would remove rate-limit: %s→%s (%s) (no-op on this platform)",
		entry.TargetGuestIP, entry.DestIPOrCIDR, entry.App)
	return nil
}

// Ensure StubEnforcer implements Enforcer at compile time.
var _ Enforcer = (*StubEnforcer)(nil)

// Provide a factory function matching the other platforms' pattern.
func init() {
	_ = fmt.Sprintf // Ensure fmt is used.
}
