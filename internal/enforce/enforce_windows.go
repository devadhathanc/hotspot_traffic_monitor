//go:build windows

// This file provides the Windows implementation of the Enforcer interface.
// It uses PowerShell New-NetQosPolicy for rate-limiting.
//
// WARNING: This implementation is best-effort. Actual QoS enforcement on Windows
// typically requires:
// - Windows Server with Group Policy support
// - Administrative privileges
// - Policy-based QoS configured at the Group Policy level
//
// The New-NetQosPolicy cmdlet may not have any effect on consumer Windows editions
// without proper Group Policy configuration.
package enforce

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

func init() {
	log.Printf("⚠️  [WARNING] Windows enforcement is best-effort. Rate-limiting via New-NetQosPolicy " +
		"may require Windows Server + Group Policy to actually take effect.")
}

// WindowsEnforcer implements rate-limiting on Windows using PowerShell New-NetQosPolicy.
type WindowsEnforcer struct {
	iface string
}

// NewWindowsEnforcer creates a Windows-specific enforcer.
func NewWindowsEnforcer(iface string) *WindowsEnforcer {
	return &WindowsEnforcer{iface: iface}
}

// NewPlatformEnforcer creates the appropriate enforcer for the current platform.
func NewPlatformEnforcer(iface, backend string) Enforcer {
	return NewWindowsEnforcer(iface)
}

// Ensure WindowsEnforcer implements Enforcer at compile time.
var _ Enforcer = (*WindowsEnforcer)(nil)

// SetupQdisc is a no-op on Windows — QoS policies are applied directly.
func (e *WindowsEnforcer) SetupQdisc() error {
	log.Printf("[SYSTEM] Windows: No root qdisc setup needed (QoS policies are direct).")
	return nil
}

// TeardownQdisc removes all hotspotd QoS policies.
func (e *WindowsEnforcer) TeardownQdisc() error {
	psCmd := `Get-NetQosPolicy | Where-Object { $_.Name -like "hotspotd-*" } | Remove-NetQosPolicy -Confirm:$false`
	return e.execPowerShell(psCmd)
}

// ApplyRateLimit creates a Windows QoS policy to throttle traffic.
func (e *WindowsEnforcer) ApplyRateLimit(targetGuestIP, destIPOrCIDR string, speedKbit int, app string) error {
	policyName := fmt.Sprintf("hotspotd-%s-%s", sanitize(targetGuestIP), sanitize(app))

	// ThrottleRateAction is in bits/sec.
	throttleBitsPerSec := speedKbit * 1000

	psCmd := fmt.Sprintf(
		`New-NetQosPolicy -Name "%s" -IPDstPrefixMatchCondition "%s" -IPSrcPrefixMatchCondition "%s" -ThrottleRateActionBitsPerSecond %d -Confirm:$false`,
		policyName, destIPOrCIDR, targetGuestIP, throttleBitsPerSec)

	return e.execPowerShell(psCmd)
}

// RemoveRateLimit removes a specific QoS policy.
func (e *WindowsEnforcer) RemoveRateLimit(entry RuleEntry) error {
	policyName := fmt.Sprintf("hotspotd-%s-%s", sanitize(entry.TargetGuestIP), sanitize(entry.App))
	psCmd := fmt.Sprintf(`Remove-NetQosPolicy -Name "%s" -Confirm:$false`, policyName)
	return e.execPowerShell(psCmd)
}

// execPowerShell runs a PowerShell command and logs it.
func (e *WindowsEnforcer) execPowerShell(psCmd string) error {
	log.Printf("🔒 [FIREWALL] Executing OS Command: powershell -Command %s", psCmd)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell command failed: %s: %s: %w",
			psCmd, strings.TrimSpace(string(output)), err)
	}
	return nil
}

// sanitize replaces characters unsafe for policy names.
func sanitize(s string) string {
	r := strings.NewReplacer(".", "-", "/", "-", ":", "-")
	return r.Replace(s)
}
