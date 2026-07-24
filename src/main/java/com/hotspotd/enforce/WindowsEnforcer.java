package com.hotspotd.enforce;

import com.hotspotd.util.ProcessExecutor;

public class WindowsEnforcer implements Enforcer {
    private final ProcessExecutor executor;

    public WindowsEnforcer(ProcessExecutor executor) {
        this.executor = executor;
        System.out.println("⚠️  [WARNING] Windows enforcement is best-effort. Rate-limiting via New-NetQosPolicy " +
                "may require Windows Server + Group Policy to actually take effect.");
    }

    @Override
    public void setupQdisc() throws Exception {
        System.out.println("[SYSTEM] Windows: No root qdisc setup needed (QoS policies are direct).");
    }

    @Override
    public void teardownQdisc() throws Exception {
        String psCmd = "Get-NetQosPolicy | Where-Object { $_.Name -like 'hotspotd-*' } | Remove-NetQosPolicy -Confirm:$false";
        execPowerShell(psCmd);
    }

    @Override
    public void applyRateLimit(String targetGuestIP, String destIPOrCIDR, int speedKbit, String app) throws Exception {
        String policyName = String.format("hotspotd-%s-%s", sanitize(targetGuestIP), sanitize(app));
        long throttleBitsPerSec = (long) speedKbit * 1000;

        String psCmd = String.format(
                "New-NetQosPolicy -Name '%s' -IPDstPrefixMatchCondition '%s' -IPSrcPrefixMatchCondition '%s' -ThrottleRateActionBitsPerSecond %d -Confirm:$false",
                policyName, destIPOrCIDR, targetGuestIP, throttleBitsPerSec);

        execPowerShell(psCmd);
    }

    @Override
    public void removeRateLimit(RuleEntry entry) throws Exception {
        String policyName = String.format("hotspotd-%s-%s", sanitize(entry.getTargetGuestIP()), sanitize(entry.getApp()));
        String psCmd = String.format("Remove-NetQosPolicy -Name '%s' -Confirm:$false", policyName);
        execPowerShell(psCmd);
    }

    private void execPowerShell(String psCmd) throws Exception {
        // Log powershell command execution as OS command.
        executor.execute("powershell", "-NoProfile", "-Command", psCmd);
    }

    private static String sanitize(String s) {
        if (s == null) return "";
        return s.replace(".", "-").replace("/", "-").replace(":", "-");
    }
}
