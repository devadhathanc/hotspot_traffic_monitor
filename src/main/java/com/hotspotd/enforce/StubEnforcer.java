package com.hotspotd.enforce;

public class StubEnforcer implements Enforcer {
    public StubEnforcer(String iface) {
        System.out.println("⚠️  [WARNING] Rate-limit enforcement is not supported on this platform. " +
                "Using stub enforcer (commands will be logged but not executed). " +
                "Deploy on Linux for actual enforcement.");
    }

    @Override
    public void setupQdisc() throws Exception {
        System.out.println("[STUB] setupQdisc (no-op on this platform)");
    }

    @Override
    public void teardownQdisc() throws Exception {
        System.out.println("[STUB] teardownQdisc (no-op on this platform)");
    }

    @Override
    public void applyRateLimit(String targetGuestIP, String destIPOrCIDR, int speedKbit, String app) throws Exception {
        System.out.printf("[STUB] 🔒 Would apply rate-limit: %s→%s (%s) at %d kbit (no-op on this platform)%n",
                targetGuestIP, destIPOrCIDR, app, speedKbit);
    }

    @Override
    public void removeRateLimit(RuleEntry entry) throws Exception {
        System.out.printf("[STUB] 🔓 Would remove rate-limit: %s→%s (%s) (no-op on this platform)%n",
                entry.getTargetGuestIP(), entry.getDestIPOrCIDR(), entry.getApp());
    }
}
