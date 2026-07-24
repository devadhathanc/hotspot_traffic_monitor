package com.hotspotd.enforce;

import java.time.Instant;

/**
 * Immutable data class representing an active traffic enforcement rule.
 */
public final class RuleEntry {
    private final String targetGuestIP;
    private final String destIPOrCIDR;
    private final int speedKbit;
    private final String tcHandle;
    private final String app;
    private final Instant appliedAt;
    private final Instant expiresAt;

    public RuleEntry(String targetGuestIP, String destIPOrCIDR, int speedKbit, String tcHandle, String app, Instant appliedAt, Instant expiresAt) {
        this.targetGuestIP = targetGuestIP;
        this.destIPOrCIDR = destIPOrCIDR;
        this.speedKbit = speedKbit;
        this.tcHandle = tcHandle;
        this.app = app;
        this.appliedAt = appliedAt;
        this.expiresAt = expiresAt;
    }

    public String getTargetGuestIP() {
        return targetGuestIP;
    }

    public String getDestIPOrCIDR() {
        return destIPOrCIDR;
    }

    public int getSpeedKbit() {
        return speedKbit;
    }

    public String getTcHandle() {
        return tcHandle;
    }

    public String getApp() {
        return app;
    }

    public Instant getAppliedAt() {
        return appliedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
