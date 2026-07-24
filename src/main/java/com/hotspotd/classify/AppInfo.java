package com.hotspotd.classify;

import java.time.Instant;

/**
 * Immutable value object representing a classified IP's associated application.
 * Thread-safe by design — once constructed, state never changes.
 */
public final class AppInfo {
    private final String app;
    private final Confidence confidence;
    private final String domain;
    private final Instant lastSeen;

    public AppInfo(String app, Confidence confidence, String domain, Instant lastSeen) {
        this.app = app;
        this.confidence = confidence;
        this.domain = domain;
        this.lastSeen = lastSeen;
    }

    public String getApp() {
        return app;
    }

    public Confidence getConfidence() {
        return confidence;
    }

    public String getDomain() {
        return domain;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    @Override
    public String toString() {
        return "AppInfo{" +
                "app='" + app + '\'' +
                ", confidence=" + confidence +
                ", domain='" + domain + '\'' +
                ", lastSeen=" + lastSeen +
                '}';
    }
}
