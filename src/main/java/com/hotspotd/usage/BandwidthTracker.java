package com.hotspotd.usage;

import java.time.Duration;

/**
 * Interface for tracking overall network interface bandwidth usage.
 * Follows the Dependency Inversion Principle (DIP) and Open/Closed Principle (OCP).
 */
public interface BandwidthTracker {

    /**
     * Polls the current network interface statistics.
     */
    void update();

    /**
     * Returns the aggregate usage since tracking started.
     */
    Usage getUsage();

    /**
     * Formats bytes into a human-readable string (B, KB, MB, GB).
     */
    static String formatBytes(long b) {
        final long KB = 1024;
        final long MB = 1024 * KB;
        final long GB = 1024 * MB;

        if (b >= GB) {
            return String.format("%.2f GB", (double) b / GB);
        } else if (b >= MB) {
            return String.format("%.2f MB", (double) b / MB);
        } else if (b >= KB) {
            return String.format("%.2f KB", (double) b / KB);
        } else {
            return String.format("%d B", b);
        }
    }
}
