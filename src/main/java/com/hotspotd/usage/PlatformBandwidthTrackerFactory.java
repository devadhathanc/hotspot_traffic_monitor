package com.hotspotd.usage;

import com.hotspotd.util.ProcessExecutor;

/**
 * Factory class that creates platform-specific {@link BandwidthTracker} instances.
 * Adheres to Factory Pattern and Open/Closed Principle (OCP).
 */
public class PlatformBandwidthTrackerFactory {

    /**
     * Creates and returns the appropriate BandwidthTracker for the current platform.
     *
     * @param iface The network interface name.
     * @param executor The ProcessExecutor instance.
     * @return BandwidthTracker implementation.
     */
    public static BandwidthTracker createTracker(String iface, ProcessExecutor executor) {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("mac") || os.contains("darwin")) {
            return new MacOSBandwidthTracker(iface, executor);
        } else {
            return new LinuxBandwidthTracker(iface, executor);
        }
    }
}
