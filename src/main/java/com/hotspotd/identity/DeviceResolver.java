package com.hotspotd.identity;

import java.util.concurrent.ScheduledExecutorService;

public interface DeviceResolver {
    /**
     * Resolves the IP address to a hostname.
     * Returns the name, or null if unknown.
     */
    String resolve(String ip);

    /**
     * Formats the device IP and hostname for display (e.g. "192.168.2.10 (Phone)").
     */
    String formatDevice(String ip);

    /**
     * Starts periodic identity refresh (every 30s) running on the provided executor.
     */
    void start(ScheduledExecutorService executor);
}
