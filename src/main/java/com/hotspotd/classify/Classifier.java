package com.hotspotd.classify;

import java.util.Map;

public interface Classifier extends AutoCloseable {
    /**
     * Looks up the classification for an IP address.
     * Returns AppInfo if found, null otherwise.
     */
    AppInfo lookup(String ip);

    /**
     * Updates the IP classification mapping based on a resolved domain.
     */
    void update(String ip, String domain);

    /**
     * Returns a point-in-time copy of all non-expired classifications.
     */
    Map<String, AppInfo> snapshot();

    /**
     * Returns a counter that increments on every new or changed classification.
     */
    long getGeneration();

    /**
     * Flushes any cached in-memory changes to disk.
     */
    void flush() throws Exception;
}
