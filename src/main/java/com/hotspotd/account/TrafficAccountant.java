package com.hotspotd.account;

import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.time.Duration;

public interface TrafficAccountant extends AutoCloseable {
    /**
     * Starts the accounting rule synchronization and counter polling.
     */
    void start(ScheduledExecutorService executor, Duration interval);

    /**
     * Returns a snapshot of current traffic counters.
     */
    Map<BucketKey, Counter> getCounters();

    /**
     * Returns total bytes counted across all buckets.
     */
    long getTotalBytes();
}
