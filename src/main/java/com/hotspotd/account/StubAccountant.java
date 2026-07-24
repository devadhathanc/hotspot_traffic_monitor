package com.hotspotd.account;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;

public class StubAccountant implements TrafficAccountant {
    @Override
    public void start(ScheduledExecutorService executor, Duration interval) {
        System.out.println("[SYSTEM] Accounting disabled on this platform (using stub accountant).");
    }

    @Override
    public Map<BucketKey, Counter> getCounters() {
        return Collections.emptyMap();
    }

    @Override
    public long getTotalBytes() {
        return 0;
    }

    @Override
    public void close() throws Exception {
        // No-op
    }
}
