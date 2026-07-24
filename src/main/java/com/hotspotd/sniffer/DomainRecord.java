package com.hotspotd.sniffer;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Thread-safe container for tracked domain metadata.
 * Access to mutable fields (ips, app, lastSeen) is synchronized, while queryCnt uses AtomicInteger.
 */
public class DomainRecord {
    private final String domain;
    private List<String> ips = Collections.emptyList();
    private String app = ""; // classified app name, or empty
    private Instant lastSeen = Instant.now();
    private final AtomicInteger queryCnt = new AtomicInteger(0);

    public DomainRecord(String domain) {
        this.domain = domain;
    }

    public String getDomain() {
        return domain;
    }

    public synchronized List<String> getIps() {
        return ips;
    }

    public synchronized void setIps(List<String> ips) {
        this.ips = ips != null ? Collections.unmodifiableList(ips) : Collections.emptyList();
    }

    public synchronized String getApp() {
        return app;
    }

    public synchronized void setApp(String app) {
        this.app = app != null ? app : "";
    }

    public synchronized Instant getLastSeen() {
        return lastSeen;
    }

    public synchronized void setLastSeen(Instant lastSeen) {
        this.lastSeen = lastSeen;
    }

    public int getQueryCnt() {
        return queryCnt.get();
    }

    public void incrementQueryCount() {
        this.queryCnt.incrementAndGet();
    }
}
