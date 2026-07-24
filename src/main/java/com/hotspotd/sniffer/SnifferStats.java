package com.hotspotd.sniffer;

public class SnifferStats {
    private final long dnsQueriesSeen;
    private final long dnsResponsesSeen;
    private final long dohEventsSeen;

    public SnifferStats(long dnsQueriesSeen, long dnsResponsesSeen, long dohEventsSeen) {
        this.dnsQueriesSeen = dnsQueriesSeen;
        this.dnsResponsesSeen = dnsResponsesSeen;
        this.dohEventsSeen = dohEventsSeen;
    }

    public long getDnsQueriesSeen() {
        return dnsQueriesSeen;
    }

    public long getDnsResponsesSeen() {
        return dnsResponsesSeen;
    }

    public long getDohEventsSeen() {
        return dohEventsSeen;
    }
}
