package com.hotspotd.sniffer;

import java.util.List;

/**
 * Immutable event object emitted when a DNS query or response is captured.
 */
public final class DnsEvent {
    private final List<String> resolvedIPs;
    private final String domain;
    private final String sourceIP;
    private final boolean isResponse;

    public DnsEvent(List<String> resolvedIPs, String domain, String sourceIP, boolean isResponse) {
        this.resolvedIPs = resolvedIPs;
        this.domain = domain;
        this.sourceIP = sourceIP;
        this.isResponse = isResponse;
    }

    public List<String> getResolvedIPs() {
        return resolvedIPs;
    }

    public String getDomain() {
        return domain;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public boolean isResponse() {
        return isResponse;
    }
}
