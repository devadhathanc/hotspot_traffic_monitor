package com.hotspotd.sniffer;

import java.util.List;

/**
 * Interface defining DNS packet sniffing capabilities.
 * Follows the Dependency Inversion Principle (DIP).
 */
public interface Sniffer {

    /**
     * Registers a listener for DNS events.
     */
    void registerListener(DnsListener listener);

    /**
     * Returns current sniffer metrics.
     */
    SnifferStats getStats();

    /**
     * Returns the current domain generation counter.
     */
    long getDomainGeneration();

    /**
     * Returns a snapshot list of tracked domains.
     */
    List<DomainRecord> getDomains();

    /**
     * Starts live packet sniffing.
     */
    void start() throws Exception;

    /**
     * Stops packet sniffing and releases native pcap handles.
     */
    void stop();
}
