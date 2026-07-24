package com.hotspotd.sniffer;

import com.hotspotd.classify.AppInfo;
import com.hotspotd.classify.Classifier;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

import java.net.InetAddress;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

public class DnsSniffer implements Sniffer {
    private final String iface;
    private final String subnet;
    private final Classifier classifier;
    private final Set<String> dohResolverSet;

    // Atomic stats counters.
    private final AtomicLong dnsQueries = new AtomicLong(0);
    private final AtomicLong dnsResponses = new AtomicLong(0);
    private final AtomicLong dohEvents = new AtomicLong(0);

    // Track domains.
    private final Map<String, DomainRecord> domains = new ConcurrentHashMap<>();
    private final AtomicLong domainGen = new AtomicLong(0);

    // Listeners for DNS events.
    private final List<DnsListener> listeners = new CopyOnWriteArrayList<>();
    private PcapHandle handle;
    private ExecutorService captureExecutor;

    public DnsSniffer(String iface, String subnet, Classifier classifier, Set<String> dohResolverSet) {
        this.iface = iface;
        this.subnet = subnet;
        this.classifier = classifier;
        this.dohResolverSet = dohResolverSet;
    }

    public void registerListener(DnsListener listener) {
        listeners.add(listener);
    }

    public SnifferStats getStats() {
        return new SnifferStats(dnsQueries.get(), dnsResponses.get(), dohEvents.get());
    }

    public long getDomainGeneration() {
        return domainGen.get();
    }

    public List<DomainRecord> getDomains() {
        return new ArrayList<>(domains.values());
    }

    private void trackDomain(String domain, List<String> ips, String app) {
        DomainRecord rec = domains.computeIfAbsent(domain, d -> {
            domainGen.incrementAndGet();
            return new DomainRecord(d);
        });
        rec.setIps(ips);
        rec.setLastSeen(Instant.now());
        rec.incrementQueryCount();
        if (app != null && !app.isEmpty()) {
            rec.setApp(app);
        }
    }

    public void start() throws Exception {
        System.out.printf("📡 [SYSTEM] Listening on interface: %s (Subnet: %s)%n", iface, subnet);

        PcapNetworkInterface nif = Pcaps.getDevByName(iface);
        if (nif == null) {
            throw new IllegalArgumentException("Network interface not found: " + iface);
        }

        // Open live capture. Timeout of 10ms (passed as int milliseconds directly).
        handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 10);

        // Set BPF filter.
        String bpfFilter = buildBPFFilter();
        handle.setFilter(bpfFilter, BpfProgram.BpfCompileMode.OPTIMIZE);

        // Buffered queue and single background worker for event processing (decoupled capture/consume pattern).
        BlockingQueue<DnsEvent> eventQueue = new LinkedBlockingQueue<>(1024);

        // Event consumer thread.
        Thread consumerThread = new Thread(() -> {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    DnsEvent event = eventQueue.take();
                    if (event.isResponse()) {
                        dnsResponses.incrementAndGet();
                        String classifiedApp = null;
                        for (String ip : event.getResolvedIPs()) {
                            classifier.update(ip, event.getDomain());
                            if (classifiedApp == null) {
                                AppInfo info = classifier.lookup(ip);
                                if (info != null) {
                                    classifiedApp = info.getApp();
                                }
                            }
                        }
                        trackDomain(event.getDomain(), event.getResolvedIPs(), classifiedApp);
                    } else {
                        dnsQueries.incrementAndGet();
                    }

                    // Fire listeners
                    for (DnsListener listener : listeners) {
                        listener.onDnsEvent(event);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "dns-sniffer-consumer");
        consumerThread.setDaemon(true);
        consumerThread.start();

        // Capture worker.
        captureExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "dns-sniffer-capture");
            t.setDaemon(true);
            return t;
        });

        captureExecutor.submit(() -> {
            try {
                handle.loop(-1, (Packet packet) -> {
                    try {
                        processPacket(packet, eventQueue);
                    } catch (Exception e) {
                        // Suppress packet processing errors in capture loop.
                    }
                });
            } catch (PcapNativeException | InterruptedException e) {
                // Stopped.
            } catch (NotOpenException e) {
                System.err.println("[WARN] Capture handle was closed.");
            }
        });
    }

    private void processPacket(Packet packet, BlockingQueue<DnsEvent> eventQueue) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet == null) {
            return;
        }
        String srcIP = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
        String dstIP = ipV4Packet.getHeader().getDstAddr().getHostAddress();

        // Check for DoH.
        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            if (srcPort == 443 || dstPort == 443) {
                if (dohResolverSet.contains(dstIP)) {
                    dohEvents.incrementAndGet();
                }
            }
            return;
        }

        // Parse UDP DNS.
        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket == null) {
            return;
        }

        DnsPacket dnsPacket = packet.get(DnsPacket.class);
        if (dnsPacket == null) {
            return;
        }

        DnsPacket.DnsHeader header = dnsPacket.getHeader();
        List<DnsQuestion> questions = header.getQuestions();
        if (questions.isEmpty()) {
            return;
        }
        String domain = questions.get(0).getQName().toString();

        if (header.isResponse()) {
            List<String> resolvedIPs = new ArrayList<>();
            for (DnsResourceRecord answer : header.getAnswers()) {
                DnsResourceRecordType type = answer.getDataType();
                if (DnsResourceRecordType.A.equals(type) || DnsResourceRecordType.AAAA.equals(type)) {
                    try {
                        byte[] rdata = answer.getRData().getRawData();
                        InetAddress addr = InetAddress.getByAddress(rdata);
                        resolvedIPs.add(addr.getHostAddress());
                    } catch (Exception e) {
                        // Ignore parse exceptions for individual records.
                    }
                }
            }

            if (!resolvedIPs.isEmpty()) {
                DnsEvent event = new DnsEvent(resolvedIPs, domain, srcIP, true);
                if (!eventQueue.offer(event)) {
                    System.err.printf("[WARN] DNS event queue full, dropping response for %s%n", domain);
                }
            }
        } else {
            DnsEvent event = new DnsEvent(Collections.emptyList(), domain, srcIP, false);
            eventQueue.offer(event);
        }
    }

    private String buildBPFFilter() {
        List<String> parts = new ArrayList<>();

        if (subnet != null && !subnet.isEmpty()) {
            // Pcap BPF filter natively supports CIDRs.
            parts.add(String.format("(udp port 53 and net %s)", subnet));
        } else {
            parts.add("(udp port 53)");
        }

        if (!dohResolverSet.isEmpty()) {
            List<String> dohParts = new ArrayList<>();
            for (String ip : dohResolverSet) {
                dohParts.add("dst host " + ip);
            }
            parts.add(String.format("(tcp port 443 and (%s))", String.join(" or ", dohParts)));
        }

        return String.join(" or ", parts);
    }

    public void stop() {
        if (handle != null) {
            try {
                handle.breakLoop();
            } catch (Exception e) {
                // Ignore.
            }
            handle.close();
        }
        if (captureExecutor != null) {
            captureExecutor.shutdownNow();
        }
    }
}
