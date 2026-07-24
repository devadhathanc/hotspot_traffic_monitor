package com.hotspotd.account;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hotspotd.classify.AppInfo;
import com.hotspotd.classify.Classifier;
import com.hotspotd.util.ProcessExecutor;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class LinuxFirewallAccountant implements TrafficAccountant {
    private final Map<BucketKey, Counter> counters = new ConcurrentHashMap<>();
    private final Set<String> managedRules = ConcurrentHashMap.newKeySet();

    private final Classifier classifier;
    private final String iface;
    private final String subnet;
    private final String backend; // "nftables" or "iptables"
    private final ProcessExecutor executor;
    private final ObjectMapper mapper = new ObjectMapper();

    private final String chainName = "HOTSPOTD_ACCT";
    private final String tableName = "hotspotd";
    private final AtomicBoolean chainReady = new AtomicBoolean(false);

    public LinuxFirewallAccountant(Classifier classifier, String iface, String subnet, String backend, ProcessExecutor executor) {
        this.classifier = classifier;
        this.iface = iface;
        this.subnet = subnet;
        this.backend = backend;
        this.executor = executor;
    }

    @Override
    public void start(ScheduledExecutorService scheduledExecutor, Duration interval) {
        try {
            setupChain();
            chainReady.set(true);
        } catch (Exception e) {
            System.err.printf("[WARN] Accounting disabled — firewall tools not available (expected on macOS): %s%n", e.getMessage());
            chainReady.set(false);
        }

        scheduledExecutor.scheduleWithFixedDelay(() -> {
            if (chainReady.get()) {
                try {
                    syncRules();
                    pollCounters();
                } catch (Exception e) {
                    System.err.printf("[WARN] Error in accounting loop: %s%n", e.getMessage());
                }
            }
        }, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    @Override
    public Map<BucketKey, Counter> getCounters() {
        return new HashMap<>(counters);
    }

    @Override
    public long getTotalBytes() {
        long total = 0;
        for (Counter c : counters.values()) {
            total += c.getBytes();
        }
        return total;
    }

    private void syncRules() {
        Map<String, AppInfo> snapshot = classifier.snapshot();
        for (Map.Entry<String, AppInfo> entry : snapshot.entrySet()) {
            String destIP = entry.getKey();
            if (managedRules.contains(destIP)) {
                continue;
            }
            try {
                insertRule(destIP, entry.getValue().getApp());
                managedRules.add(destIP);
            } catch (Exception e) {
                System.err.printf("[WARN] Failed to insert accounting rule for %s (%s): %s%n", destIP, entry.getValue().getApp(), e.getMessage());
            }
        }
    }

    private void pollCounters() {
        if ("nftables".equalsIgnoreCase(backend)) {
            pollNftables();
        } else {
            pollIptables();
        }
    }

    private void setupChain() throws Exception {
        if ("nftables".equalsIgnoreCase(backend)) {
            // Create table.
            executor.execute("nft", "add", "table", "ip", tableName);
            // Create chain.
            executor.execute("nft", "add", "chain", "ip", tableName, chainName,
                    "{", "type", "filter", "hook", "forward", "priority", "0", ";", "policy", "accept", ";", "}");
        } else {
            // Create chain (ignore error if exists).
            executor.executeQuietly("iptables", "-N", chainName);
            // Insert jump.
            executor.executeQuietly("iptables", "-I", "FORWARD", "-j", chainName);
        }
    }

    private void insertRule(String destIP, String app) throws Exception {
        String comment = String.format("hotspotd:%s:%s", destIP, app);
        if ("nftables".equalsIgnoreCase(backend)) {
            executor.execute("nft", "add", "rule", "ip", tableName, chainName, "ip", "daddr", destIP, "counter", "comment", "\"" + comment + "\"");
        } else {
            executor.execute("iptables", "-A", chainName, "-d", destIP, "-j", "ACCEPT", "-m", "comment", "--comment", comment);
        }
    }

    private void pollNftables() {
        try {
            String output = executor.execute("nft", "-j", "list", "chain", "ip", tableName, chainName);
            JsonNode root = mapper.readTree(output);
            JsonNode nftables = root.get("nftables");
            if (nftables == null || !nftables.isArray()) {
                return;
            }

            for (JsonNode item : nftables) {
                JsonNode ruleNode = item.get("rule");
                if (ruleNode == null) {
                    continue;
                }
                JsonNode commentNode = ruleNode.get("comment");
                if (commentNode == null || !commentNode.asText().startsWith("hotspotd:")) {
                    continue;
                }

                String comment = commentNode.asText();
                String[] parts = comment.split(":", 3);
                if (parts.length != 3) {
                    continue;
                }
                String app = parts[2];

                JsonNode exprNode = ruleNode.get("expr");
                if (exprNode != null && exprNode.isArray()) {
                    for (JsonNode expr : exprNode) {
                        JsonNode counterNode = expr.get("counter");
                        if (counterNode != null) {
                            long bytes = counterNode.get("bytes").asLong();
                            long packets = counterNode.get("packets").asLong();
                            BucketKey key = new BucketKey("all", app);
                            counters.put(key, new Counter(bytes, packets));
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Silence parsing/exec exceptions in periodic loops.
        }
    }

    private void pollIptables() {
        try {
            String output = executor.execute("iptables", "-L", chainName, "-v", "-n", "-x");
            String[] lines = output.split("\\r?\\n");
            for (String line : lines) {
                line = line.trim();
                if (!line.contains("hotspotd:")) {
                    continue;
                }
                String[] fields = line.split("\\s+");
                if (fields.length < 10) {
                    continue;
                }

                long packets = Long.parseLong(fields[0]);
                long bytes = Long.parseLong(fields[1]);

                int commentIdx = line.indexOf("hotspotd:");
                if (commentIdx < 0) {
                    continue;
                }
                String comment = line.substring(commentIdx);
                String[] parts = comment.split(":", 3);
                if (parts.length != 3) {
                    continue;
                }
                String app = parts[2].trim();

                BucketKey key = new BucketKey("all", app);
                counters.put(key, new Counter(bytes, packets));
            }
        } catch (Exception e) {
            // Silence exceptions in loop.
        }
    }

    private void cleanup() {
        System.out.println("[SYSTEM] Cleaning up accounting rules...");
        if ("nftables".equalsIgnoreCase(backend)) {
            executor.executeQuietly("nft", "flush", "chain", "ip", tableName, chainName);
            executor.executeQuietly("nft", "delete", "chain", "ip", tableName, chainName);
            executor.executeQuietly("nft", "delete", "table", "ip", tableName);
        } else {
            executor.executeQuietly("iptables", "-D", "FORWARD", "-j", chainName);
            executor.executeQuietly("iptables", "-F", chainName);
            executor.executeQuietly("iptables", "-X", chainName);
        }
    }

    @Override
    public void close() throws Exception {
        if (chainReady.get()) {
            cleanup();
        }
    }
}
