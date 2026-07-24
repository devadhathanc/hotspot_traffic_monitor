package com.hotspotd.alert;

import com.hotspotd.account.BucketKey;
import com.hotspotd.account.Counter;
import com.hotspotd.account.TrafficAccountant;
import com.hotspotd.classify.AppInfo;
import com.hotspotd.classify.Classifier;
import com.hotspotd.classify.Confidence;
import com.hotspotd.config.AlertThreshold;
import com.hotspotd.config.ClientPolicy;
import com.hotspotd.config.Config;
import com.hotspotd.identity.DeviceResolver;
import com.hotspotd.sniffer.DomainRecord;
import com.hotspotd.sniffer.Sniffer;
import com.hotspotd.sniffer.SnifferStats;
import com.hotspotd.usage.BandwidthTracker;
import com.hotspotd.usage.Usage;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AlertMonitor {
    private final TrafficAccountant accountant;
    private final Classifier classifier;
    private final DeviceResolver resolver;
    private final Sniffer sniffer;
    private final Config cfg;
    private final BandwidthTracker tracker;

    private long lastDomainGen = -1;
    private final DateTimeFormatter timeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    public AlertMonitor(TrafficAccountant accountant, Classifier classifier, DeviceResolver resolver,
                        Sniffer sniffer, Config cfg, BandwidthTracker tracker) {
        this.accountant = accountant;
        this.classifier = classifier;
        this.resolver = resolver;
        this.sniffer = sniffer;
        this.cfg = cfg;
        this.tracker = tracker;
    }

    public void start(ScheduledExecutorService executor) {
        Duration interval = cfg.getAlertThresholds().getInterval();
        executor.scheduleWithFixedDelay(this::evaluate, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }

    private synchronized void evaluate() {
        try {
            Map<BucketKey, Counter> counters = accountant.getCounters();
            Map<String, AppInfo> snapshot = classifier.snapshot();

            // Update interface bandwidth.
            tracker.update();

            // Check thresholds and emit warnings.
            checkThresholds(counters, snapshot);

            // Reprint table if new domains appear.
            long gen = sniffer.getDomainGeneration();
            if (gen != lastDomainGen) {
                lastDomainGen = gen;
                printTable();
            }
        } catch (Exception e) {
            System.err.printf("[WARN] Error evaluating alerts: %s%n", e.getMessage());
        }
    }

    private void checkThresholds(Map<BucketKey, Counter> counters, Map<String, AppInfo> snapshot) {
        Map<String, ClientPolicy> policyMap = cfg.getClientPolicyMap();

        for (Map.Entry<BucketKey, Counter> entry : counters.entrySet()) {
            BucketKey key = entry.getKey();
            Counter counter = entry.getValue();

            // Aggressive mode check: skip low confidence unless aggressive is enabled.
            if (!cfg.isAggressive()) {
                boolean hasHighConfidence = false;
                for (AppInfo info : snapshot.values()) {
                    if (info.getApp().equals(key.getApp()) && info.getConfidence() == Confidence.HIGH) {
                        hasHighConfidence = true;
                        break;
                    }
                }
                if (!hasHighConfidence) {
                    continue;
                }
            }

            AlertThreshold threshold = cfg.getAlertThresholds();
            ClientPolicy policy = policyMap.get(key.getClientIP());
            if (policy != null) {
                if (policy.isExempt()) {
                    continue;
                }
                if (policy.getAlertThreshold() != null) {
                    threshold = policy.getAlertThreshold();
                }
            }

            if (counter.getBytes() > threshold.getBytesPerInterval() ||
                    counter.getPackets() > threshold.getPacketsPerInterval()) {
                String deviceStr = resolver.formatDevice(key.getClientIP());
                System.out.printf("⚠️  [WARNING] Client %s heavy on %s (Bytes: %s, Packets: %d)%n",
                        deviceStr, key.getApp(), BandwidthTracker.formatBytes(counter.getBytes()), counter.getPackets());
            }
        }
    }

    private void printTable() {
        List<DomainRecord> domainList = sniffer.getDomains();
        if (domainList.isEmpty()) {
            return;
        }

        // Group by app name. Unclassified go to "Others".
        Map<String, List<DomainRecord>> groups = new HashMap<>();
        for (DomainRecord d : domainList) {
            String app = d.getApp();
            if (app == null || app.isEmpty()) {
                app = "Others";
            }
            groups.computeIfAbsent(app, k -> new ArrayList<>()).add(d);
        }

        // Sort each group by last seen (most recent first).
        for (List<DomainRecord> recs : groups.values()) {
            recs.sort((a, b) -> b.getLastSeen().compareTo(a.getLastSeen()));
        }

        // Build sorted app list: named apps first (sorted), "Others" last.
        List<String> appOrder = new ArrayList<>();
        for (String app : groups.keySet()) {
            if (!"Others".equals(app)) {
                appOrder.add(app);
            }
        }
        Collections.sort(appOrder);
        if (groups.containsKey("Others")) {
            appOrder.add("Others");
        }

        String rowFmt = "| %-8s | %-31s | %-40s | %-8s |\n";
        String sep = "+----------+---------------------------------+------------------------------------------+----------+";

        StringBuilder sb = new StringBuilder();
        sb.append("\n").append(sep).append("\n");
        sb.append(String.format(rowFmt, "App", "Domain", "Resolved IPs", "LastSeen"));
        sb.append(sep).append("\n");

        for (String app : appOrder) {
            List<DomainRecord> recs = groups.get(app);
            for (int i = 0; i < recs.size(); i++) {
                DomainRecord d = recs.get(i);
                String appCol = (i == 0) ? app : "";
                String ipStr = String.join(", ", d.getIps() == null ? Collections.emptyList() : d.getIps());

                sb.append(String.format(rowFmt,
                        trunc(appCol, 8),
                        trunc(d.getDomain(), 31),
                        trunc(ipStr, 40),
                        timeFormatter.format(d.getLastSeen())
                ));
            }
            sb.append(sep).append("\n");
        }

        // Footer.
        SnifferStats stats = sniffer.getStats();
        Usage u = tracker.getUsage();
        long totalSeconds = u.getDuration().getSeconds();
        String dur = String.format("%dm%ds", totalSeconds / 60, totalSeconds % 60);

        sb.append(String.format(rowFmt,
                domainList.size() + " dom",
                "Down: " + BandwidthTracker.formatBytes(u.getDownload()),
                "Up: " + BandwidthTracker.formatBytes(u.getUpload()) + "  |  Total: " + BandwidthTracker.formatBytes(u.getDownload() + u.getUpload()),
                dur
        ));

        sb.append(String.format(rowFmt,
                "",
                "Queries: " + stats.getDnsQueriesSeen(),
                "Responses: " + stats.getDnsResponsesSeen(),
                ""
        ));
        sb.append(sep).append("\n");

        System.out.print(sb.toString());
    }

    private static String trunc(String s, int maxLen) {
        if (s == null) return "";
        if (s.length() <= maxLen) {
            return s;
        }
        if (maxLen <= 3) {
            return s.substring(0, maxLen);
        }
        return s.substring(0, maxLen - 3) + "...";
    }
}
