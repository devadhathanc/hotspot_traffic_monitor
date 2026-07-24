package com.hotspotd.enforce;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe registry for rate-limiting enforcement rules.
 * Uses Map lookup for O(1) duplicate checks instead of O(N) linear scanning.
 */
public class EnforceRegistry {
    private final Map<String, RuleEntry> rules = new LinkedHashMap<>();
    private final Enforcer enforcer;
    private final int minKbitFloor;
    private final Duration autoExpireDuration;
    private final boolean aggressive;
    private int handleCounter = 10; // Start at 1:10

    public EnforceRegistry(Enforcer enforcer, int minKbitFloor, Duration autoExpireDuration, boolean aggressive) {
        this.enforcer = enforcer;
        this.minKbitFloor = minKbitFloor;
        this.autoExpireDuration = autoExpireDuration;
        this.aggressive = aggressive;
    }

    private static String makeKey(String targetGuestIP, String destIPOrCIDR) {
        return targetGuestIP + "->" + destIPOrCIDR;
    }

    public synchronized void applyRateLimit(String targetGuestIP, String destIPOrCIDR, int speedKbit, String app, boolean confidenceHigh) throws Exception {
        // Safety rail: never enforce on low-confidence unless aggressive mode is enabled.
        if (!confidenceHigh && !aggressive) {
            System.out.printf("[ENFORCE] Skipping rate-limit for %s→%s (%s): low confidence, aggressive mode disabled%n",
                    targetGuestIP, destIPOrCIDR, app);
            return;
        }

        // Safety rail: enforce minimum speed floor.
        if (speedKbit < minKbitFloor) {
            System.out.printf("[ENFORCE] Clamping speed from %d to %d kbit (minimum floor)%n", speedKbit, minKbitFloor);
            speedKbit = minKbitFloor;
        }

        String ruleKey = makeKey(targetGuestIP, destIPOrCIDR);

        // O(1) duplicate check
        if (rules.containsKey(ruleKey)) {
            System.out.printf("[ENFORCE] Rate-limit already active for %s→%s (%s), skipping%n",
                    targetGuestIP, destIPOrCIDR, app);
            return;
        }

        // Apply rate limit via enforcer.
        enforcer.applyRateLimit(targetGuestIP, destIPOrCIDR, speedKbit, app);

        Instant now = Instant.now();
        Instant expires = now.plus(autoExpireDuration);
        handleCounter++;
        String tcHandle = "1:" + handleCounter;

        RuleEntry entry = new RuleEntry(targetGuestIP, destIPOrCIDR, speedKbit, tcHandle, app, now, expires);
        rules.put(ruleKey, entry);

        System.out.printf("🔒 [ENFORCE] Rate-limit applied: %s→%s (%s) at %d kbit, expires %s%n",
                targetGuestIP, destIPOrCIDR, app, speedKbit,
                DateTimeFormatter.ISO_INSTANT.format(expires));
    }

    public synchronized List<RuleEntry> expireRules() {
        Instant now = Instant.now();
        List<RuleEntry> expired = new ArrayList<>();
        List<String> keysToRemove = new ArrayList<>();

        for (Map.Entry<String, RuleEntry> mapEntry : rules.entrySet()) {
            RuleEntry entry = mapEntry.getValue();
            if (now.isAfter(entry.getExpiresAt())) {
                try {
                    enforcer.removeRateLimit(entry);
                    System.out.printf("🔓 [ENFORCE] Rate-limit expired and removed: %s→%s (%s)%n",
                            entry.getTargetGuestIP(), entry.getDestIPOrCIDR(), entry.getApp());
                } catch (Exception e) {
                    System.err.printf("[WARN] Failed to remove expired rule for %s→%s: %s%n",
                            entry.getTargetGuestIP(), entry.getDestIPOrCIDR(), e.getMessage());
                }
                expired.add(entry);
                keysToRemove.add(mapEntry.getKey());
            }
        }

        for (String k : keysToRemove) {
            rules.remove(k);
        }
        return expired;
    }

    public synchronized void reset() {
        System.out.printf("[ENFORCE] Resetting all rate-limit rules (%d entries)...%n", rules.size());

        for (RuleEntry entry : rules.values()) {
            try {
                enforcer.removeRateLimit(entry);
                System.out.printf("🔓 [ENFORCE] Removed rate-limit: %s→%s (%s)%n",
                        entry.getTargetGuestIP(), entry.getDestIPOrCIDR(), entry.getApp());
            } catch (Exception e) {
                System.err.printf("[WARN] Failed to remove rule for %s→%s: %s%n",
                        entry.getTargetGuestIP(), entry.getDestIPOrCIDR(), e.getMessage());
            }
        }

        try {
            enforcer.teardownQdisc();
        } catch (Exception e) {
            System.err.printf("[WARN] Failed to teardown root qdisc: %s%n", e.getMessage());
        }

        rules.clear();
        System.out.println("[ENFORCE] Reset complete — all rules removed.");
    }

    public synchronized List<RuleEntry> getRules() {
        return new ArrayList<>(rules.values());
    }

    public void startExpiryLoop(ScheduledExecutorService executor, Duration interval) {
        executor.scheduleWithFixedDelay(this::expireRules, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
    }
}
