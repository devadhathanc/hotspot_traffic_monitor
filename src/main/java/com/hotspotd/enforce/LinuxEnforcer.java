package com.hotspotd.enforce;

import com.hotspotd.util.ProcessExecutor;

public class LinuxEnforcer implements Enforcer {
    private final String iface;
    private final String backend; // "nftables" or "iptables"
    private final ProcessExecutor executor;

    public LinuxEnforcer(String iface, String backend, ProcessExecutor executor) {
        this.iface = iface;
        this.backend = backend;
        this.executor = executor;
    }

    @Override
    public void setupQdisc() throws Exception {
        // Delete existing root qdisc first (ignore failure).
        executor.executeQuietly("tc", "qdisc", "del", "dev", iface, "root");

        // Create root HTB qdisc.
        executor.execute("tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "99");

        // Create default class with high bandwidth (uncapped).
        executor.execute("tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:99",
                "htb", "rate", "1000mbit", "ceil", "1000mbit");

        System.out.printf("🔒 [FIREWALL] Root HTB qdisc created on %s%n", iface);
    }

    @Override
    public void teardownQdisc() throws Exception {
        executor.execute("tc", "qdisc", "del", "dev", iface, "root");
    }

    @Override
    public void applyRateLimit(String targetGuestIP, String destIPOrCIDR, int speedKbit, String app) throws Exception {
        String handle = ipToHandle(targetGuestIP, destIPOrCIDR);
        String rate = speedKbit + "kbit";

        // Create HTB class for this throttle.
        executor.execute("tc", "class", "add", "dev", iface,
                "parent", "1:", "classid", handle,
                "htb", "rate", rate, "ceil", rate);

        // Add a TBF qdisc under the class for burst control (best effort).
        String subH = subHandle(handle);
        executor.executeQuietly("tc", "qdisc", "add", "dev", iface,
                "parent", handle, "handle", subH,
                "tbf", "rate", rate, "burst", "32kbit", "latency", "400ms");

        // Create iptables/nftables mark rule.
        String mark = handleToMark(handle);
        addMarkRule(targetGuestIP, destIPOrCIDR, mark, app);

        // Create tc filter to match the mark and direct traffic to our class.
        executor.execute("tc", "filter", "add", "dev", iface,
                "parent", "1:", "protocol", "ip", "prio", "1",
                "handle", mark, "fw", "classid", handle);
    }

    @Override
    public void removeRateLimit(RuleEntry entry) throws Exception {
        String handle = ipToHandle(entry.getTargetGuestIP(), entry.getDestIPOrCIDR());
        String mark = handleToMark(handle);

        // Remove tc filter.
        executor.executeQuietly("tc", "filter", "del", "dev", iface,
                "parent", "1:", "protocol", "ip", "prio", "1",
                "handle", mark, "fw", "classid", handle);

        // Remove tc class.
        executor.executeQuietly("tc", "class", "del", "dev", iface, "classid", handle);

        // Remove firewall mark rule.
        removeMarkRule(entry.getTargetGuestIP(), entry.getDestIPOrCIDR(), mark, entry.getApp());
    }

    private void addMarkRule(String srcIP, String dstIP, String mark, String app) throws Exception {
        String comment = String.format("hotspotd-enforce:%s:%s", dstIP, app);
        if ("nftables".equalsIgnoreCase(backend)) {
            // Split command properly.
            executor.execute("nft", "add", "rule", "ip", "hotspotd", "HOTSPOTD_ENFORCE",
                    "ip", "saddr", srcIP, "ip", "daddr", dstIP, "meta", "mark", "set", mark,
                    "comment", "\"" + comment + "\"");
        } else {
            executor.execute("iptables", "-t", "mangle", "-A", "FORWARD",
                    "-s", srcIP, "-d", dstIP,
                    "-j", "MARK", "--set-mark", mark,
                    "-m", "comment", "--comment", comment);
        }
    }

    private void removeMarkRule(String srcIP, String dstIP, String mark, String app) {
        String comment = String.format("hotspotd-enforce:%s:%s", dstIP, app);
        if ("nftables".equalsIgnoreCase(backend)) {
            System.out.printf("[ENFORCE] Removing nftables mark rule for %s→%s (best-effort)%n", srcIP, dstIP);
            executor.executeQuietly("nft", "flush", "chain", "ip", "hotspotd", "HOTSPOTD_ENFORCE");
        } else {
            executor.executeQuietly("iptables", "-t", "mangle", "-D", "FORWARD",
                    "-s", srcIP, "-d", dstIP,
                    "-j", "MARK", "--set-mark", mark,
                    "-m", "comment", "--comment", comment);
        }
    }

    private static String ipToHandle(String srcIP, String dstIP) {
        int h = 0;
        String combined = srcIP + dstIP;
        for (int i = 0; i < combined.length(); i++) {
            h = (h * 31 + combined.charAt(i)) & 0xFFFF;
        }
        h = (h % 9989) + 10;
        if (h == 99) {
            h = 100;
        }
        return "1:" + h;
    }

    private static String subHandle(String classHandle) {
        int minor = Integer.parseInt(classHandle.substring(2));
        return minor + ":";
    }

    private static String handleToMark(String handle) {
        int minor = Integer.parseInt(handle.substring(2));
        return "0x" + Integer.toHexString(minor);
    }
}
