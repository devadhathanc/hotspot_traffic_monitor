package com.hotspotd.identity;

import com.hotspotd.util.ProcessExecutor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DhcpArpResolver implements DeviceResolver {
    private final Map<String, DeviceInfo> macCache = new ConcurrentHashMap<>();
    private final Map<String, String> ipToMAC = new ConcurrentHashMap<>();
    private final String dhcpLeaseFile;
    private final ProcessExecutor executor;

    public DhcpArpResolver(String dhcpLeaseFile) {
        this(dhcpLeaseFile, new ProcessExecutor());
    }

    public DhcpArpResolver(String dhcpLeaseFile, ProcessExecutor executor) {
        this.dhcpLeaseFile = dhcpLeaseFile;
        this.executor = executor;
        // Initial population.
        refresh();
    }

    @Override
    public String resolve(String ip) {
        String mac = ipToMAC.get(ip);
        if (mac == null) {
            return null;
        }
        DeviceInfo info = macCache.get(mac);
        if (info == null || info.getName() == null || info.getName().isEmpty()) {
            return null;
        }
        return info.getName();
    }

    @Override
    public String formatDevice(String ip) {
        String name = resolve(ip);
        if (name != null && !name.isEmpty()) {
            return String.format("%s (%s)", ip, name);
        }
        return ip;
    }

    @Override
    public void start(ScheduledExecutorService scheduledExecutor) {
        scheduledExecutor.scheduleWithFixedDelay(this::refresh, 30, 30, TimeUnit.SECONDS);
    }

    private synchronized void refresh() {
        // 1. Parse DHCP lease file (highest priority).
        parseDHCPLeases();

        // 2. Parse ARP table (lower priority, best-effort).
        parseARPTable();
    }

    private void parseDHCPLeases() {
        if (dhcpLeaseFile == null || dhcpLeaseFile.isEmpty()) {
            return;
        }
        File file = new File(dhcpLeaseFile);
        if (!file.exists() || !file.canRead()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.split("\\s+");
                if (fields.length < 4) {
                    continue;
                }
                String mac = fields[1].toLowerCase();
                String ip = fields[2];
                String hostname = fields[3];

                if ("*".equals(hostname)) {
                    hostname = "";
                }

                ipToMAC.put(ip, mac);
                // DHCP source is highest priority — overwrite.
                macCache.put(mac, new DeviceInfo(hostname, mac, ip, "dhcp", Instant.now()));
            }
        } catch (Exception e) {
            // Silently ignore file read exceptions.
        }
    }

    private void parseARPTable() {
        // 1. Try ip neigh via ProcessExecutor
        try {
            String output = executor.executeQuietly("ip", "neigh");
            if (output != null && !output.trim().isEmpty()) {
                String[] lines = output.split("\\r?\\n");
                boolean parsed = false;
                for (String line : lines) {
                    String[] fields = line.trim().split("\\s+");
                    if (fields.length < 5) {
                        continue;
                    }
                    String ip = fields[0];
                    int lladdrIdx = -1;
                    for (int i = 0; i < fields.length; i++) {
                        if ("lladdr".equals(fields[i]) && i + 1 < fields.length) {
                            lladdrIdx = i + 1;
                            break;
                        }
                    }
                    if (lladdrIdx < 0) {
                        continue;
                    }
                    String mac = fields[lladdrIdx].toLowerCase();

                    ipToMAC.put(ip, mac);
                    updateArpCache(mac, ip);
                    parsed = true;
                }
                if (parsed) {
                    return;
                }
            }
        } catch (Exception e) {
            // Fall through to arp -a
        }

        // 2. Fallback to arp -a via ProcessExecutor
        try {
            String output = executor.executeQuietly("arp", "-a");
            if (output != null && !output.trim().isEmpty()) {
                String[] lines = output.split("\\r?\\n");
                Pattern pattern = Pattern.compile("\\((.*?)\\)\\s+at\\s+([a-fA-F0-9:]+)");
                for (String line : lines) {
                    Matcher matcher = pattern.matcher(line);
                    if (matcher.find()) {
                        String ip = matcher.group(1);
                        String mac = matcher.group(2).toLowerCase();
                        if ("(incomplete)".equals(mac)) {
                            continue;
                        }
                        ipToMAC.put(ip, mac);
                        updateArpCache(mac, ip);
                    }
                }
            }
        } catch (Exception e) {
            // Ignore fallback errors.
        }
    }

    private void updateArpCache(String mac, String ip) {
        DeviceInfo existing = macCache.get(mac);
        if (existing == null) {
            macCache.put(mac, new DeviceInfo("", mac, ip, "arp", Instant.now()));
        } else {
            // Update IP mapping but keep existing name.
            existing.setIp(ip);
            existing.setLastSeen(Instant.now());
            macCache.put(mac, existing);
        }
    }
}
