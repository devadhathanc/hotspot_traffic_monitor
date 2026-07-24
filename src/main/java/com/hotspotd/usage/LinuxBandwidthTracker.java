package com.hotspotd.usage;

import com.hotspotd.util.ProcessExecutor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.time.Duration;
import java.time.Instant;

public class LinuxBandwidthTracker implements BandwidthTracker {
    private final String iface;
    private final Instant started;
    private final ProcessExecutor executor;
    private InterfaceStats baseline;
    private InterfaceStats current;

    public LinuxBandwidthTracker(String iface, ProcessExecutor executor) {
        this.iface = iface;
        this.executor = executor;
        this.started = Instant.now();

        InterfaceStats stats = readInterfaceStats();
        this.baseline = stats;
        this.current = stats;
    }

    @Override
    public synchronized void update() {
        this.current = readInterfaceStats();
    }

    @Override
    public synchronized Usage getUsage() {
        long dl = current.getInBytes() - baseline.getInBytes();
        long ul = current.getOutBytes() - baseline.getOutBytes();
        return new Usage(dl, ul, Duration.between(started, Instant.now()));
    }

    private InterfaceStats readInterfaceStats() {
        // Read directly from /proc/net/dev if available
        File sysFile = new File("/proc/net/dev");
        if (sysFile.exists() && sysFile.canRead()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(sysFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith(iface + ":")) {
                        String data = line.substring(iface.length() + 1).trim();
                        String[] fields = data.split("\\s+");
                        if (fields.length >= 9) {
                            long rxBytes = Long.parseLong(fields[0]);
                            long txBytes = Long.parseLong(fields[8]);
                            return new InterfaceStats(rxBytes, txBytes);
                        }
                    }
                }
            } catch (Exception e) {
                // Fallback
            }
        }

        // Fallback to ip -s link show via ProcessExecutor
        try {
            String output = executor.executeQuietly("ip", "-s", "link", "show", iface);
            if (output != null && !output.isEmpty()) {
                String[] lines = output.split("\\r?\\n");
                for (int i = 0; i < lines.length; i++) {
                    if (lines[i].trim().startsWith("RX:")) {
                        String[] rxFields = lines[i + 1].trim().split("\\s+");
                        long rxBytes = Long.parseLong(rxFields[0]);

                        for (int j = i + 2; j < lines.length; j++) {
                            if (lines[j].trim().startsWith("TX:")) {
                                String[] txFields = lines[j + 1].trim().split("\\s+");
                                long txBytes = Long.parseLong(txFields[0]);
                                return new InterfaceStats(rxBytes, txBytes);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }

        return new InterfaceStats(0, 0);
    }
}
