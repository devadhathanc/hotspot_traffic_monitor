package com.hotspotd.usage;

import com.hotspotd.util.ProcessExecutor;

import java.time.Duration;
import java.time.Instant;

public class MacOSBandwidthTracker implements BandwidthTracker {
    private final String iface;
    private final Instant started;
    private final ProcessExecutor executor;
    private InterfaceStats baseline;
    private InterfaceStats current;

    public MacOSBandwidthTracker(String iface, ProcessExecutor executor) {
        this.iface = iface;
        this.executor = executor;
        this.started = Instant.now();

        try {
            InterfaceStats stats = readInterfaceStats();
            this.baseline = stats;
            this.current = stats;
        } catch (Exception e) {
            this.baseline = new InterfaceStats(0, 0);
            this.current = new InterfaceStats(0, 0);
        }
    }

    @Override
    public synchronized void update() {
        try {
            InterfaceStats stats = readInterfaceStats();
            this.current = stats;
        } catch (Exception e) {
            // Ignore temporary errors.
        }
    }

    @Override
    public synchronized Usage getUsage() {
        long dl = current.getInBytes() - baseline.getInBytes();
        long ul = current.getOutBytes() - baseline.getOutBytes();
        return new Usage(dl, ul, Duration.between(started, Instant.now()));
    }

    private InterfaceStats readInterfaceStats() throws Exception {
        String output = executor.executeQuietly("netstat", "-bI", iface);
        if (output == null || output.trim().isEmpty()) {
            throw new RuntimeException("Empty output from netstat for interface " + iface);
        }
        String[] lines = output.split("\\r?\\n");
        for (int i = 1; i < lines.length; i++) {
            String[] fields = lines[i].trim().split("\\s+");
            if (fields.length < 11 || !fields[0].equals(iface)) {
                continue;
            }
            long ibytes = Long.parseLong(fields[6]);
            long obytes = Long.parseLong(fields[9]);
            return new InterfaceStats(ibytes, obytes);
        }
        throw new RuntimeException("Interface " + iface + " not found in netstat output");
    }
}
