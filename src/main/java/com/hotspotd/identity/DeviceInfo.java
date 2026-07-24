package com.hotspotd.identity;

import java.time.Instant;

public class DeviceInfo {
    private final String name;
    private final String mac;
    private String ip;
    private final String source; // "dhcp" or "arp"
    private Instant lastSeen;

    public DeviceInfo(String name, String mac, String ip, String source, Instant lastSeen) {
        this.name = name;
        this.mac = mac;
        this.ip = ip;
        this.source = source;
        this.lastSeen = lastSeen;
    }

    public String getName() {
        return name;
    }

    public String getMac() {
        return mac;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getSource() {
        return source;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(Instant lastSeen) {
        this.lastSeen = lastSeen;
    }
}
