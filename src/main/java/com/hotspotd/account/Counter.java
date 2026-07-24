package com.hotspotd.account;

public class Counter {
    private final long bytes;
    private final long packets;

    public Counter(long bytes, long packets) {
        this.bytes = bytes;
        this.packets = packets;
    }

    public long getBytes() {
        return bytes;
    }

    public long getPackets() {
        return packets;
    }

    @Override
    public String toString() {
        return "Counter{" +
                "bytes=" + bytes +
                ", packets=" + packets +
                '}';
    }
}
