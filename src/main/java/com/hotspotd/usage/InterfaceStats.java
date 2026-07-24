package com.hotspotd.usage;

public class InterfaceStats {
    private final long inBytes;
    private final long outBytes;

    public InterfaceStats(long inBytes, long outBytes) {
        this.inBytes = inBytes;
        this.outBytes = outBytes;
    }

    public long getInBytes() {
        return inBytes;
    }

    public long getOutBytes() {
        return outBytes;
    }
}
