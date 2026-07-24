package com.hotspotd.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.hotspotd.util.DurationParser;
import java.time.Duration;

public class AlertThreshold {
    @JsonProperty("bytes_per_interval")
    private long bytesPerInterval;

    @JsonProperty("packets_per_interval")
    private long packetsPerInterval;

    @JsonProperty("interval")
    private String intervalString = "5s";

    public AlertThreshold() {}

    public AlertThreshold(long bytesPerInterval, long packetsPerInterval, String intervalString) {
        this.bytesPerInterval = bytesPerInterval;
        this.packetsPerInterval = packetsPerInterval;
        this.intervalString = intervalString;
    }

    public long getBytesPerInterval() {
        return bytesPerInterval;
    }

    public void setBytesPerInterval(long bytesPerInterval) {
        this.bytesPerInterval = bytesPerInterval;
    }

    public long getPacketsPerInterval() {
        return packetsPerInterval;
    }

    public void setPacketsPerInterval(long packetsPerInterval) {
        this.packetsPerInterval = packetsPerInterval;
    }

    public String getIntervalString() {
        return intervalString;
    }

    public void setIntervalString(String intervalString) {
        this.intervalString = intervalString;
    }

    @JsonIgnore
    public Duration getInterval() {
        return DurationParser.parse(intervalString);
    }
}
