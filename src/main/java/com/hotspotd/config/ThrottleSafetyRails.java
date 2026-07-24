package com.hotspotd.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.hotspotd.util.DurationParser;
import java.time.Duration;

public class ThrottleSafetyRails {
    @JsonProperty("min_kbit_floor")
    private int minKbitFloor = 64;

    @JsonProperty("auto_expire_duration")
    private String autoExpireDurationString = "30m";

    public ThrottleSafetyRails() {}

    public ThrottleSafetyRails(int minKbitFloor, String autoExpireDurationString) {
        this.minKbitFloor = minKbitFloor;
        this.autoExpireDurationString = autoExpireDurationString;
    }

    public int getMinKbitFloor() {
        return minKbitFloor;
    }

    public void setMinKbitFloor(int minKbitFloor) {
        this.minKbitFloor = minKbitFloor;
    }

    public String getAutoExpireDurationString() {
        return autoExpireDurationString;
    }

    public void setAutoExpireDurationString(String autoExpireDurationString) {
        this.autoExpireDurationString = autoExpireDurationString;
    }

    @JsonIgnore
    public Duration getAutoExpireDuration() {
        return DurationParser.parse(autoExpireDurationString);
    }
}
