package com.hotspotd.classify;

public enum Confidence {
    HIGH("high"),
    LOW("low");

    private final String value;

    Confidence(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Confidence fromValue(String value) {
        for (Confidence c : Confidence.values()) {
            if (c.value.equalsIgnoreCase(value)) {
                return c;
            }
        }
        return LOW;
    }
}
