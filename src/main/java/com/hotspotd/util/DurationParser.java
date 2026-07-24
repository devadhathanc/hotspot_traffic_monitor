package com.hotspotd.util;

import java.time.Duration;

/**
 * Utility class for parsing human-readable duration strings (e.g., "5s", "30m", "24h").
 * Extracted from AlertThreshold to adhere to Single Responsibility Principle (SRP).
 */
public final class DurationParser {

    private DurationParser() {
        // Utility class — prevent instantiation.
    }

    /**
     * Parses a human-readable duration string into a {@link Duration}.
     * Supports: ms (milliseconds), s (seconds), m (minutes), h (hours), d (days).
     * Falls back to seconds if no suffix is present.
     *
     * @param s The duration string (e.g., "5s", "30m", "24h", "500ms").
     * @return The parsed Duration.
     * @throws IllegalArgumentException if the format is invalid.
     */
    public static Duration parse(String s) {
        if (s == null || s.trim().isEmpty()) {
            return Duration.ofSeconds(5);
        }
        s = s.trim().toLowerCase();
        try {
            if (s.endsWith("ms")) {
                return Duration.ofMillis(Long.parseLong(s.substring(0, s.length() - 2)));
            } else if (s.endsWith("s")) {
                return Duration.ofSeconds(Long.parseLong(s.substring(0, s.length() - 1)));
            } else if (s.endsWith("m")) {
                return Duration.ofMinutes(Long.parseLong(s.substring(0, s.length() - 1)));
            } else if (s.endsWith("h")) {
                return Duration.ofHours(Long.parseLong(s.substring(0, s.length() - 1)));
            } else if (s.endsWith("d")) {
                return Duration.ofDays(Long.parseLong(s.substring(0, s.length() - 1)));
            }
            return Duration.ofSeconds(Long.parseLong(s));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid duration format: " + s, e);
        }
    }
}
