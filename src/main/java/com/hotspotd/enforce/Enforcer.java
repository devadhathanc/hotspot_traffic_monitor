package com.hotspotd.enforce;

public interface Enforcer {
    /**
     * Throttles traffic from targetGuestIP to destIPOrCIDR at the given speed.
     */
    void applyRateLimit(String targetGuestIP, String destIPOrCIDR, int speedKbit, String app) throws Exception;

    /**
     * Removes the rate limit rule.
     */
    void removeRateLimit(RuleEntry entry) throws Exception;

    /**
     * Creates the root qdisc or QoS root configuration.
     */
    void setupQdisc() throws Exception;

    /**
     * Removes the root qdisc or QoS configuration.
     */
    void teardownQdisc() throws Exception;
}
