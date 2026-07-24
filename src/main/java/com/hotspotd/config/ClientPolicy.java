package com.hotspotd.config;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ClientPolicy {
    @JsonProperty("client_ip")
    private String clientIP;

    @JsonProperty("throttle_kbit")
    private Integer throttleKbit;

    @JsonProperty("alert_threshold")
    private AlertThreshold alertThreshold;

    @JsonProperty("exempt")
    private boolean exempt;

    public ClientPolicy() {}

    public String getClientIP() {
        return clientIP;
    }

    public void setClientIP(String clientIP) {
        this.clientIP = clientIP;
    }

    public Integer getThrottleKbit() {
        return throttleKbit;
    }

    public void setThrottleKbit(Integer throttleKbit) {
        this.throttleKbit = throttleKbit;
    }

    public AlertThreshold getAlertThreshold() {
        return alertThreshold;
    }

    public void setAlertThreshold(AlertThreshold alertThreshold) {
        this.alertThreshold = alertThreshold;
    }

    public boolean isExempt() {
        return exempt;
    }

    public void setExempt(boolean exempt) {
        this.exempt = exempt;
    }
}
