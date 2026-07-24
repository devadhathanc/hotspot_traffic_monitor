package com.hotspotd.config;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AppSignature {
    @JsonProperty("domain_suffix")
    private String domainSuffix;

    @JsonProperty("app_name")
    private String appName;

    public AppSignature() {}

    public AppSignature(String domainSuffix, String appName) {
        this.domainSuffix = domainSuffix;
        this.appName = appName;
    }

    public String getDomainSuffix() {
        return domainSuffix;
    }

    public void setDomainSuffix(String domainSuffix) {
        this.domainSuffix = domainSuffix;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }
}
