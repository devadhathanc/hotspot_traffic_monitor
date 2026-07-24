package com.hotspotd.account;

import java.util.Objects;

public class BucketKey {
    private final String clientIP;
    private final String app;

    public BucketKey(String clientIP, String app) {
        this.clientIP = clientIP;
        this.app = app;
    }

    public String getClientIP() {
        return clientIP;
    }

    public String getApp() {
        return app;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BucketKey bucketKey = (BucketKey) o;
        return Objects.equals(clientIP, bucketKey.clientIP) && Objects.equals(app, bucketKey.app);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientIP, app);
    }

    @Override
    public String toString() {
        return "BucketKey{" +
                "clientIP='" + clientIP + '\'' +
                ", app='" + app + '\'' +
                '}';
    }
}
