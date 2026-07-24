package com.hotspotd.config;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.hotspotd.util.DurationParser;
import java.time.Duration;
import java.util.*;

public class Config {
    @JsonProperty("interface")
    private String networkInterface = "wlan0";

    @JsonProperty("subnet")
    private String subnet = "192.168.4.0/24";

    @JsonProperty("signatures")
    private List<AppSignature> signatures = new ArrayList<>();

    @JsonProperty("alert_thresholds")
    private AlertThreshold alertThresholds = new AlertThreshold(50 * 1024 * 1024, 5000, "5s");

    @JsonProperty("client_policies")
    private List<ClientPolicy> clientPolicies = new ArrayList<>();

    @JsonProperty("safety_rails")
    private ThrottleSafetyRails safetyRails = new ThrottleSafetyRails(64, "30m");

    @JsonProperty("persistence_ttl")
    private String persistenceTTLString = "24h";

    @JsonProperty("dhcp_lease_file")
    private String dhcpLeaseFile = "/var/lib/misc/dnsmasq.leases";

    @JsonProperty("doh_resolver_ips")
    private List<String> dohResolverIPs = Arrays.asList("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4");

    @JsonProperty("shared_cdn_suffixes")
    private List<String> sharedCDNSuffixes = Arrays.asList(
            "cloudfront.net", "akamaihd.net", "akamaized.net", "fastly.net",
            "cdn.cloudflare.net", "edgecastcdn.net", "llnwd.net"
    );

    @JsonProperty("db_path")
    private String dbPath = "hotspotd.db";

    @JsonProperty("aggressive")
    private boolean aggressive = false;

    @JsonProperty("firewall_backend")
    private String firewallBackend = "nftables";

    // Cached derived collections — built lazily, invalidated on setter calls.
    @JsonIgnore
    private transient Map<String, String> cachedSignatureMap;
    @JsonIgnore
    private transient Set<String> cachedCDNSet;
    @JsonIgnore
    private transient Set<String> cachedDoHSet;
    @JsonIgnore
    private transient Map<String, ClientPolicy> cachedPolicyMap;

    public Config() {}

    public String getNetworkInterface() { return networkInterface; }
    public void setNetworkInterface(String networkInterface) { this.networkInterface = networkInterface; }

    public String getSubnet() { return subnet; }
    public void setSubnet(String subnet) { this.subnet = subnet; }

    public List<AppSignature> getSignatures() { return signatures; }
    public void setSignatures(List<AppSignature> signatures) {
        this.signatures = signatures;
        this.cachedSignatureMap = null; // Invalidate cache.
    }

    public AlertThreshold getAlertThresholds() { return alertThresholds; }
    public void setAlertThresholds(AlertThreshold alertThresholds) { this.alertThresholds = alertThresholds; }

    public List<ClientPolicy> getClientPolicies() { return clientPolicies; }
    public void setClientPolicies(List<ClientPolicy> clientPolicies) {
        this.clientPolicies = clientPolicies;
        this.cachedPolicyMap = null; // Invalidate cache.
    }

    public ThrottleSafetyRails getSafetyRails() { return safetyRails; }
    public void setSafetyRails(ThrottleSafetyRails safetyRails) { this.safetyRails = safetyRails; }

    public String getPersistenceTTLString() { return persistenceTTLString; }
    public void setPersistenceTTLString(String persistenceTTLString) { this.persistenceTTLString = persistenceTTLString; }

    @JsonIgnore
    public Duration getPersistenceTTL() { return DurationParser.parse(persistenceTTLString); }

    public String getDhcpLeaseFile() { return dhcpLeaseFile; }
    public void setDhcpLeaseFile(String dhcpLeaseFile) { this.dhcpLeaseFile = dhcpLeaseFile; }

    public List<String> getDohResolverIPs() { return dohResolverIPs; }
    public void setDohResolverIPs(List<String> dohResolverIPs) {
        this.dohResolverIPs = dohResolverIPs;
        this.cachedDoHSet = null; // Invalidate cache.
    }

    public List<String> getSharedCDNSuffixes() { return sharedCDNSuffixes; }
    public void setSharedCDNSuffixes(List<String> sharedCDNSuffixes) {
        this.sharedCDNSuffixes = sharedCDNSuffixes;
        this.cachedCDNSet = null; // Invalidate cache.
    }

    public String getDbPath() { return dbPath; }
    public void setDbPath(String dbPath) { this.dbPath = dbPath; }

    public boolean isAggressive() { return aggressive; }
    public void setAggressive(boolean aggressive) { this.aggressive = aggressive; }

    public String getFirewallBackend() { return firewallBackend; }
    public void setFirewallBackend(String firewallBackend) { this.firewallBackend = firewallBackend; }

    // --- Cached derived collection helpers ---

    @JsonIgnore
    public Map<String, String> getSignatureMap() {
        if (cachedSignatureMap == null) {
            Map<String, String> map = new HashMap<>();
            if (signatures != null) {
                for (AppSignature sig : signatures) {
                    map.put(sig.getDomainSuffix(), sig.getAppName());
                }
            }
            cachedSignatureMap = Collections.unmodifiableMap(map);
        }
        return cachedSignatureMap;
    }

    @JsonIgnore
    public Set<String> getSharedCDNSet() {
        if (cachedCDNSet == null) {
            cachedCDNSet = sharedCDNSuffixes != null
                    ? Collections.unmodifiableSet(new HashSet<>(sharedCDNSuffixes))
                    : Collections.emptySet();
        }
        return cachedCDNSet;
    }

    @JsonIgnore
    public Set<String> getDoHResolverSet() {
        if (cachedDoHSet == null) {
            cachedDoHSet = dohResolverIPs != null
                    ? Collections.unmodifiableSet(new HashSet<>(dohResolverIPs))
                    : Collections.emptySet();
        }
        return cachedDoHSet;
    }

    @JsonIgnore
    public Map<String, ClientPolicy> getClientPolicyMap() {
        if (cachedPolicyMap == null) {
            Map<String, ClientPolicy> map = new HashMap<>();
            if (clientPolicies != null) {
                for (ClientPolicy policy : clientPolicies) {
                    map.put(policy.getClientIP(), policy);
                }
            }
            cachedPolicyMap = Collections.unmodifiableMap(map);
        }
        return cachedPolicyMap;
    }
}
