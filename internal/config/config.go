// Package config loads and merges hotspotd configuration from YAML files and CLI flags.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AppSignature maps a domain suffix to an application name.
type AppSignature struct {
	DomainSuffix string `yaml:"domain_suffix"`
	AppName      string `yaml:"app_name"`
}

// AlertThreshold defines bytes/packet limits per interval.
type AlertThreshold struct {
	BytesPerInterval   int64         `yaml:"bytes_per_interval"`
	PacketsPerInterval int64         `yaml:"packets_per_interval"`
	Interval           time.Duration `yaml:"interval"`
}

// ClientPolicy holds per-client overrides.
type ClientPolicy struct {
	ClientIP       string          `yaml:"client_ip"`
	ThrottleKbit   int             `yaml:"throttle_kbit,omitempty"`
	AlertThreshold *AlertThreshold `yaml:"alert_threshold,omitempty"`
	Exempt         bool            `yaml:"exempt,omitempty"`
}

// ThrottleSafetyRails defines guardrails for rate-limiting.
type ThrottleSafetyRails struct {
	MinKbitFloor      int           `yaml:"min_kbit_floor"`
	AutoExpireDuration time.Duration `yaml:"auto_expire_duration"`
}

// Config is the top-level configuration for hotspotd.
type Config struct {
	// Network interface to monitor (e.g. "wlan0").
	Interface string `yaml:"interface"`
	// Subnet in CIDR notation (e.g. "192.168.4.0/24").
	Subnet string `yaml:"subnet"`

	// App signature dictionary: domain suffix → app name.
	Signatures []AppSignature `yaml:"signatures"`

	// Alert thresholds (global default).
	AlertThresholds AlertThreshold `yaml:"alert_thresholds"`

	// Per-client policy overrides.
	ClientPolicies []ClientPolicy `yaml:"client_policies"`

	// Throttle safety rails.
	SafetyRails ThrottleSafetyRails `yaml:"safety_rails"`

	// Persistence TTL for DNS cache entries.
	PersistenceTTL time.Duration `yaml:"persistence_ttl"`

	// Path to DHCP lease file (e.g. /var/lib/misc/dnsmasq.leases).
	DHCPLeaseFile string `yaml:"dhcp_lease_file"`

	// Known DoH resolver IPs for detection.
	DoHResolverIPs []string `yaml:"doh_resolver_ips"`

	// Known shared-CDN domain suffixes (classified as "low" confidence).
	// Heuristic: domains matching these suffixes serve content for multiple apps,
	// so we cannot reliably attribute traffic to a single app.
	SharedCDNSuffixes []string `yaml:"shared_cdn_suffixes"`

	// Persistence database path.
	DBPath string `yaml:"db_path"`

	// Aggressive mode: enforce on low-confidence classifications.
	Aggressive bool `yaml:"aggressive"`

	// Firewall backend preference: "nftables" or "iptables".
	// If nft is unavailable at runtime, we fall back to iptables automatically.
	FirewallBackend string `yaml:"firewall_backend"`
}

// CLIFlags holds command-line flag values for merging with file config.
type CLIFlags struct {
	Iface      string
	ConfigPath string
	Reset      bool
	Aggressive bool
	// IfaceSet/AggressiveSet track whether the flag was explicitly provided.
	IfaceSet      bool
	AggressiveSet bool
}

// Defaults returns a Config with sane default values.
// This is used when no config file is found.
func Defaults() *Config {
	return &Config{
		Interface: "wlan0",
		Subnet:    "192.168.4.0/24",
		Signatures: []AppSignature{
			{DomainSuffix: "googlevideo.com", AppName: "YouTube"},
			{DomainSuffix: "fbcdn.net", AppName: "Facebook-Instagram"},
			{DomainSuffix: "tiktokv.com", AppName: "TikTok"},
			{DomainSuffix: "netflix.com", AppName: "Netflix"},
		},
		AlertThresholds: AlertThreshold{
			BytesPerInterval:   50 * 1024 * 1024, // 50 MB
			PacketsPerInterval: 5000,
			Interval:           5 * time.Second,
		},
		SafetyRails: ThrottleSafetyRails{
			MinKbitFloor:      64,
			AutoExpireDuration: 30 * time.Minute,
		},
		PersistenceTTL: 24 * time.Hour,
		DHCPLeaseFile:  "/var/lib/misc/dnsmasq.leases",
		DoHResolverIPs: []string{
			"1.1.1.1", "1.0.0.1", // Cloudflare
			"8.8.8.8", "8.8.4.4", // Google
		},
		// Heuristic: These CDN suffixes are known to serve content for multiple
		// different apps/services. Traffic resolved to these domains cannot be
		// attributed to a single app with high confidence.
		SharedCDNSuffixes: []string{
			"cloudfront.net",
			"akamaihd.net",
			"akamaized.net",
			"fastly.net",
			"cdn.cloudflare.net",
			"edgecastcdn.net",
			"llnwd.net",
		},
		DBPath:          "hotspotd.db",
		FirewallBackend: "nftables",
	}
}

// Load reads config from the given YAML file path, falling back to defaults
// if the file does not exist. CLI flags override file values when explicitly set.
func Load(flags CLIFlags) (*Config, error) {
	cfg := Defaults()

	path := flags.ConfigPath
	if path == "" {
		path = "config.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — use defaults, merge flags.
			mergeFlags(cfg, flags)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	// Re-apply defaults for zero-valued fields that the YAML didn't set.
	applyDefaults(cfg)

	mergeFlags(cfg, flags)
	return cfg, nil
}

// mergeFlags applies CLI flag values, which take precedence over file config.
func mergeFlags(cfg *Config, flags CLIFlags) {
	if flags.IfaceSet && flags.Iface != "" {
		cfg.Interface = flags.Iface
	}
	if flags.AggressiveSet {
		cfg.Aggressive = flags.Aggressive
	}
}

// applyDefaults fills in zero-valued fields with defaults so a partial YAML
// file doesn't leave critical settings empty.
func applyDefaults(cfg *Config) {
	defaults := Defaults()

	if cfg.Interface == "" {
		cfg.Interface = defaults.Interface
	}
	if cfg.Subnet == "" {
		cfg.Subnet = defaults.Subnet
	}
	if len(cfg.Signatures) == 0 {
		cfg.Signatures = defaults.Signatures
	}
	if cfg.AlertThresholds.Interval == 0 {
		cfg.AlertThresholds = defaults.AlertThresholds
	}
	if cfg.SafetyRails.MinKbitFloor == 0 {
		cfg.SafetyRails = defaults.SafetyRails
	}
	if cfg.PersistenceTTL == 0 {
		cfg.PersistenceTTL = defaults.PersistenceTTL
	}
	if cfg.DHCPLeaseFile == "" {
		cfg.DHCPLeaseFile = defaults.DHCPLeaseFile
	}
	if len(cfg.DoHResolverIPs) == 0 {
		cfg.DoHResolverIPs = defaults.DoHResolverIPs
	}
	if len(cfg.SharedCDNSuffixes) == 0 {
		cfg.SharedCDNSuffixes = defaults.SharedCDNSuffixes
	}
	if cfg.DBPath == "" {
		cfg.DBPath = defaults.DBPath
	}
	if cfg.FirewallBackend == "" {
		cfg.FirewallBackend = defaults.FirewallBackend
	}
}

// SignatureMap returns a map of domain suffix → app name for efficient lookups.
func (c *Config) SignatureMap() map[string]string {
	m := make(map[string]string, len(c.Signatures))
	for _, sig := range c.Signatures {
		m[sig.DomainSuffix] = sig.AppName
	}
	return m
}

// SharedCDNSet returns a set of shared-CDN domain suffixes for fast membership checks.
func (c *Config) SharedCDNSet() map[string]bool {
	m := make(map[string]bool, len(c.SharedCDNSuffixes))
	for _, s := range c.SharedCDNSuffixes {
		m[s] = true
	}
	return m
}

// DoHResolverSet returns a set of known DoH resolver IPs for fast membership checks.
func (c *Config) DoHResolverSet() map[string]bool {
	m := make(map[string]bool, len(c.DoHResolverIPs))
	for _, ip := range c.DoHResolverIPs {
		m[ip] = true
	}
	return m
}

// ClientPolicyMap returns per-client policies keyed by IP for fast lookups.
func (c *Config) ClientPolicyMap() map[string]ClientPolicy {
	m := make(map[string]ClientPolicy, len(c.ClientPolicies))
	for _, p := range c.ClientPolicies {
		m[p.ClientIP] = p
	}
	return m
}
