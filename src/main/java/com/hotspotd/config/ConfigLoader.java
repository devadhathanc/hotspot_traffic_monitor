package com.hotspotd.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.FileNotFoundException;

public class ConfigLoader {
    public static class CLIFlags {
        public String iface = "";
        public String configPath = "config.yaml";
        public boolean reset = false;
        public boolean aggressive = false;
        public boolean ifaceSet = false;
        public boolean aggressiveSet = false;
    }

    /**
     * Parses CLI arguments and builds CLIFlags structure.
     */
    public static CLIFlags parseFlags(String[] args) {
        CLIFlags flags = new CLIFlags();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--iface".equals(arg) && i + 1 < args.length) {
                flags.iface = args[++i];
                flags.ifaceSet = true;
            } else if ("--config".equals(arg) && i + 1 < args.length) {
                flags.configPath = args[++i];
            } else if ("--reset".equals(arg)) {
                flags.reset = true;
            } else if ("--aggressive".equals(arg)) {
                flags.aggressive = true;
                flags.aggressiveSet = true;
            }
        }
        return flags;
    }

    /**
     * Loads the configuration from the specified path, merges it with CLI flags,
     * and applies default fallbacks for zero/null fields.
     */
    public static Config load(CLIFlags flags) throws Exception {
        Config config = null;
        File file = new File(flags.configPath);
        if (file.exists()) {
            try {
                ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
                config = mapper.readValue(file, Config.class);
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse config file " + flags.configPath + ": " + e.getMessage(), e);
            }
        } else {
            // Sane defaults.
            config = createDefaults();
        }

        // Apply defaults to fields that were absent/null in YAML.
        applyDefaultsIfNull(config);

        // Merge CLI flags.
        if (flags.ifaceSet && !flags.iface.isEmpty()) {
            config.setNetworkInterface(flags.iface);
        }
        if (flags.aggressiveSet) {
            config.setAggressive(flags.aggressive);
        }

        return config;
    }

    private static Config createDefaults() {
        return new Config(); // Initialized with defaults in fields
    }

    private static void applyDefaultsIfNull(Config config) {
        Config defaults = createDefaults();
        if (config.getNetworkInterface() == null) {
            config.setNetworkInterface(defaults.getNetworkInterface());
        }
        if (config.getSubnet() == null) {
            config.setSubnet(defaults.getSubnet());
        }
        if (config.getSignatures() == null || config.getSignatures().isEmpty()) {
            config.setSignatures(defaults.getSignatures());
        }
        if (config.getAlertThresholds() == null) {
            config.setAlertThresholds(defaults.getAlertThresholds());
        }
        if (config.getSafetyRails() == null) {
            config.setSafetyRails(defaults.getSafetyRails());
        }
        if (config.getPersistenceTTLString() == null) {
            config.setPersistenceTTLString(defaults.getPersistenceTTLString());
        }
        if (config.getDhcpLeaseFile() == null) {
            config.setDhcpLeaseFile(defaults.getDhcpLeaseFile());
        }
        if (config.getDohResolverIPs() == null || config.getDohResolverIPs().isEmpty()) {
            config.setDohResolverIPs(defaults.getDohResolverIPs());
        }
        if (config.getSharedCDNSuffixes() == null || config.getSharedCDNSuffixes().isEmpty()) {
            config.setSharedCDNSuffixes(defaults.getSharedCDNSuffixes());
        }
        if (config.getDbPath() == null) {
            config.setDbPath(defaults.getDbPath());
        }
        if (config.getFirewallBackend() == null) {
            config.setFirewallBackend(defaults.getFirewallBackend());
        }
    }
}
