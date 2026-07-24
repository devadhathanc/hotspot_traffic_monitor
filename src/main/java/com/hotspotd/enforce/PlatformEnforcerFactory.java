package com.hotspotd.enforce;

import com.hotspotd.util.ProcessExecutor;

public class PlatformEnforcerFactory {
    /**
     * Creates and returns the appropriate Enforcer implementation based on the host OS.
     *
     * @param iface The interface to monitor/throttle.
     * @param backend The firewall backend preference ("nftables" or "iptables") for Linux.
     * @param executor The ProcessExecutor instance.
     * @return An Enforcer implementation.
     */
    public static Enforcer createEnforcer(String iface, String backend, ProcessExecutor executor) {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("linux")) {
            return new LinuxEnforcer(iface, backend, executor);
        } else if (os.contains("win")) {
            return new WindowsEnforcer(executor);
        } else {
            return new StubEnforcer(iface);
        }
    }
}
