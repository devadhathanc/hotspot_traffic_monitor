package com.hotspotd.account;

import com.hotspotd.classify.Classifier;
import com.hotspotd.config.Config;
import com.hotspotd.util.ProcessExecutor;

/**
 * Factory class that creates the appropriate {@link TrafficAccountant} strategy based on host OS.
 * Follows the Factory Pattern and Open/Closed Principle (OCP).
 */
public class PlatformAccountantFactory {

    /**
     * Creates and returns the appropriate TrafficAccountant implementation.
     *
     * @param classifier The IP classifier.
     * @param cfg The system configuration.
     * @param executor The process executor for OS command execution.
     * @return A TrafficAccountant instance tailored to the host platform.
     */
    public static TrafficAccountant createAccountant(Classifier classifier, Config cfg, ProcessExecutor executor) {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("linux")) {
            return new LinuxFirewallAccountant(
                    classifier,
                    cfg.getNetworkInterface(),
                    cfg.getSubnet(),
                    cfg.getFirewallBackend(),
                    executor
            );
        } else {
            return new StubAccountant();
        }
    }
}
