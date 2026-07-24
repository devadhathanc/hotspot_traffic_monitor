package com.hotspotd;

import com.hotspotd.account.TrafficAccountant;
import com.hotspotd.alert.AlertMonitor;
import com.hotspotd.classify.Classifier;
import com.hotspotd.classify.DnsCacheRepository;
import com.hotspotd.classify.IPClassifier;
import com.hotspotd.classify.SqliteDnsCacheRepository;
import com.hotspotd.config.Config;
import com.hotspotd.config.ConfigLoader;
import com.hotspotd.enforce.EnforceRegistry;
import com.hotspotd.enforce.Enforcer;
import com.hotspotd.enforce.PlatformEnforcerFactory;
import com.hotspotd.identity.DeviceResolver;
import com.hotspotd.identity.DhcpArpResolver;
import com.hotspotd.sniffer.DnsSniffer;
import com.hotspotd.usage.BandwidthTracker;
import com.hotspotd.util.ProcessExecutor;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Entry point for hotspotd — Wi-Fi Hotspot Traffic Monitor & Rate Limiter Daemon.
 * Wires together modules adhering to Dependency Inversion (DIP) and Single Responsibility (SRP).
 */
public class App {
    public static void main(String[] args) {
        ProcessExecutor executor = new ProcessExecutor();

        try {
            // Parse CLI flags.
            ConfigLoader.CLIFlags flags = ConfigLoader.parseFlags(args);

            // Load configuration.
            Config cfg = ConfigLoader.load(flags);

            // Initialize persistence repository & classifier.
            DnsCacheRepository repo = null;
            try {
                repo = new SqliteDnsCacheRepository(cfg.getDbPath());
            } catch (Exception e) {
                System.err.printf("❌ [ERROR] Failed to open persistence DB at %s: %s%n", cfg.getDbPath(), e.getMessage());
            }

            Classifier classifier = new IPClassifier(
                    cfg.getSignatureMap(),
                    cfg.getSharedCDNSet(),
                    repo,
                    cfg.getPersistenceTTL()
            );

            // Platform enforcer & registry.
            Enforcer platformEnforcer = PlatformEnforcerFactory.createEnforcer(cfg.getNetworkInterface(), cfg.getFirewallBackend(), executor);
            EnforceRegistry registry = new EnforceRegistry(
                    platformEnforcer,
                    cfg.getSafetyRails().getMinKbitFloor(),
                    cfg.getSafetyRails().getAutoExpireDuration(),
                    cfg.isAggressive()
            );

            // Reset mode check.
            if (flags.reset) {
                System.out.println("🔄 [SYSTEM] Reset mode — removing all applied rules...");
                registry.reset();
                classifier.close();
                System.out.println("✅ [SYSTEM] Reset complete. Exiting.");
                System.exit(0);
            }

            // Print banner.
            printBanner(cfg);

            // Set up background thread pool for periodic background tasks.
            ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(4, r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            });

            // Identity resolver.
            DeviceResolver resolver = new DhcpArpResolver(cfg.getDhcpLeaseFile());
            resolver.start(scheduler);

            // Sniffer.
            com.hotspotd.sniffer.Sniffer sniffer = new DnsSniffer(
                    cfg.getNetworkInterface(),
                    cfg.getSubnet(),
                    classifier,
                    cfg.getDoHResolverSet()
            );

            // Traffic accountant.
            TrafficAccountant accountant = com.hotspotd.account.PlatformAccountantFactory.createAccountant(classifier, cfg, executor);
            accountant.start(scheduler, cfg.getAlertThresholds().getInterval());

            // Bandwidth tracker.
            BandwidthTracker tracker = com.hotspotd.usage.PlatformBandwidthTrackerFactory.createTracker(cfg.getNetworkInterface(), executor);

            // Alert monitor.
            AlertMonitor monitor = new AlertMonitor(accountant, classifier, resolver, sniffer, cfg, tracker);
            monitor.start(scheduler);

            // Enforce expiry loop.
            registry.startExpiryLoop(scheduler, cfg.getAlertThresholds().getInterval());

            // Setup Qdisc.
            try {
                platformEnforcer.setupQdisc();
            } catch (Exception e) {
                System.err.printf("⚠️  [WARNING] Failed to set up root qdisc (may need root): %s%n", e.getMessage());
            }

            // Start Sniffer.
            try {
                sniffer.start();
            } catch (Exception e) {
                System.err.printf("❌ [ERROR] Sniffer failed to start: %s%n", e.getMessage());
            }

            // Shutdown Hook for Graceful Cleanup (SIGINT / SIGTERM).
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                System.out.println("\n🛑 [SYSTEM] Initiating graceful shutdown...");
                try {
                    sniffer.stop();
                    scheduler.shutdownNow();
                    scheduler.awaitTermination(3, TimeUnit.SECONDS);

                    System.out.println("[SYSTEM] Shutting down — resetting enforcement rules...");
                    registry.reset();

                    System.out.println("[SYSTEM] Flushing DNS classification cache to disk...");
                    classifier.close();
                    accountant.close();

                    System.out.println("✅ [SYSTEM] Hotspot Background Daemon stopped cleanly.");
                } catch (Exception e) {
                    System.err.printf("⚠️  [WARNING] Shutdown error: %s%n", e.getMessage());
                }
            }));

            // Keep main thread alive.
            Thread.currentThread().join();

        } catch (Exception e) {
            System.err.printf("❌ [FATAL] Daemon failure: %s%n", e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printBanner(Config cfg) {
        System.out.println();
        System.out.println("🚀 [SYSTEM] Hotspot Background Daemon Started (Java Version).");
        System.out.printf("📡 [SYSTEM] Interface: %s (Subnet: %s)%n", cfg.getNetworkInterface(), cfg.getSubnet());
        System.out.printf("📚 [SYSTEM] Signature dictionary loaded: %d app signatures%n", cfg.getSignatures().size());
        System.out.printf("🔧 [SYSTEM] Firewall backend: %s%n", cfg.getFirewallBackend());
        System.out.printf("⏱️  [SYSTEM] Polling interval: %s%n", cfg.getAlertThresholds().getIntervalString());
        System.out.printf("🛡️  [SYSTEM] Safety rails: min floor %d kbit, auto-expire %s%n",
                cfg.getSafetyRails().getMinKbitFloor(), cfg.getSafetyRails().getAutoExpireDurationString());
        if (cfg.isAggressive()) {
            System.out.println("⚡ [SYSTEM] Aggressive mode ENABLED — enforcing on low-confidence classifications");
        }
        System.out.println();
    }
}
