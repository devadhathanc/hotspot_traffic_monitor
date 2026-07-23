// Package main is the entry point for hotspotd — a host-side Wi-Fi hotspot
// traffic monitor and rate-limiter daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"hotspotd/internal/account"
	"hotspotd/internal/alert"
	"hotspotd/internal/classify"
	"hotspotd/internal/config"
	"hotspotd/internal/enforce"
	"hotspotd/internal/identity"
	"hotspotd/internal/sniffer"
	"hotspotd/internal/usage"
)

func main() {
	// Parse CLI flags.
	flags := parseFlags()

	// Load configuration.
	cfg, err := config.Load(flags)
	if err != nil {
		log.Fatalf("❌ [ERROR] Failed to load config: %v", err)
	}

	// -- Initialize modules --

	// Classify (Module 2): DNS classification with persistence.
	persister, err := classify.NewPersister(cfg.DBPath)
	if err != nil {
		log.Fatalf("❌ [ERROR] Failed to open persistence DB at %s: %v", cfg.DBPath, err)
	}
	classifier := classify.NewClassifier(
		cfg.SignatureMap(),
		cfg.SharedCDNSet(),
		persister,
		cfg.PersistenceTTL,
	)

	// Enforce (Module 5): Rate-limit enforcement.
	platformEnforcer := enforce.NewPlatformEnforcer(cfg.Interface, cfg.FirewallBackend)
	registry := enforce.NewRegistry(
		platformEnforcer,
		cfg.SafetyRails.MinKbitFloor,
		cfg.SafetyRails.AutoExpireDuration,
		cfg.Aggressive,
	)

	// Handle --reset mode: load registry, tear down all rules, exit.
	if flags.Reset {
		log.Printf("🔄 [SYSTEM] Reset mode — removing all applied rules...")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := registry.Reset(ctx); err != nil {
			log.Printf("⚠️  [WARNING] Reset completed with errors: %v", err)
		}
		if err := classifier.Close(); err != nil {
			log.Printf("⚠️  [WARNING] Failed to close classifier: %v", err)
		}
		log.Printf("✅ [SYSTEM] Reset complete. Exiting.")
		os.Exit(0)
	}

	// -- Print startup banner --
	printBanner(cfg)

	// -- Set up root context with signal handling --
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handler: SIGINT/SIGTERM → cancel context → graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		log.Printf("\n🛑 [SYSTEM] Received signal %v — initiating graceful shutdown...", sig)
		cancel()
	}()

	// -- Set up qdisc for enforcement --
	if err := platformEnforcer.SetupQdisc(); err != nil {
		log.Printf("⚠️  [WARNING] Failed to set up root qdisc (may need root): %v", err)
		// Continue — enforcement may not work but monitoring will.
	}

	// -- Identity (Module 6): Device name resolution --
	resolver := identity.NewResolver(cfg.DHCPLeaseFile)

	// -- Sniffer (Module 1): DNS packet capture --
	sniff := sniffer.New(cfg.Interface, cfg.Subnet, classifier, cfg.DoHResolverSet())

	// -- Account (Module 3): Traffic accounting --
	accountant := account.NewAccountant(
		classifier, cfg.Interface, cfg.Subnet,
		cfg.AlertThresholds.Interval, cfg.FirewallBackend,
	)

	// -- Usage tracker --
	tracker := usage.NewTracker(cfg.Interface)

	// -- Alert (Module 4): Threshold monitoring --
	monitor := alert.NewMonitor(accountant, classifier, resolver, sniff, cfg, tracker)

	// -- Launch all modules in goroutines --
	var wg sync.WaitGroup

	// Identity resolver (periodic refresh).
	wg.Add(1)
	go func() {
		defer wg.Done()
		resolver.Start(ctx)
	}()

	// Sniffer (DNS capture loop).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sniff.Start(ctx); err != nil {
			log.Printf("❌ [ERROR] Sniffer failed: %v", err)
			cancel() // Sniffer failure is fatal — trigger shutdown.
		}
	}()

	// Accountant (counter polling loop).
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := accountant.Start(ctx); err != nil {
			log.Printf("❌ [ERROR] Accountant failed: %v", err)
		}
	}()

	// Alert monitor (threshold checking loop).
	wg.Add(1)
	go func() {
		defer wg.Done()
		monitor.Start(ctx)
	}()

	// Enforce expiry loop (periodic rule expiry check).
	wg.Add(1)
	go func() {
		defer wg.Done()
		registry.StartExpiryLoop(ctx, cfg.AlertThresholds.Interval)
	}()

	// -- Wait for shutdown --
	wg.Wait()

	// -- Graceful shutdown sequence --
	log.Printf("[SYSTEM] Shutting down — resetting enforcement rules...")
	shutdownCtx := context.Background()

	if err := registry.Reset(shutdownCtx); err != nil {
		log.Printf("⚠️  [WARNING] Reset on shutdown had errors: %v", err)
	}

	log.Printf("[SYSTEM] Flushing DNS classification cache to disk...")
	if err := classifier.Close(); err != nil {
		log.Printf("⚠️  [WARNING] Failed to close classifier: %v", err)
	}

	log.Printf("✅ [SYSTEM] Hotspot Background Daemon stopped cleanly.")
}

// parseFlags parses CLI flags and returns a CLIFlags struct.
func parseFlags() config.CLIFlags {
	var flags config.CLIFlags

	flag.StringVar(&flags.Iface, "iface", "", "Network interface to monitor (overrides config)")
	flag.StringVar(&flags.ConfigPath, "config", "config.yaml", "Path to config file")
	flag.BoolVar(&flags.Reset, "reset", false, "Reset mode: remove all applied rules and exit")
	flag.BoolVar(&flags.Aggressive, "aggressive", false, "Enforce on low-confidence classifications")

	flag.Parse()

	// Track which flags were explicitly set.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "iface":
			flags.IfaceSet = true
		case "aggressive":
			flags.AggressiveSet = true
		}
	})

	return flags
}

// printBanner prints the startup banner matching the spec format.
func printBanner(cfg *config.Config) {
	fmt.Println()
	log.Printf("🚀 [SYSTEM] Hotspot Background Daemon Started.")
	log.Printf("📡 [SYSTEM] Interface: %s (Subnet: %s)", cfg.Interface, cfg.Subnet)
	log.Printf("📚 [SYSTEM] Signature dictionary loaded: %d app signatures", len(cfg.Signatures))
	log.Printf("🔧 [SYSTEM] Firewall backend: %s", cfg.FirewallBackend)
	log.Printf("⏱️  [SYSTEM] Polling interval: %s", cfg.AlertThresholds.Interval)
	log.Printf("🛡️  [SYSTEM] Safety rails: min floor %d kbit, auto-expire %s",
		cfg.SafetyRails.MinKbitFloor, cfg.SafetyRails.AutoExpireDuration)
	if cfg.Aggressive {
		log.Printf("⚡ [SYSTEM] Aggressive mode ENABLED — enforcing on low-confidence classifications")
	}
	fmt.Println()
}
