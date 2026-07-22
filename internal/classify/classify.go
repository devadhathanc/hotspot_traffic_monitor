// Package classify maintains a thread-safe mapping of resolved IPs to application
// classifications, using DNS domain suffix matching against a configurable signature dictionary.
package classify

import (
	"log"
	"strings"
	"sync"
	"time"
)

// Confidence represents how reliably an IP was classified.
type Confidence string

const (
	// ConfidenceHigh means the domain matched a known vendor-specific suffix directly.
	ConfidenceHigh Confidence = "high"
	// ConfidenceLow means the domain matched via a shared-CDN pattern, so the
	// resolved IP may serve content for multiple apps.
	ConfidenceLow Confidence = "low"
)

// AppInfo holds the classification result for a resolved IP.
type AppInfo struct {
	App        string     `json:"app"`
	Confidence Confidence `json:"confidence"`
	Domain     string     `json:"domain"`
	LastSeen   time.Time  `json:"last_seen"`
}

// Classifier is a thread-safe IP→app classifier backed by DNS suffix matching.
type Classifier struct {
	mu sync.RWMutex
	// resolved maps IP address strings to their classification.
	resolved map[string]AppInfo

	// signatureMap maps domain suffix → app name (from config).
	signatureMap map[string]string
	// sharedCDNSet is a set of known shared-CDN domain suffixes.
	sharedCDNSet map[string]bool

	// persist is the optional BoltDB persistence layer.
	persist *Persister

	// ttl for cache entries.
	ttl time.Duration
}

// NewClassifier creates a classifier with the given signature dictionary and CDN set.
// If persister is non-nil, the in-memory map is preloaded from disk on creation.
func NewClassifier(signatureMap map[string]string, sharedCDNSet map[string]bool, persister *Persister, ttl time.Duration) *Classifier {
	c := &Classifier{
		resolved:     make(map[string]AppInfo),
		signatureMap: signatureMap,
		sharedCDNSet: sharedCDNSet,
		persist:      persister,
		ttl:          ttl,
	}

	// Preload from persistence if available.
	if persister != nil {
		entries, err := persister.LoadAll()
		if err != nil {
			log.Printf("[WARN] Failed to preload DNS cache from disk: %v", err)
		} else {
			now := time.Now()
			loaded := 0
			expired := 0
			for ip, info := range entries {
				if now.Sub(info.LastSeen) > ttl {
					// Purge expired entry from disk.
					if delErr := persister.Delete(ip); delErr != nil {
						log.Printf("[WARN] Failed to purge expired cache entry for %s: %v", ip, delErr)
					}
					expired++
					continue
				}
				c.resolved[ip] = info
				loaded++
			}
			log.Printf("[SYSTEM] DNS cache preloaded: %d entries loaded, %d expired entries purged", loaded, expired)
		}
	}

	return c
}

// Lookup returns the classification for an IP address.
func (c *Classifier) Lookup(ip string) (app string, confidence Confidence, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	info, exists := c.resolved[ip]
	if !exists {
		return "", "", false
	}
	// Check TTL expiry at read time.
	if time.Since(info.LastSeen) > c.ttl {
		return "", "", false
	}
	return info.App, info.Confidence, true
}

// Update classifies the given IP based on the domain it resolved to.
// Performs suffix matching against the signature dictionary and writes through
// to the persistence layer.
func (c *Classifier) Update(ip string, domain string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	app, confidence := c.classify(domain)
	if app == "" {
		return // No match — don't pollute the map.
	}

	info := AppInfo{
		App:        app,
		Confidence: confidence,
		Domain:     domain,
		LastSeen:   time.Now(),
	}

	c.mu.Lock()
	c.resolved[ip] = info
	c.mu.Unlock()

	// Write-through to persistence.
	if c.persist != nil {
		if err := c.persist.Put(ip, info); err != nil {
			log.Printf("[WARN] Failed to persist classification for %s: %v", ip, err)
		}
	}
}

// classify performs domain suffix matching against the signature dictionary.
// Returns (appName, confidence). Returns ("", "") if no match.
func (c *Classifier) classify(domain string) (string, Confidence) {
	// First, try direct vendor domain suffix match (high confidence).
	for suffix, appName := range c.signatureMap {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			// Check if this specific domain also matches a shared CDN.
			// Vendor-specific domains take priority over CDN classification.
			return appName, ConfidenceHigh
		}
	}

	// Check if the domain matches a known shared-CDN suffix.
	// If so, we still try to match against signatures, but with low confidence.
	for cdnSuffix := range c.sharedCDNSet {
		if domain == cdnSuffix || strings.HasSuffix(domain, "."+cdnSuffix) {
			// CDN domain — check if we can still match an app by subdomain pattern.
			// For example, "youtube.cdn.cloudflare.net" might still match "youtube".
			// This is best-effort and will typically not match.
			for suffix, appName := range c.signatureMap {
				if strings.Contains(domain, suffix) {
					return appName, ConfidenceLow
				}
			}
			// Known CDN but no app match — still no classification.
			return "", ""
		}
	}

	return "", ""
}

// Snapshot returns a point-in-time copy of all classifications.
// Used by account and enforce modules to enumerate known app IPs.
func (c *Classifier) Snapshot() map[string]AppInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := make(map[string]AppInfo, len(c.resolved))
	now := time.Now()
	for ip, info := range c.resolved {
		// Only include non-expired entries.
		if now.Sub(info.LastSeen) <= c.ttl {
			snap[ip] = info
		}
	}
	return snap
}

// Flush persists the entire in-memory map to disk. Called on graceful shutdown.
func (c *Classifier) Flush() error {
	if c.persist == nil {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for ip, info := range c.resolved {
		if err := c.persist.Put(ip, info); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes the persistence layer.
func (c *Classifier) Close() error {
	if err := c.Flush(); err != nil {
		log.Printf("[WARN] Failed to flush classify cache on close: %v", err)
	}
	if c.persist != nil {
		return c.persist.Close()
	}
	return nil
}
