package com.hotspotd.classify;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class IPClassifier implements Classifier {
    private final Map<String, AppInfo> resolved = new ConcurrentHashMap<>();
    private final DomainTrie<String> signatureTrie = new DomainTrie<>();
    private final DomainTrie<Boolean> cdnTrie = new DomainTrie<>();
    private final Map<String, String> signatureMap;
    private final DnsCacheRepository repository;
    private final Duration ttl;
    private final AtomicLong generation = new AtomicLong(0);

    public IPClassifier(Map<String, String> signatureMap, Set<String> sharedCDNSet,
                        DnsCacheRepository repository, Duration ttl) {
        this.signatureMap = signatureMap;
        this.repository = repository;
        this.ttl = ttl;

        // Build Trie structures for O(L) lookup on packet sniffing path
        if (signatureMap != null) {
            for (Map.Entry<String, String> entry : signatureMap.entrySet()) {
                signatureTrie.insert(entry.getKey(), entry.getValue());
            }
        }

        if (sharedCDNSet != null) {
            for (String cdn : sharedCDNSet) {
                cdnTrie.insert(cdn, Boolean.TRUE);
            }
        }

        // Preload from database persistence.
        if (repository != null) {
            try {
                Map<String, AppInfo> entries = repository.loadAll();
                Instant now = Instant.now();
                int loaded = 0;
                int expired = 0;

                for (Map.Entry<String, AppInfo> entry : entries.entrySet()) {
                    String ip = entry.getKey();
                    AppInfo info = entry.getValue();

                    if (Duration.between(info.getLastSeen(), now).compareTo(ttl) > 0) {
                        try {
                            repository.delete(ip);
                        } catch (Exception ex) {
                            System.err.printf("[WARN] Failed to purge expired cache entry for %s: %s%n", ip, ex.getMessage());
                        }
                        expired++;
                    } else {
                        resolved.put(ip, info);
                        loaded++;
                    }
                }
                System.out.printf("[SYSTEM] DNS cache preloaded: %d entries loaded, %d expired entries purged%n", loaded, expired);
            } catch (Exception e) {
                System.err.printf("[WARN] Failed to preload DNS cache from disk: %s%n", e.getMessage());
            }
        }
    }

    @Override
    public AppInfo lookup(String ip) {
        AppInfo info = resolved.get(ip);
        if (info == null) {
            return null;
        }
        // Read-time TTL check.
        if (Duration.between(info.getLastSeen(), Instant.now()).compareTo(ttl) > 0) {
            resolved.remove(ip);
            return null;
        }
        return info;
    }

    @Override
    public void update(String ip, String domain) {
        if (domain == null) return;
        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        domain = domain.toLowerCase();

        ClassificationResult result = classify(domain);
        if (result == null) {
            return; // No match.
        }

        AppInfo info = new AppInfo(result.app, result.confidence, domain, Instant.now());
        AppInfo existing = resolved.get(ip);
        boolean changed = (existing == null || !existing.getApp().equals(result.app));

        resolved.put(ip, info);

        if (changed) {
            generation.incrementAndGet();
        }

        // Write-through to persistence.
        if (repository != null) {
            try {
                repository.put(ip, info);
            } catch (Exception e) {
                System.err.printf("[WARN] Failed to persist classification for %s: %s%n", ip, e.getMessage());
            }
        }
    }

    private static class ClassificationResult {
        String app;
        Confidence confidence;

        ClassificationResult(String app, Confidence confidence) {
            this.app = app;
            this.confidence = confidence;
        }
    }

    private ClassificationResult classify(String domain) {
        // Fast path: O(L) direct vendor domain suffix match via Trie (high confidence).
        String matchedApp = signatureTrie.searchSuffix(domain);
        if (matchedApp != null) {
            return new ClassificationResult(matchedApp, Confidence.HIGH);
        }

        // Check if domain matches a known shared CDN suffix (low confidence).
        Boolean isCdn = cdnTrie.searchSuffix(domain);
        if (Boolean.TRUE.equals(isCdn)) {
            // If it matches a CDN, see if we can identify the specific app by subdomain keyword.
            for (Map.Entry<String, String> entry : signatureMap.entrySet()) {
                String suffix = entry.getKey().toLowerCase();
                if (domain.contains(suffix)) {
                    return new ClassificationResult(entry.getValue(), Confidence.LOW);
                }
            }
            return null; // Known CDN, but no specific app identified.
        }

        return null;
    }

    @Override
    public Map<String, AppInfo> snapshot() {
        Map<String, AppInfo> snap = new HashMap<>();
        Instant now = Instant.now();
        for (Map.Entry<String, AppInfo> entry : resolved.entrySet()) {
            AppInfo info = entry.getValue();
            if (Duration.between(info.getLastSeen(), now).compareTo(ttl) <= 0) {
                snap.put(entry.getKey(), info);
            }
        }
        return snap;
    }

    @Override
    public long getGeneration() {
        return generation.get();
    }

    @Override
    public void flush() throws Exception {
        if (repository == null) return;
        for (Map.Entry<String, AppInfo> entry : resolved.entrySet()) {
            repository.put(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public void close() throws Exception {
        try {
            flush();
        } catch (Exception e) {
            System.err.printf("[WARN] Failed to flush classify cache on close: %s%n", e.getMessage());
        }
        if (repository != null) {
            repository.close();
        }
    }
}
