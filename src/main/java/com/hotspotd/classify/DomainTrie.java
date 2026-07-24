package com.hotspotd.classify;

import java.util.HashMap;
import java.util.Map;

/**
 * A reverse-domain Trie data structure for high-performance suffix matching.
 * Provides O(L) domain lookup complexity (where L is domain label depth, typically 2-4)
 * replacing O(N) signature scanning.
 */
public class DomainTrie<T> {

    private static class TrieNode<T> {
        private final Map<String, TrieNode<T>> children = new HashMap<>();
        private T value;
    }

    private final TrieNode<T> root = new TrieNode<>();

    /**
     * Inserts a domain suffix (e.g., "netflix.com") into the reverse Trie with a value.
     */
    public void insert(String domainSuffix, T value) {
        if (domainSuffix == null || domainSuffix.trim().isEmpty()) {
            return;
        }
        String[] labels = domainSuffix.toLowerCase().split("\\.");
        TrieNode<T> current = root;

        // Traverse in reverse order (tld first)
        for (int i = labels.length - 1; i >= 0; i--) {
            String label = labels[i];
            current = current.children.computeIfAbsent(label, k -> new TrieNode<>());
        }
        current.value = value;
    }

    /**
     * Searches for the longest matching domain suffix for the given full domain.
     * E.g. for "video.netflix.com", matches suffix "netflix.com".
     *
     * @return The matched value, or null if no matching suffix is registered.
     */
    public T searchSuffix(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return null;
        }
        String[] labels = domain.toLowerCase().split("\\.");
        TrieNode<T> current = root;
        T lastMatch = null;

        for (int i = labels.length - 1; i >= 0; i--) {
            String label = labels[i];
            current = current.children.get(label);
            if (current == null) {
                break;
            }
            if (current.value != null) {
                lastMatch = current.value;
            }
        }
        return lastMatch;
    }
}
