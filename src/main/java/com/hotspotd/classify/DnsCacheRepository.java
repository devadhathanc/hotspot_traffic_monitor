package com.hotspotd.classify;

import java.util.Map;

public interface DnsCacheRepository extends AutoCloseable {
    /**
     * Persists an IP classification entry.
     */
    void put(String ip, AppInfo info) throws Exception;

    /**
     * Deletes an IP entry from disk.
     */
    void delete(String ip) throws Exception;

    /**
     * Loads all entries from the persistence database.
     */
    Map<String, AppInfo> loadAll() throws Exception;
}
