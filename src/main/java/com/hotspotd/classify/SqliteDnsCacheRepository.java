package com.hotspotd.classify;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * SQLite-backed implementation of {@link DnsCacheRepository}.
 * Uses reusable prepared statements for optimal write performance.
 */
public class SqliteDnsCacheRepository implements DnsCacheRepository {
    private final Connection connection;
    private final PreparedStatement putStatement;
    private final PreparedStatement deleteStatement;

    public SqliteDnsCacheRepository(String dbPath) throws Exception {
        // Load the SQLite JDBC driver class.
        Class.forName("org.sqlite.JDBC");

        String url = "jdbc:sqlite:" + dbPath;
        this.connection = DriverManager.getConnection(url);

        // Auto-create schema.
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS dns_cache (" +
                    "ip TEXT PRIMARY KEY, " +
                    "app TEXT NOT NULL, " +
                    "confidence TEXT NOT NULL, " +
                    "domain TEXT NOT NULL, " +
                    "last_seen INTEGER NOT NULL" +
                    ")");
        }

        // Cache prepared statements for high performance write/delete
        this.putStatement = connection.prepareStatement(
                "INSERT OR REPLACE INTO dns_cache (ip, app, confidence, domain, last_seen) VALUES (?, ?, ?, ?, ?)"
        );
        this.deleteStatement = connection.prepareStatement(
                "DELETE FROM dns_cache WHERE ip = ?"
        );
    }

    @Override
    public synchronized void put(String ip, AppInfo info) throws Exception {
        putStatement.setString(1, ip);
        putStatement.setString(2, info.getApp());
        putStatement.setString(3, info.getConfidence().getValue());
        putStatement.setString(4, info.getDomain());
        putStatement.setLong(5, info.getLastSeen().getEpochSecond());
        putStatement.executeUpdate();
    }

    @Override
    public synchronized void delete(String ip) throws Exception {
        deleteStatement.setString(1, ip);
        deleteStatement.executeUpdate();
    }

    @Override
    public synchronized Map<String, AppInfo> loadAll() throws Exception {
        Map<String, AppInfo> result = new HashMap<>();
        String sql = "SELECT ip, app, confidence, domain, last_seen FROM dns_cache";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                String ip = rs.getString("ip");
                String app = rs.getString("app");
                String confidenceVal = rs.getString("confidence");
                String domain = rs.getString("domain");
                long lastSeenSec = rs.getLong("last_seen");

                AppInfo info = new AppInfo(
                        app,
                        Confidence.fromValue(confidenceVal),
                        domain,
                        Instant.ofEpochSecond(lastSeenSec)
                );
                result.put(ip, info);
            }
        }
        return result;
    }

    @Override
    public synchronized void close() throws Exception {
        try {
            if (putStatement != null && !putStatement.isClosed()) {
                putStatement.close();
            }
            if (deleteStatement != null && !deleteStatement.isClosed()) {
                deleteStatement.close();
            }
        } finally {
            if (connection != null && !connection.isClosed()) {
                connection.close();
            }
        }
    }
}
