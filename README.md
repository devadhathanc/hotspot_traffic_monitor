# hotspotd — Wi-Fi Hotspot Traffic Monitor & Rate Limiter

A host-side daemon written in Java that monitors guest devices connected to your Wi-Fi hotspot, classifies their traffic by application via DNS snooping, tracks bandwidth usage, and rate-limits heavy consumers using Linux traffic control (`tc`) and firewall rules (`nftables`/`iptables`).

## Features

- **Live DNS Activity Table** — grouped by app, refreshes only when new domains appear
- **App Classification** — 29+ app signatures (YouTube, GitHub, Reddit, WhatsApp, etc.)
- **Bandwidth Tracking** — real-time download/upload counters from interface stats
- **Rate Limiting** — throttle heavy consumers via `tc`/`nftables` (Linux) or NetQoS (Windows)
- **Persistence** — DNS cache survives restarts via SQLite embedded database
- **Graceful Shutdown** — JVM shutdown hook cleans up all firewall rules on exit

### Sample Output

```
+----------+---------------------------------+------------------------------------------+----------+
| App      | Domain                          | Resolved IPs                             | LastSeen |
+----------+---------------------------------+------------------------------------------+----------+
| GitHub   | api.github.com                  | 20.207.73.85                             | 21:31:32 |
|          | collector.github.com            | 140.82.113.21                            | 21:31:31 |
|          | github.com                      | 20.207.73.82                             | 21:31:30 |
+----------+---------------------------------+------------------------------------------+----------+
| WhatsApp | scontent.whatsapp.net           | 57.144.49.32                             | 21:31:15 |
|          | www.whatsapp.com                | 57.144.49.32                             | 21:31:14 |
+----------+---------------------------------+------------------------------------------+----------+
| YouTube  | www.youtube.com                 | 142.251.153.4, 142.251.150.4, 142.251... | 21:31:25 |
+----------+---------------------------------+------------------------------------------+----------+
| Others   | awakesecurity.com               | 172.67.74.98, 104.26.14.86, 104.26.15.86| 21:31:38 |
|          | www.google.com                  | 142.251.152.119, 142.251.154.119, 142... | 21:31:23 |
+----------+---------------------------------+------------------------------------------+----------+
| 17 dom   | Down: 336.70 KB                 | Up: 4.14 MB  |  Total: 4.47 MB           | 0m45s    |
|          | Queries: 60                     | Responses: 30                            |          |
+----------+---------------------------------+------------------------------------------+----------+
```

---

## Requirements

### System Requirements

- **Java 22+**
- **Maven 3.8+**
- **macOS / Linux / Windows**
  - Root/sudo privileges (required for pcap raw socket capture and firewall rules)
  - `libpcap` installed (`apt install libpcap-dev` on Debian/Ubuntu, native on macOS)

### Building

```bash
mvn clean package
```

This generates an executable fat JAR in `target/hotspotd-1.0-SNAPSHOT-jar-with-dependencies.jar`.

### Running

```bash
# Run with default config
sudo java -jar target/hotspotd-1.0-SNAPSHOT-jar-with-dependencies.jar

# Specify interface and config
sudo java -jar target/hotspotd-1.0-SNAPSHOT-jar-with-dependencies.jar --iface wlan0 --config config.yaml

# Aggressive mode (enforce on low-confidence classifications)
sudo java -jar target/hotspotd-1.0-SNAPSHOT-jar-with-dependencies.jar --aggressive

# Reset mode: remove all applied rules and exit
sudo java -jar target/hotspotd-1.0-SNAPSHOT-jar-with-dependencies.jar --reset
```

---

## Software Architecture

```
com.hotspotd
├── App.java                            — Supervisor / Entry point (DI wiring)
├── config/
│   ├── Config.java                     — Configuration model (cached derived collections)
│   ├── ConfigLoader.java               — YAML loader & CLI flag merger
│   ├── AppSignature.java               — Domain-to-App mapping model
│   ├── AlertThreshold.java             — Threshold configuration
│   ├── ClientPolicy.java               — Per-client policy overrides
│   └── ThrottleSafetyRails.java        — Safety rail parameters
├── sniffer/
│   ├── Sniffer.java                    — Packet sniffer interface (DIP)
│   ├── DnsSniffer.java                 — Pcap4j capture loop & raw packet parser
│   ├── DnsEvent.java                   — Immutable DNS Query/Response event model
│   ├── DnsListener.java                — Observer interface for DNS events
│   ├── DomainRecord.java               — Thread-safe network domain tracking entity
│   └── SnifferStats.java               — Packet capture counters
├── classify/
│   ├── Classifier.java                 — ISP classification interface
│   ├── IPClassifier.java               — Thread-safe IP→App classifier using DomainTrie
│   ├── DomainTrie.java                 — Reverse-domain Trie for O(L) suffix matching
│   ├── Confidence.java                 — Classification confidence enum (HIGH/LOW)
│   ├── AppInfo.java                    — Immutable classification result model
│   ├── DnsCacheRepository.java         — Repository pattern interface
│   └── SqliteDnsCacheRepository.java   — SQLite JDBC persistence with PreparedStatement caching
├── account/
│   ├── TrafficAccountant.java          — Traffic accounting interface
│   ├── PlatformAccountantFactory.java  — Factory for OS-specific accountants (OCP)
│   ├── LinuxFirewallAccountant.java    — nftables/iptables counter parser
│   ├── StubAccountant.java             — macOS stub accountant
│   ├── BucketKey.java                  — Client+App counter key
│   └── Counter.java                    — Byte & packet metrics container
├── identity/
│   ├── DeviceResolver.java             — Device identity resolution interface
│   ├── DhcpArpResolver.java            — dnsmasq lease & ARP table parser (uses ProcessExecutor)
│   └── DeviceInfo.java                 — Client device details
├── enforce/
│   ├── Enforcer.java                   — Strategy pattern rate-limiter interface
│   ├── LinuxEnforcer.java              — Linux tc HTB/TBF & mark enforcer
│   ├── WindowsEnforcer.java            — Windows PowerShell NetQoS enforcer
│   ├── StubEnforcer.java               — macOS stub enforcer
│   ├── PlatformEnforcerFactory.java    — Factory for OS-specific enforcers (OCP)
│   ├── EnforceRegistry.java            — O(1) active rule tracking & expiry monitor
│   └── RuleEntry.java                  — Immutable applied rule representation
├── usage/
│   ├── BandwidthTracker.java           — Interface for network bandwidth tracking (DIP)
│   ├── MacOSBandwidthTracker.java      — macOS netstat interface parser
│   ├── LinuxBandwidthTracker.java      — Linux /proc/net/dev parser
│   ├── PlatformBandwidthTrackerFactory.java — Factory for OS bandwidth trackers (OCP)
│   ├── InterfaceStats.java             — Byte counter snapshot
│   └── Usage.java                      — Duration & total bandwidth metrics
└── util/
    ├── ProcessExecutor.java            — Process execution & command logger
    ├── DurationParser.java             — Duration string parser utility (SRP)
    └── CidrBlock.java                  — Subnet CIDR matching helper
```

---

## SOLID Principles in Detail

1. **Single Responsibility Principle (SRP)**
   - `ConfigLoader` handles parsing and flag merging.
   - `ProcessExecutor` handles subprocess execution and command logging (`🔒 [FIREWALL] Executing OS Command:`).
   - `DurationParser` isolates string-to-duration parsing logic (`"5s"`, `"30m"`).
   - `SqliteDnsCacheRepository` manages SQL queries and database connection lifecycle.

2. **Open/Closed Principle (OCP)**
   - `PlatformEnforcerFactory`, `PlatformAccountantFactory`, and `PlatformBandwidthTrackerFactory` dynamically instantiate platform-specific strategies based on host OS without mutating client code.
   - `DnsSniffer` exposes a `DnsListener` observer interface so new features (e.g. external telemetry logging) can be attached without altering capture logic.

3. **Liskov Substitution Principle (LSP)**
   - `LinuxEnforcer`, `WindowsEnforcer`, and `StubEnforcer` implement `Enforcer`. `EnforceRegistry` accepts any `Enforcer` instance seamlessly without unexpected side-effects.
   - `MacOSBandwidthTracker` and `LinuxBandwidthTracker` fully satisfy the `BandwidthTracker` contract.

4. **Interface Segregation Principle (ISP)**
   - `Classifier`, `Sniffer`, `BandwidthTracker`, `DnsCacheRepository`, `TrafficAccountant`, and `DeviceResolver` provide focused, single-purpose interfaces.

5. **Dependency Inversion Principle (DIP)**
   - High-level classes depend on abstract interfaces rather than concrete implementations (e.g., `AlertMonitor` depends on `Sniffer` and `BandwidthTracker` interfaces; `IPClassifier` depends on `DnsCacheRepository`; `DhcpArpResolver` depends on `ProcessExecutor`).

---

## Configuration (`config.yaml`)

```yaml
interface: wlan0
subnet: "192.168.2.0/24"
alert_thresholds:
  bytes_per_interval: 52428800 # 50 MB
  packets_per_interval: 5000
  interval: 5s
safety_rails:
  min_kbit_floor: 64
  auto_expire_duration: 30m
persistence_ttl: 24h
db_path: hotspotd.db
firewall_backend: nftables
```
