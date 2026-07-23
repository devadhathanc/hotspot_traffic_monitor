# hotspotd — Wi-Fi Hotspot Traffic Monitor & Rate Limiter

A host-side daemon that monitors guest devices connected to your Wi-Fi hotspot, classifies their traffic by application via DNS snooping, tracks bandwidth usage, and rate-limits heavy consumers using Linux traffic control (`tc`) and firewall rules.

## Features

- **Live DNS Activity Table** — grouped by app, refreshes only when new domains appear
- **App Classification** — 29+ app signatures (YouTube, GitHub, Reddit, WhatsApp, etc.)
- **Bandwidth Tracking** — real-time download/upload counters from interface stats
- **Rate Limiting** — throttle heavy consumers via `tc`/`nftables` (Linux)
- **Persistence** — DNS cache survives restarts via BoltDB
- **Graceful Shutdown** — cleans up all firewall rules on exit

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

## Requirements

### System Requirements

- **Linux** (primary target) with:
  - Root/sudo privileges (required for packet capture, firewall rules, and traffic control)
  - `libpcap-dev` installed (`apt install libpcap-dev` on Debian/Ubuntu)
  - `nftables` or `iptables` available
  - `tc` (iproute2) for traffic shaping
  - Go 1.22+ for building
- **macOS**: Builds and runs for development/testing. DNS capture, classification, bandwidth tracking, and the live table all work. Rate-limit enforcement is stubbed out (no-op).
- **Windows** (best-effort):
  - Administrative privileges
  - PowerShell with `New-NetQosPolicy` cmdlet

### Building

```bash
go build -o hotspotd ./cmd/hotspotd/
```

### Running

```bash
# Run with default config (looks for config.yaml in current directory)
sudo ./hotspotd

# Specify interface and config
sudo ./hotspotd --iface wlan0 --config /etc/hotspotd/config.yaml

# Aggressive mode (enforce on low-confidence classifications)
sudo ./hotspotd --aggressive

# Reset mode: remove all applied rules and exit
sudo ./hotspotd --reset
```

### Testing with a Real Hotspot (macOS)

> **Note:** On macOS, DNS capture/classification/alerting work fully. Rate-limit enforcement is stubbed out (requires Linux).

**Step 1 — Create a Wi-Fi Hotspot**

1. Open **System Settings → General → Sharing → Internet Sharing**
2. "Share your connection from": select your internet source (e.g. **Wi-Fi** or **Ethernet**)
3. "To devices using": check **Wi-Fi**
4. Click **Wi-Fi Options** → set a network name and password
5. Toggle Internet Sharing **ON**

**Step 2 — Find your hotspot interface and subnet**

```bash
ifconfig | grep -A3 bridge100
```

You'll see output like:
```
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,...> mtu 1500
    inet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255
```

Here, the interface is `bridge100` and the subnet is `192.168.2.0/24`.

**Step 3 — Connect your phone/tablet** to the hotspot Wi-Fi network.

**Step 4 — Run hotspotd**

```bash
sudo ./hotspotd --iface bridge100
```

**Step 5 — Browse on your phone** — open YouTube, Reddit, GitHub, etc. and watch the live table update.

**Step 6 — Stop** with `Ctrl+C` (gracefully flushes cache and cleans up).

### Testing with a Real Hotspot (Linux — Full Enforcement)

On Linux (e.g. Raspberry Pi running `hostapd` + `dnsmasq`):

```bash
# Install dependencies
sudo apt install libpcap-dev nftables iproute2

# Build
go build -o hotspotd ./cmd/hotspotd/

# Run (wlan0 = your hotspot interface)
sudo ./hotspotd --iface wlan0
```

On Linux you'll see actual firewall/tc commands being applied for rate limiting.

### Troubleshooting

| Problem | Solution |
|---------|----------|
| `failed to open pcap`: no such device | Check interface name: `ifconfig \| grep bridge` |
| `Operation not permitted` | Must run with `sudo` |
| No DNS traffic captured | Phone may be using DNS-over-HTTPS. Check phone DNS settings |
| No classifications appearing | Verify phone is on hotspot (not cellular). Open YouTube to trigger |
| Build fails: `pcap.h not found` | Install Xcode CLI tools: `xcode-select --install` |

## Architecture

```
cmd/hotspotd/main.go          — Supervisor: wires all modules, signal handling
internal/config/               — YAML config loading + CLI flag merge
internal/sniffer/              — DNS packet capture + domain tracking (Module 1)
internal/classify/             — IP→App classification with BoltDB persistence (Module 2)
internal/account/              — Traffic accounting via firewall counters (Module 3)
internal/alert/                — Live table display + threshold monitoring (Module 4)
internal/enforce/              — Rate-limiting via tc + iptables/nftables (Module 5)
internal/identity/             — Device name resolution via DHCP/ARP (Module 6)
internal/usage/                — Interface bandwidth tracking via netstat
```

### Data Flow

```
DNS packets (pcap) → Sniffer → Classifier → Account (firewall counters)
                        ↓            ↓              ↓
                   Domain Tracker  Identity      Alert (live table + thresholds)
                        ↓                            ↓
                   Usage Tracker              Enforce (tc rate-limit)
```

## Configuration

See `config.yaml` for the full configuration with comments. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `interface` | `wlan0` | Hotspot network interface |
| `subnet` | `192.168.4.0/24` | Client subnet in CIDR |
| `alert_thresholds.bytes_per_interval` | 50 MB | Alert threshold per 5s interval |
| `safety_rails.min_kbit_floor` | 64 kbit | Minimum throttle rate (never go below) |
| `safety_rails.auto_expire_duration` | 30 min | Throttles auto-expire after this |
| `persistence_ttl` | 24h | DNS cache entry TTL |

### App Signature Dictionary

The signature dictionary in `config.yaml` maps domain suffixes to application names (29+ apps included). Add your own:

```yaml
signatures:
  - domain_suffix: googlevideo.com
    app_name: YouTube
  - domain_suffix: fbcdn.net
    app_name: Facebook-Instagram
  - domain_suffix: tiktokv.com
    app_name: TikTok
  - domain_suffix: netflix.com
    app_name: Netflix
  - domain_suffix: spotify.com
    app_name: Spotify
```

## Known Limitations

> **These are inherent to DNS-based traffic classification and cannot be fully resolved without DPI (Deep Packet Inspection).**

### 1. DNS-over-HTTPS (DoH) Blind Spot
Clients using DoH bypass our DNS sniffer entirely. We **detect** DoH traffic (TCP:443 to known resolver IPs) and report it in stats, but cannot classify it.

### 2. CDN IP Sharing
Multiple apps may share CDN IPs (CloudFront, Akamai, Fastly). CDN-resolved IPs are classified with **low confidence** and not enforced unless `--aggressive` mode is enabled.

### 3. Stale DNS Cache
DNS resolutions are cached for 24h (configurable). If an app's CDN IP changes, we may continue classifying the old IP. The cache is purged on startup.

### 4. Bandwidth Tracking Granularity
Interface-level bandwidth is tracked via `netstat` counters (total download/upload on the hotspot interface). Per-app bandwidth breakdowns require Linux nftables accounting rules.

## Persistence

DNS classification data is persisted in BoltDB (`hotspotd.db`). On startup, the cache is preloaded. On shutdown (SIGINT/SIGTERM), the cache is flushed to disk.

## Safety Rails

- **Minimum throttle floor**: Never go below 64 kbit/s (configurable)
- **Auto-expire**: Throttles expire after 30 minutes (configurable)
- **Low-confidence protection**: Rate-limiting only on high-confidence classifications by default
- **Graceful shutdown**: All rules removed on exit. Use `--reset` to manually clear.

## License

Internal tool — not licensed for redistribution.
