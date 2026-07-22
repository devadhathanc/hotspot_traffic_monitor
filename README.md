# hotspotd — Wi-Fi Hotspot Traffic Monitor & Rate Limiter

A host-side daemon that monitors guest devices connected to your Wi-Fi hotspot, classifies their traffic by application via DNS snooping, and rate-limits heavy consumers using Linux traffic control (`tc`) and firewall rules.

## Requirements

### System Requirements

- **Linux** (primary target) with:
  - Root/sudo privileges (required for packet capture, firewall rules, and traffic control)
  - `libpcap-dev` installed (`apt install libpcap-dev` on Debian/Ubuntu)
  - `nftables` or `iptables` available
  - `tc` (iproute2) for traffic shaping
  - Go 1.22+ for building
- **Windows** (best-effort):
  - Administrative privileges
  - PowerShell with `New-NetQosPolicy` cmdlet
  - **Note:** QoS enforcement may require Windows Server + Group Policy to actually take effect
- **macOS**: Builds and runs for development/testing, but enforcement is stubbed out (no-op)

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
# A new bridge interface appears when sharing is active
ifconfig | grep -A3 bridge100
```

You'll see output like:
```
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,...> mtu 1500
    inet 192.168.2.1 netmask 0xffffff00 broadcast 192.168.2.255
```

Here, the interface is `bridge100` and the subnet is `192.168.2.0/24`.

**Step 3 — Connect your phone/tablet** to the hotspot Wi-Fi network.

**Step 4 — Update `config.yaml`** (optional — you can use `--iface` flag instead)

```yaml
interface: bridge100
subnet: "192.168.2.0/24"
```

**Step 5 — Run hotspotd**

```bash
sudo ./hotspotd --iface bridge100
```

Expected startup output:
```
🚀 [SYSTEM] Hotspot Background Daemon Started.
📡 [SYSTEM] Interface: bridge100 (Subnet: 192.168.2.0/24)
📚 [SYSTEM] Signature dictionary loaded: 4 app signatures
```

**Step 6 — Generate traffic on your phone**

| Action on phone          | Expected classification       |
|--------------------------|-------------------------------|
| Play a **YouTube** video | `YouTube` (high confidence)   |
| Scroll **Instagram**     | `Facebook-Instagram` (high)   |
| Open **TikTok**          | `TikTok` (high confidence)    |
| Browse **Netflix**       | `Netflix` (high confidence)   |

Watch the terminal for `[STATS]`, `[METRIC UPDATE]`, and `⚠️ [WARNING]` lines.

**Step 7 — Stop** with `Ctrl+C` (gracefully flushes cache and cleans up).

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

On Linux you'll see actual firewall/tc commands logged:
```
🔒 [FIREWALL] Executing OS Command: nft add table ip hotspotd
🔒 [FIREWALL] Executing OS Command: tc qdisc add dev wlan0 root handle 1: htb default 99
```

### Verifying Specific Features

```bash
# Test --reset with no prior rules (should exit cleanly)
sudo ./hotspotd --reset

# Test persistence (restart and see cached entries preloaded)
sudo ./hotspotd --iface bridge100    # run, let DNS flow, Ctrl+C
sudo ./hotspotd --iface bridge100    # restart — see "DNS cache preloaded: X entries"

# Test aggressive mode (enforce on CDN/low-confidence matches)
sudo ./hotspotd --iface bridge100 --aggressive
```

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
internal/sniffer/              — DNS packet capture via gopacket/pcap (Module 1)
internal/classify/             — IP→App classification with BoltDB persistence (Module 2)
internal/account/              — Traffic accounting via firewall counters (Module 3)
internal/alert/                — Threshold monitoring and stats emission (Module 4)
internal/enforce/              — Rate-limiting via tc + iptables/nftables (Module 5)
internal/identity/             — Device name resolution via DHCP/ARP (Module 6)
```

### Data Flow

```
DNS packets (pcap) → Sniffer → Classifier → Account (firewall counters)
                                    ↓              ↓
                               Identity        Alert (thresholds)
                                    ↓              ↓
                                              Enforce (tc rate-limit)
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

The signature dictionary in `config.yaml` maps domain suffixes to application names. Add your own entries:

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
  # Add more:
  - domain_suffix: spotify.com
    app_name: Spotify
```

## Known Limitations

> **These are inherent to DNS-based traffic classification and cannot be fully resolved without DPI (Deep Packet Inspection).**

### 1. DNS-over-HTTPS (DoH) Blind Spot
Clients using DoH (e.g., Firefox with Cloudflare DoH, Chrome with Google DoH) bypass our DNS sniffer entirely. We **detect** DoH traffic (TCP:443 to known resolver IPs like 1.1.1.1, 8.8.8.8) and report it as "unobservable" in stats, but we cannot classify the traffic.

### 2. CDN IP Sharing
Multiple apps may share the same CDN IP addresses (e.g., CloudFront, Akamai, Fastly). When a CDN IP is resolved for one app but also serves traffic for another, we may misattribute traffic. CDN-resolved IPs are classified with **low confidence** and are not enforced unless `--aggressive` mode is enabled.

### 3. Stale DNS Cache
DNS resolutions are cached for 24h (configurable). If an app's CDN IP changes, we may continue classifying traffic to the old IP as belonging to that app. The cache is preloaded on startup and expired entries are purged.

### 4. Foreground/Background Tagging
Without DPI or per-app socket tracking, we cannot distinguish foreground vs. background app traffic. All classified traffic is tagged as "foreground" in metric reports.

### 5. IPv6 Partial Support
IPv6 DNS responses (AAAA records) are captured and classified, but firewall rules for accounting and enforcement are IPv4-only (`ip` table in nftables, `iptables` not `ip6tables`).

## Persistence

DNS classification data is persisted in a BoltDB database (`hotspotd.db` by default). On startup, the cache is preloaded from disk with expired entries purged. On graceful shutdown (SIGINT/SIGTERM), the cache is flushed to disk.

## Safety Rails

- **Minimum throttle floor**: Rate-limits never go below 64 kbit/s (configurable). This prevents accidentally cutting off a device entirely.
- **Auto-expire**: All throttle rules automatically expire after 30 minutes (configurable). On expiry, traffic is re-evaluated — re-throttled only if still over threshold.
- **Low-confidence protection**: By default, rate-limiting is only applied to high-confidence classifications. Use `--aggressive` to override.
- **Graceful shutdown**: On SIGINT/SIGTERM, all applied rules are removed before exit. Use `--reset` to manually clear all rules.

## License

Internal tool — not licensed for redistribution.
