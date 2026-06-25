<p align="center">
  <h1 align="center">ftagent-lite</h1>
  <p align="center">Real-time DDoS traffic monitor. Single file. No account. No cloud.</p>
</p>

<p align="center">
  <a href="https://pypi.org/project/ftagent-lite/"><img src="https://img.shields.io/pypi/v/ftagent-lite?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/ftagent-lite/"><img src="https://img.shields.io/pypi/pyversions/ftagent-lite" alt="Python versions"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Flowtriq/ftagent-lite" alt="License"></a>
  <a href="https://pypi.org/project/ftagent-lite/"><img src="https://img.shields.io/pypi/dm/ftagent-lite?color=green" alt="Downloads"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Flowtriq/ftagent-lite/main/.github/demo.gif" alt="ftagent-lite demo" width="700">
</p>

---

Drop it on any Linux server and see packets per second, bandwidth, protocol breakdown, source IP cardinality, and attack severity in real time. Pipe JSON to your own tooling or watch the live dashboard in your terminal.

> For a full TUI dashboard with real-time charts and sparklines, see [NetHawk](https://github.com/Flowtriq/nethawk).

---

## Quick Start

### Install from PyPI

```bash
pip install ftagent-lite[full]
sudo ftagent-lite
```

The `[full]` extra pulls in `scapy` (packet capture and protocol parsing) and `psutil` (fallback counters).

### Or run the single file directly

```bash
curl -O https://raw.githubusercontent.com/Flowtriq/ftagent-lite/main/ftagent_lite.py
pip install scapy psutil
sudo python3 ftagent_lite.py
```

Root / sudo is required for raw socket capture.

---

## What It Does

**Two things, well:**

1. **Traffic monitoring** -- PPS, bandwidth (Gbps/Mbps), TCP/UDP/ICMP breakdown, unique source IPs, top destination ports, and average packet size. Every interval, printed to stdout.

2. **Attack pattern detection** -- Classifies traffic severity against your threshold. When PPS exceeds the threshold it flags the interval, shows top source IPs, and identifies the attack pattern.

| PPS vs threshold | Severity   |
| ---------------- | ---------- |
| Below threshold  | `NORMAL`   |
| 1x threshold     | `MEDIUM`   |
| 2x threshold     | `HIGH`     |
| 5x threshold     | `CRITICAL` |

No config files. No daemons. No accounts. It starts capturing packets immediately and prints what it sees.

---

## Usage

```
sudo ftagent-lite [options]

Options:
  -i, --interface IFACE   Network interface (default: any)
  -t, --interval  SECS    Reporting interval in seconds (default: 2)
  -T, --threshold PPS     PPS alert threshold (default: 5000)
  -j, --json              Machine-readable JSON (one object per line)
  -w, --watch             Live updating terminal dashboard
      --no-color          Disable ANSI colors
  -V, --version           Show version
```

### Examples

```bash
# Monitor all interfaces, default 2-second intervals
sudo ftagent-lite

# Monitor eth0, 5-second intervals, 50K PPS threshold
sudo ftagent-lite -i eth0 -t 5 -T 50000

# Live terminal dashboard
sudo ftagent-lite --watch

# JSON output piped to jq
sudo ftagent-lite --json | jq '{pps: .pps, bps: .bps, srcs: .src_ip_count}'

# Log to file for later analysis
sudo ftagent-lite --json >> /var/log/traffic.jsonl

# Feed into your own alerting
sudo ftagent-lite --json | while read line; do
  pps=$(echo "$line" | jq .pps)
  [ "$pps" -gt 100000 ] && curl -X POST your-webhook -d "$line"
done
```

### JSON Output

Every interval emits one JSON object:

```json
{
  "timestamp": "2026-06-14T03:12:07+00:00",
  "pps": 47821,
  "bps": 215000,
  "tcp": 1530,
  "udp": 45100,
  "icmp": 191,
  "other": 0,
  "tcp_pct": 3.2,
  "udp_pct": 94.1,
  "icmp_pct": 0.4,
  "src_ip_count": 8421,
  "top_src_ips": ["203.0.113.5", "198.51.100.8", "192.0.2.99"],
  "top_dst_ports": [[11211, 31042], [53, 12831], [80, 3201]],
  "avg_pkt_size": 38
}
```

---

## Use Cases

- **Quick diagnostics** -- SSH into a server under attack and see what's hitting it in seconds
- **CI/CD pipelines** -- Run traffic tests against staging and assert PPS stays below a threshold
- **Custom tooling** -- Pipe JSON into your own alerting, dashboards, or SIEM
- **Honeypots and research** -- Log traffic patterns to JSONL for offline analysis
- **Lightweight monitoring** -- Leave it running on a small VPS where a full agent is overkill

---

## Requirements

- Python 3.7+
- Linux (raw socket capture; macOS works with BPF)
- Root / sudo for packet capture
- `scapy` for full protocol analysis (recommended)
- `psutil` as fallback (PPS/BPS only, no protocol breakdown)

---

## Need Production DDoS Protection?

ftagent-lite is intentionally simple: monitor and alert to stdout, nothing more. For teams that need auto-mitigation, multi-node visibility, and incident response, [Flowtriq](https://flowtriq.com) extends the same agent with:

- Attack alerts via Slack, Discord, PagerDuty, Teams, Telegram, SMS, and email
- PCAP forensic capture on every incident
- Automatic classification across 8 attack vector types
- Auto-mitigation through iptables, nftables, Cloudflare, and BGP FlowSpec
- Multi-node cloud dashboard with incident timelines
- Team workspaces with RBAC and unlimited seats
- White-label options for MSPs and hosting providers

[Start a 14-day free trial](https://flowtriq.com/signup) -- no credit card required.

---

## Support

- Discord: [discord.gg/SsTWMYuyGG](https://discord.gg/SsTWMYuyGG)
- Issues: [github.com/Flowtriq/ftagent-lite/issues](https://github.com/Flowtriq/ftagent-lite/issues)

## Contributing

Issues and PRs welcome. This is a single-file tool and we intend to keep it that way.

If you find a bug, please include:
- Python version (`python3 --version`)
- OS and kernel (`uname -a`)
- The command you ran
- The error output

---

## Learn More

- [ftagent-lite on GitHub](https://github.com/Flowtriq/ftagent-lite) - Source code, issues, and releases
- [Start Free Trial](https://flowtriq.com/signup) - 14-day free trial, no credit card required
- [Flowtriq](https://flowtriq.com) - Real-time DDoS detection and mitigation

## License

MIT License. Copyright (c) 2026 [Flowtriq](https://flowtriq.com).

Use it, fork it, ship it. Attribution appreciated but not required.

---

Built by [Flowtriq](https://flowtriq.com) - Real-time DDoS detection and mitigation.
