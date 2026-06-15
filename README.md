# ftagent-lite

[![PyPI](https://img.shields.io/pypi/v/ftagent-lite)](https://pypi.org/project/ftagent-lite/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://pypi.org/project/ftagent-lite/)

**Real-time DDoS traffic monitor that prints to stdout. Single file. No account. No cloud.**

Drop it on any Linux server and see packets per second, bandwidth, protocol breakdown, source IP cardinality, and attack severity in real time. Pipe JSON to your own tooling or watch the live dashboard in your terminal.

```
2026-06-14 03:12:07 [HIGH]
  Traffic : 47.8K pps  1.7 Gbps
  Proto   : TCP 3.2%  UDP 94.1%  ICMP 0.4%
  Sources : 8,421 unique IPs  |  Avg pkt: 38 bytes
  Top dst : :11211(31042)  :53(12831)  :80(3201)
  Top src : 203.0.113.5  198.51.100.8  192.0.2.99
```

---

## Install

```bash
pip install ftagent-lite[full]
```

That pulls in `scapy` (packet capture + protocol parsing) and `psutil` (fallback). Then:

```bash
sudo ftagent-lite
```

Or run the single file directly without installing:

```bash
curl -O https://raw.githubusercontent.com/Flowtriq/ftagent-lite/main/ftagent_lite.py
pip install scapy psutil
sudo python3 ftagent_lite.py
```

Root/sudo is required for raw socket capture.

---

## What it does

**Two things, well:**

1. **Traffic monitoring** -- PPS, bandwidth (Gbps/Mbps), TCP/UDP/ICMP breakdown, unique source IPs, top destination ports, average packet size. Every interval, printed to stdout.

2. **Attack pattern detection** -- Classifies traffic severity against your threshold. When PPS exceeds the threshold, it flags the interval, shows top source IPs, and identifies the attack pattern.

| PPS vs threshold | Severity |
|---|---|
| Below threshold | `NORMAL` |
| 1x threshold | `MEDIUM` |
| 2x threshold | `HIGH` |
| 5x threshold | `CRITICAL` |

That's it. No config files. No daemons. No accounts. It starts capturing packets immediately and prints what it sees.

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

### JSON output

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

## Use cases

- **Quick diagnostics** -- SSH into a server under attack and see what's hitting it in 2 seconds flat
- **CI/CD pipelines** -- Run traffic tests against a staging server and assert PPS stays below a threshold
- **Custom tooling** -- Pipe JSON into your own alerting, dashboards, or SIEM
- **Honeypots and research** -- Log all traffic patterns to JSONL for offline analysis
- **Lightweight monitoring** -- Leave it running on a small VPS where a full agent is overkill

---

## Requirements

- Python 3.7+
- Linux (raw socket capture; macOS works with BPF)
- Root/sudo for packet capture
- `scapy` for full protocol analysis (recommended)
- `psutil` as fallback (PPS/BPS only, no protocol breakdown)

---

## When you need more

ftagent-lite is intentionally simple: two features, stdout output, zero dependencies on external services. If you need production DDoS detection, this is where it stops and [Flowtriq](https://flowtriq.com) picks up:

| Capability | ftagent-lite | [Flowtriq](https://flowtriq.com) |
|---|---|---|
| Real-time PPS / BPS | Yes | Yes |
| Protocol breakdown | Yes | Yes |
| Source IP tracking | Yes | Yes |
| JSON stdout output | Yes | Yes |
| Attack alerts (Slack, Discord, PagerDuty, Teams, Telegram, SMS, email) | -- | Yes |
| PCAP forensic capture | -- | Yes |
| Automatic attack classification (8 vector types) | -- | Yes |
| Auto-mitigation (iptables, nftables, Cloudflare, BGP FlowSpec) | -- | Yes |
| Multi-node cloud dashboard | -- | Yes |
| Incident timeline and AI analysis | -- | Yes |
| Team workspaces with RBAC | -- | Yes |
| Unlimited team seats | -- | Yes |
| White-label for MSPs / hosting | -- | Yes |

Flowtriq is $9.99/node/month with a [14-day free trial](https://flowtriq.com/signup). No credit card required.

---

## Contributing

Issues and PRs welcome. This is a single-file tool and we intend to keep it that way.

If you find a bug, please include:
- Python version (`python3 --version`)
- OS and kernel (`uname -a`)
- The command you ran
- The error output

---

## License

MIT License. Copyright (c) 2026 [Flowtriq](https://flowtriq.com).

Use it, fork it, ship it. Attribution appreciated but not required.
