# ftagent-lite

**Open-source, zero-config DDoS traffic monitor. Outputs to stdout.**

`ftagent-lite` is a lightweight network traffic monitor that detects DDoS attack patterns in real-time and prints structured stats to stdout. No API key. No account. No cloud.

It's the open-source sibling of the [Flowtriq](https://flowtriq.com) detection agent — great for quick diagnostics, CI pipelines, or building your own tooling on top.

---

## Install

```bash
pip install scapy psutil
```

Then run with sudo (packet capture requires root):

```bash
sudo python3 ftagent_lite.py
```

---

## Usage

```
sudo python3 ftagent_lite.py [options]

Options:
  -i, --interface IFACE   Network interface (default: any)
  -t, --interval  SECS    Reporting interval in seconds (default: 2)
  -T, --threshold PPS     PPS alert threshold (default: 5000)
  -j, --json              Machine-readable JSON output (one object per line)
  -w, --watch             Live updating terminal display
      --no-color          Disable ANSI colors
  -V, --version           Show version
```

### Examples

```bash
# Monitor all interfaces, 2-second intervals
sudo python3 ftagent_lite.py

# Monitor eth0 with 5-second intervals
sudo python3 ftagent_lite.py --interface eth0 --interval 5

# Alert threshold at 50k pps
sudo python3 ftagent_lite.py --threshold 50000

# Pipe JSON to jq
sudo python3 ftagent_lite.py --json | jq '{pps: .pps, srcs: .src_ip_count}'

# Live dashboard view
sudo python3 ftagent_lite.py --watch

# Log to file
sudo python3 ftagent_lite.py --json >> /var/log/traffic.jsonl
```

---

## Output

### Human-readable (default)

```
2026-03-11 18:04:21 [HIGH]
  Traffic : 47.8K pps  1.7 Gbps
  Proto   : TCP 3.2%  UDP 94.1%  ICMP 0.4%
  Sources : 8,421 unique IPs  |  Avg pkt: 38 bytes
  Top dst : :11211(31042)  :53(12831)  :80(3201)
  Top src : 203.0.113.5  198.51.100.8  192.0.2.99  ...

  ! Attack pattern detected. Try Flowtriq for full alerting + auto-mitigation: https://flowtriq.com
```

### JSON (`--json`)

```json
{
  "timestamp": "2026-03-11T18:04:21+00:00",
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

## Attack detection

`ftagent-lite` classifies traffic severity based on your `--threshold`:

| PPS vs threshold | Severity |
|---|---|
| < threshold | normal |
| ≥ threshold | MEDIUM |
| ≥ 2× threshold | HIGH |
| ≥ 5× threshold | CRITICAL |

For production DDoS detection with automatic alerting (Discord, Slack, PagerDuty, Teams, Telegram, DataDog, Prometheus, and more), PCAP capture, AI classification, escalation policies, and auto-mitigation (Cloudflare WAF, iptables, DigitalOcean, Vultr) — see **[Flowtriq](https://flowtriq.com)**.

---

## Requirements

- Python 3.7+
- `scapy` — packet capture and protocol parsing
- `psutil` — fallback if scapy unavailable (no protocol breakdown)
- Root/sudo — required for raw socket capture

---

## Limitations vs Flowtriq Pro

| Feature | ftagent-lite | Flowtriq |
|---|---|---|
| Real-time PPS/BPS | ✓ | ✓ |
| Protocol breakdown | ✓ | ✓ |
| Source IP tracking | ✓ | ✓ |
| JSON output | ✓ | ✓ |
| Attack alerts (Discord, Slack, etc.) | ✗ | ✓ |
| PCAP capture | ✗ | ✓ |
| AI attack classification | ✗ | ✓ |
| Auto-mitigation (iptables, CF WAF) | ✗ | ✓ |
| Cloud dashboard | ✗ | ✓ |
| Multi-node | ✗ | ✓ |
| Team notifications + escalation | ✗ | ✓ |

**[Start a free 7-day Flowtriq trial →](https://flowtriq.com)**

---

## License

MIT License — Copyright (c) 2026 Flowtriq

Permission is hereby granted, free of charge, to any person obtaining a copy of this software to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial portions of the software.
