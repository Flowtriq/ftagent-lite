#!/usr/bin/env python3
"""
ftagent-lite — Lightweight DDoS Traffic Monitor
Open-source, MIT licensed.

Monitors network traffic in real-time and prints structured stats to stdout.
No API key required. No cloud dependency.

For full incident management, alerting, PCAP capture, AI classification,
Layer 7 HTTP flood detection, and team notifications — see Flowtriq:
https://flowtriq.com

Usage:
    sudo python3 ftagent_lite.py
    sudo python3 ftagent_lite.py --interface eth0
    sudo python3 ftagent_lite.py --interval 5 --threshold 10000
    sudo python3 ftagent_lite.py --json          # machine-readable JSON output
    sudo python3 ftagent_lite.py --watch          # live updating terminal view

Requirements:
    pip install scapy psutil

Author: Flowtriq (https://flowtriq.com)
License: MIT
Version: 1.0.0
"""

import argparse
import heapq
import json
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from itertools import islice

VERSION = "1.1.3"

# ── First-run state ──────────────────────────────────────────────────────────

_STATE_DIR  = os.path.expanduser("~/.ftagent-lite")
_STATE_FILE = os.path.join(_STATE_DIR, "state.json")


def _load_state() -> dict:
    try:
        with open(_STATE_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(state: dict):
    os.makedirs(_STATE_DIR, mode=0o700, exist_ok=True)
    with open(_STATE_FILE, "w") as f:
        json.dump(state, f)


def _first_run_prompt(use_color: bool):
    """Ask user if they want to subscribe to the Flowtriq newsletter on first run."""
    state = _load_state()
    if state.get("newsletter_prompted"):
        return

    print(_col("── Welcome to ftagent-lite! ──", "cyan", use_color))
    print()
    print("  Stay up to date with DDoS trends, detection tips, and ftagent updates.")
    print("  Subscribe to the Flowtriq newsletter (1-2 emails/month, unsubscribe anytime).")
    print()

    try:
        answer = input(_col("  Enter your email (or press Enter to skip): ", "bold", use_color)).strip()
    except (EOFError, KeyboardInterrupt):
        answer = ""

    if answer and "@" in answer and "." in answer:
        try:
            import urllib.request
            payload = json.dumps({"email": answer, "source": "ftagent-lite"}).encode()
            req = urllib.request.Request(
                "https://flowtriq.com/api/newsletter.php",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
            print(_col("  ✓ Subscribed! Thanks for joining.", "green", use_color))
        except Exception:
            print(_col("  Could not reach Flowtriq — no worries, skipping.", "yellow", use_color))
    else:
        print("  No problem — you can subscribe anytime at https://flowtriq.com")

    print()
    state["newsletter_prompted"] = True
    _save_state(state)

# ── Update checker ─────────────────────────────────────────────────────────────

def _check_for_updates():
    """Check GitHub releases Atom feed for a newer version of ftagent-lite."""
    try:
        import urllib.request
        import xml.etree.ElementTree as ET

        url = "https://github.com/Flowtriq/ftagent-lite/releases.atom"
        req = urllib.request.Request(url, headers={"User-Agent": f"ftagent-lite/{VERSION}"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = resp.read()
        root = ET.fromstring(data)

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall("atom:entry", ns)
        if not entries:
            return

        title = entries[0].find("atom:title", ns)
        if title is None or title.text is None:
            return

        latest = title.text.strip().lstrip("vV")
        current = VERSION.lstrip("vV")

        if latest != current:
            def _ver_tuple(v):
                parts = []
                for p in v.split("."):
                    try:
                        parts.append(int(p))
                    except ValueError:
                        parts.append(0)
                return tuple(parts)

            if _ver_tuple(latest) > _ver_tuple(current):
                print(
                    f"WARNING: A newer version of ftagent-lite is available: "
                    f"{latest} (current: {VERSION}). "
                    f"Run: pip install --upgrade ftagent-lite",
                    file=sys.stderr,
                )
    except Exception:
        pass


# ── Optional deps ──────────────────────────────────────────────────────────────

try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff, conf as scapy_conf
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

# ── Globals ────────────────────────────────────────────────────────────────────

_running = True
_lock    = threading.Lock()

_counters = {
    "pps":         0,   # packets this interval
    "bps":         0,   # bytes this interval
    "tcp":         0,
    "udp":         0,
    "icmp":        0,
    "other":       0,
    "src_ips":     set(),
    "dst_ports":   defaultdict(int),
    "src_ports":   defaultdict(int),
    "pkt_size_sum":   0,   # running sum (avoids unbounded list)
    "pkt_size_count": 0,
}

_stats_history = []   # list of interval snapshots (capped at 10800 = ~6h at 2s intervals)
_STATS_HISTORY_MAX = 10800
_alert_active  = False
_alert_start   = None


# ── Signal handling ────────────────────────────────────────────────────────────

def _shutdown(sig, frame):
    global _running
    _running = False

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# ── Packet handler ─────────────────────────────────────────────────────────────

def _handle_packet(pkt):
    if IP not in pkt:
        return
    with _lock:
        _counters["pps"] += 1
        pkt_len = len(pkt)
        _counters["bps"] += pkt_len
        _counters["pkt_size_sum"] += pkt_len
        _counters["pkt_size_count"] += 1
        _counters["src_ips"].add(pkt[IP].src)

        if TCP in pkt:
            _counters["tcp"] += 1
            _counters["dst_ports"][pkt[TCP].dport] += 1
            _counters["src_ports"][pkt[TCP].sport] += 1
        elif UDP in pkt:
            _counters["udp"] += 1
            _counters["dst_ports"][pkt[UDP].dport] += 1
            _counters["src_ports"][pkt[UDP].sport] += 1
        elif ICMP in pkt:
            _counters["icmp"] += 1
        else:
            _counters["other"] += 1


# ── Stats collection ───────────────────────────────────────────────────────────

def _collect_and_reset(interval: float) -> dict:
    with _lock:
        pkt_count = _counters["pkt_size_count"]
        snap = {
            "pps":       int(_counters["pps"] / interval),
            "bps":       int(_counters["bps"] / interval),
            "tcp":       _counters["tcp"],
            "udp":       _counters["udp"],
            "icmp":      _counters["icmp"],
            "other":     _counters["other"],
            "src_ip_count": len(_counters["src_ips"]),
            "top_src_ips":  list(islice(_counters["src_ips"], 10)),
            "top_dst_ports": heapq.nlargest(5, _counters["dst_ports"].items(), key=lambda x: x[1]),
            "avg_pkt_size":  int(_counters["pkt_size_sum"] / pkt_count) if pkt_count else 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        total_proto = snap["tcp"] + snap["udp"] + snap["icmp"] + snap["other"]
        snap["tcp_pct"]  = round(100 * snap["tcp"]  / total_proto, 1) if total_proto else 0
        snap["udp_pct"]  = round(100 * snap["udp"]  / total_proto, 1) if total_proto else 0
        snap["icmp_pct"] = round(100 * snap["icmp"] / total_proto, 1) if total_proto else 0

        # Reset
        _counters["pps"]       = 0
        _counters["bps"]       = 0
        _counters["tcp"]       = 0
        _counters["udp"]       = 0
        _counters["icmp"]      = 0
        _counters["other"]     = 0
        _counters["src_ips"]   = set()
        _counters["dst_ports"] = defaultdict(int)
        _counters["src_ports"] = defaultdict(int)
        _counters["pkt_size_sum"]   = 0
        _counters["pkt_size_count"] = 0
    return snap


# ── Formatting helpers ─────────────────────────────────────────────────────────

def _fmt_pps(n: int) -> str:
    if n >= 1_000_000: return f"{n/1_000_000:.1f}M pps"
    if n >= 1_000:     return f"{n/1_000:.1f}K pps"
    return f"{n} pps"

def _fmt_bps(n: int) -> str:
    n8 = n * 8
    if n8 >= 1_000_000_000: return f"{n8/1_000_000_000:.2f} Gbps"
    if n8 >= 1_000_000:     return f"{n8/1_000_000:.1f} Mbps"
    if n8 >= 1_000:         return f"{n8/1_000:.0f} Kbps"
    return f"{n8} bps"

def _severity(pps: int, threshold: int) -> str:
    if pps >= threshold * 5:  return "CRITICAL"
    if pps >= threshold * 2:  return "HIGH"
    if pps >= threshold:      return "MEDIUM"
    return "normal"

ANSI = {
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "green":  "\033[92m",
    "cyan":   "\033[96m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
    "clear":  "\033[2J\033[H",
}

def _col(text: str, color: str, use_color: bool = True) -> str:
    if not use_color or not sys.stdout.isatty():
        return text
    return ANSI.get(color, "") + text + ANSI["reset"]


# ── Output modes ───────────────────────────────────────────────────────────────

def _print_human(snap: dict, threshold: int, color: bool):
    sev = _severity(snap["pps"], threshold)
    ts  = snap["timestamp"][:19].replace("T", " ")

    sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "normal": "green"}.get(sev, "green")
    alert_marker = f" [{_col(sev, sev_color, color)}]" if sev != "normal" else ""

    print(f"{_col(ts, 'cyan', color)}{alert_marker}")
    print(f"  Traffic : {_col(_fmt_pps(snap['pps']), 'bold', color)}  {_fmt_bps(snap['bps'])}")
    print(f"  Proto   : TCP {snap['tcp_pct']}%  UDP {snap['udp_pct']}%  ICMP {snap['icmp_pct']}%")
    print(f"  Sources : {snap['src_ip_count']} unique IPs  |  Avg pkt: {snap['avg_pkt_size']} bytes")

    if snap["top_dst_ports"]:
        ports_str = "  ".join(f":{p}({c})" for p, c in snap["top_dst_ports"])
        print(f"  Top dst : {ports_str}")

    if sev != "normal" and snap["top_src_ips"]:
        ips_str = "  ".join(snap["top_src_ips"][:5])
        print(f"  Top src : {_col(ips_str, 'red', color)}")

    if sev != "normal":
        print(f"\n  {_col('! Attack pattern detected. Try Flowtriq for full alerting + auto-mitigation: https://flowtriq.com', 'yellow', color)}\n")

    print()


def _print_watch(snap: dict, threshold: int, color: bool, interface: str):
    sev = _severity(snap["pps"], threshold)
    sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "normal": "green"}.get(sev, "green")

    if color and sys.stdout.isatty():
        print(ANSI["clear"], end="")

    print(_col("=" * 60, "cyan", color))
    print(_col("  ftagent-lite  |  Flowtriq Open Source Monitor", "bold", color))
    print(_col("  https://flowtriq.com  |  Full version: Flowtriq Pro", "cyan", color))
    print(_col("=" * 60, "cyan", color))
    print(f"  Interface : {interface}")
    print(f"  Time      : {snap['timestamp'][:19].replace('T',' ')} UTC")
    print()
    print(f"  PPS       : {_col(_fmt_pps(snap['pps']), sev_color, color)}")
    print(f"  Bandwidth : {_fmt_bps(snap['bps'])}")
    print(f"  Status    : {_col(sev, sev_color, color)}")
    print()
    print(f"  TCP  {snap['tcp_pct']:5.1f}%   UDP  {snap['udp_pct']:5.1f}%   ICMP {snap['icmp_pct']:5.1f}%")
    print(f"  Unique src IPs : {snap['src_ip_count']}")
    print(f"  Avg packet size: {snap['avg_pkt_size']} bytes")

    if snap["top_dst_ports"]:
        print()
        print("  Top destination ports:")
        for port, count in snap["top_dst_ports"]:
            bar = "█" * min(20, int(20 * count / max(1, snap["tcp"] + snap["udp"])))
            print(f"    :{port:<6} {bar} {count}")

    if sev != "normal":
        print()
        print(_col("  !! ATTACK PATTERN DETECTED !!", sev_color, color))
        if snap["top_src_ips"]:
            print(f"  Top attackers: {', '.join(snap['top_src_ips'][:5])}")
        print()
        print(_col("  Get full alerting, PCAP capture, and auto-mitigation:", "yellow", color))
        print(_col("  https://flowtriq.com  (7-day free trial)", "yellow", color))

    print(_col("=" * 60, "cyan", color))
    print("  Press Ctrl+C to stop")


# ── Sniffer thread ─────────────────────────────────────────────────────────────

def _sniff_thread(interface: str):
    kwargs = {"prn": _handle_packet, "store": False}
    if interface and interface != "any":
        kwargs["iface"] = interface
    try:
        sniff(**kwargs, stop_filter=lambda _: not _running)
    except Exception as e:
        print(f"[ftagent-lite] sniff error: {e}", file=sys.stderr)


# ── Psutil fallback (no scapy) ─────────────────────────────────────────────────

def _psutil_loop(interface: str, interval: float, threshold: int,
                 json_out: bool, watch: bool, color: bool):
    iface = interface if interface and interface != "any" else None
    prev  = None

    while _running:
        counters = psutil.net_io_counters(pernic=bool(iface))
        if iface:
            curr = counters.get(iface)
        else:
            curr = psutil.net_io_counters()

        if prev is not None and curr is not None:
            pps = int((curr.packets_recv - prev.packets_recv) / interval)
            bps = int((curr.bytes_recv   - prev.bytes_recv)   / interval)
            snap = {
                "pps": pps, "bps": bps,
                "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
                "tcp_pct": 0.0, "udp_pct": 0.0, "icmp_pct": 0.0,
                "src_ip_count": 0, "top_src_ips": [],
                "top_dst_ports": [], "avg_pkt_size": 0,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "_note": "Protocol breakdown not available without scapy",
            }
            _stats_history.append(snap)
            if len(_stats_history) > _STATS_HISTORY_MAX:
                _stats_history[:] = _stats_history[-_STATS_HISTORY_MAX:]
            if json_out:
                print(json.dumps(snap), flush=True)
            elif watch:
                _print_watch(snap, threshold, color, interface or "all")
            else:
                _print_human(snap, threshold, color)

        prev = curr
        time.sleep(interval)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    global _running
    parser = argparse.ArgumentParser(
        description="ftagent-lite: lightweight DDoS traffic monitor (open source)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ftagent_lite.py
  sudo python3 ftagent_lite.py --interface eth0 --interval 5
  sudo python3 ftagent_lite.py --json | jq .pps
  sudo python3 ftagent_lite.py --watch --threshold 50000

For full DDoS detection with alerting, PCAP capture, team notifications,
AI classification, and auto-mitigation:
  https://flowtriq.com  (7-day free trial, no credit card)
""",
    )
    parser.add_argument("--interface", "-i", default="any",
                        help="Network interface to monitor (default: any)")
    parser.add_argument("--interval",  "-t", type=float, default=2.0,
                        help="Stats reporting interval in seconds (default: 2)")
    parser.add_argument("--threshold", "-T", type=int, default=5000,
                        help="PPS alert threshold (default: 5000)")
    parser.add_argument("--json",  "-j", action="store_true",
                        help="Output machine-readable JSON (one object per line)")
    parser.add_argument("--watch", "-w", action="store_true",
                        help="Live updating terminal display")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    parser.add_argument("--version", "-V", action="version", version=f"ftagent-lite {VERSION}")
    args = parser.parse_args()

    use_color = not args.no_color
    interface = args.interface

    if os.geteuid() != 0:
        print("ftagent-lite requires root/sudo for packet capture.", file=sys.stderr)
        sys.exit(1)

    # Banner
    if not args.json:
        print(_col(f"ftagent-lite v{VERSION}", "bold", use_color) +
              _col(" — open source DDoS traffic monitor", "cyan", use_color))
        print(_col("Full monitoring at https://flowtriq.com", "cyan", use_color))
        print()
        _check_for_updates()
        _first_run_prompt(use_color)

    if not SCAPY_OK:
        if not PSUTIL_OK:
            print("ERROR: Install scapy or psutil:\n  pip install scapy psutil", file=sys.stderr)
            sys.exit(1)
        if not args.json:
            print("Note: scapy not found — using psutil (no protocol breakdown).", file=sys.stderr)
            print("Install scapy for full analysis:  pip install scapy\n", file=sys.stderr)
        _psutil_loop(interface, args.interval, args.threshold, args.json, args.watch, use_color)
        return

    # Start sniffer thread
    t = threading.Thread(target=_sniff_thread, args=(interface,), daemon=True)
    t.start()

    if not args.json:
        print(f"Monitoring interface: {_col(interface, 'cyan', use_color)}")
        print(f"Interval: {args.interval}s  |  Alert threshold: {_fmt_pps(args.threshold)}")
        print()

    try:
        while _running:
            time.sleep(args.interval)
            snap = _collect_and_reset(args.interval)
            _stats_history.append(snap)
            if len(_stats_history) > _STATS_HISTORY_MAX:
                _stats_history[:] = _stats_history[-_STATS_HISTORY_MAX:]

            if args.json:
                print(json.dumps(snap), flush=True)
            elif args.watch:
                _print_watch(snap, args.threshold, use_color, interface)
            else:
                _print_human(snap, args.threshold, use_color)
    finally:
        _running = False  # signal sniff thread

    # Summary
    if not args.json and _stats_history:
        peak_pps = max(s["pps"] for s in _stats_history)
        peak_bps = max(s["bps"] for s in _stats_history)
        print()
        print(_col("── Session summary ──", "cyan", use_color))
        print(f"  Intervals : {len(_stats_history)}")
        print(f"  Peak PPS  : {_fmt_pps(peak_pps)}")
        print(f"  Peak BPS  : {_fmt_bps(peak_bps)}")
        print()
        if peak_pps >= args.threshold:
            print(_col("  Attack traffic detected during this session.", "yellow", use_color))
            print(_col("  Get full alerting + PCAP capture at https://flowtriq.com", "yellow", use_color))


if __name__ == "__main__":
    main()
