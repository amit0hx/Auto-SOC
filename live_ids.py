"""
live_ids.py  —  Real-world bridge for Auto-SOC
================================================
Wireshark/Npcap raw packets  ->  10 NSL-KDD features  ->  ML model  ->  IR playbook

The trained model (model.pkl) does NOT understand raw packets. It was trained on
10 *connection-level aggregated* NSL-KDD features. This script rebuilds those
features from real captured traffic, so the project can be tested on real data
instead of only the synthetic dataset.

  IMPORTANT — these are HONEST APPROXIMATIONS of the real NSL-KDD features:
    * service  is mapped from destination port (real NSL-KDD inspects payload)
    * flag     is derived from observed TCP flags of the flow
    * count / srv_count        = connections in the last 2 seconds (time window)
    * dst_host_* counts        = over the last 100 connections (host window)
  This is the same idea real flow meters use, but simplified for a student project.

USAGE
-----
  # 1) Offline — analyse a .pcap saved from Wireshark (no admin needed):
  python live_ids.py --pcap capture.pcap

  # 2) Live — sniff the network in real time (needs Npcap + Administrator):
  python live_ids.py --live --iface "Wi-Fi" --count 200

  # List available interface names:
  python live_ids.py --list-ifaces

Requires: scapy, joblib, pandas, scikit-learn  (+ Npcap for --live on Windows)
"""

import argparse
import ipaddress
import os
import shutil
import socket
import subprocess
import sys
import time
from collections import deque

# Windows consoles default to cp1252 and choke on emoji in playbooks/severity.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import joblib
import pandas as pd

# Quiet scapy's noisy import warnings on Windows
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import rdpcap, sniff, IP, IPv6, TCP, UDP, get_if_list  # noqa: E402

# Reuse the existing playbook + severity engine from the project
from llm_engine import generate_ir_playbook, get_severity  # noqa: E402


# ── Feature column order MUST match train_model.py exactly ──
FEATURE_COLS = [
    "duration", "protocol_type", "service", "src_bytes", "dst_bytes",
    "flag", "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]

# Map destination port -> service token the model's encoder knows.
# (Encoder was fit on: http https dns smtp ftp ssh pop3 imap telnet private other)
PORT_SERVICE = {
    80: "http", 8080: "http", 8000: "http",
    443: "https", 8443: "https",
    53: "dns",
    25: "smtp", 587: "smtp", 465: "smtp",
    21: "ftp", 20: "ftp",
    22: "ssh",
    110: "pop3",
    143: "imap",
    23: "telnet",
}

# Time window (seconds) for count / srv_count, per NSL-KDD "same-host/same-srv".
TIME_WINDOW = 2.0
# Connection window (last N connections) for dst_host_* features.
HOST_WINDOW = 100


def port_to_service(dport):
    """Best-effort service name from destination port (encoder-safe tokens only)."""
    if dport in PORT_SERVICE:
        return PORT_SERVICE[dport]
    # NSL-KDD lumps unrecognised high ports as 'private', rest as 'other'.
    return "private" if dport and dport >= 1024 else "other"


def derive_flag(f):
    """
    Derive an NSL-KDD-style connection flag from the TCP flags we observed
    across the whole flow. Only returns tokens the encoder was trained on:
    SF, S0, REJ, RSTO, RSTR, SH.
    """
    syn, synack, fin, rst = f["syn"], f["synack"], f["fin"], f["rst"]
    if synack and fin:
        return "SF"            # established + clean close
    if synack and rst:
        return "RSTO"          # established then reset
    if synack:
        return "SF"            # established, still open / no close seen
    if syn and rst:
        return "REJ"           # connection refused (RST to SYN)
    if syn and not synack:
        return "S0"            # SYN with no reply (typical scan / SYN flood)
    if rst:
        return "RSTR"
    return "SH"                # SYN to half-open / nothing else


def packets_to_flows(packets):
    """
    Group raw packets into flows keyed by (proto, src, dst, sport, dport),
    treating both directions of a TCP/UDP conversation as one flow.
    Returns a list of flow dicts ordered by first-seen time.
    """
    flows = {}
    order = []

    for pkt in packets:
        # Handle both IPv4 and IPv6 (modern traffic is mostly IPv6).
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            continue
        ip_src, ip_dst = ip.src, ip.dst
        ts = float(pkt.time)
        length = len(pkt)

        if TCP in pkt:
            proto, l4 = "tcp", pkt[TCP]
            sport, dport = int(l4.sport), int(l4.dport)
        elif UDP in pkt:
            proto, l4 = "udp", pkt[UDP]
            sport, dport = int(l4.sport), int(l4.dport)
        else:
            # ICMP / ICMPv6 / other -> map to NSL-KDD 'icmp' (no ports).
            proto, l4 = "icmp", None
            sport, dport = 0, 0

        # Canonical key so A->B and B->A map to the same flow.
        a, b = (ip_src, sport), (ip_dst, dport)
        fwd = a <= b
        key = (proto, a, b) if fwd else (proto, b, a)

        if key not in flows:
            flows[key] = {
                "proto": proto,
                "src": ip_src if fwd else ip_dst,
                "dst": ip_dst if fwd else ip_src,
                "dport": dport if fwd else sport,
                "first_ts": ts, "last_ts": ts,
                "src_bytes": 0, "dst_bytes": 0,
                "syn": False, "synack": False, "fin": False, "rst": False,
            }
            order.append(key)
        fl = flows[key]
        fl["last_ts"] = ts

        # Direction: is this packet going src->dst (forward) for the flow?
        going_fwd = (ip.src == fl["src"])
        if going_fwd:
            fl["src_bytes"] += length
        else:
            fl["dst_bytes"] += length

        if proto == "tcp" and l4 is not None:
            flags = l4.flags
            S, A, F, R = 0x02, 0x10, 0x01, 0x04
            if (flags & S) and not (flags & A):
                fl["syn"] = True
            if (flags & S) and (flags & A):
                fl["synack"] = True
            if flags & F:
                fl["fin"] = True
            if flags & R:
                fl["rst"] = True

    return [flows[k] for k in order]


def flow_to_features(fl, history):
    """Convert one flow dict + connection history into the 10 model features."""
    service = port_to_service(fl["dport"]) if fl["proto"] != "icmp" else "other"
    flag = derive_flag(fl) if fl["proto"] == "tcp" else "SF"
    duration = int(fl["last_ts"] - fl["first_ts"])

    now = fl["first_ts"]
    # Time-window (2s) same-host / same-srv counts.
    recent = [h for h in history if now - h["ts"] <= TIME_WINDOW]
    count = sum(1 for h in recent if h["dst"] == fl["dst"])
    srv_count = sum(1 for h in recent if h["service"] == service)
    # Last-100-connections same-host / same-srv counts.
    last100 = list(history)[-HOST_WINDOW:]
    dst_host_count = sum(1 for h in last100 if h["dst"] == fl["dst"])
    dst_host_srv_count = sum(1 for h in last100 if h["service"] == service)

    # Record this connection into history for subsequent flows.
    history.append({"ts": now, "dst": fl["dst"], "service": service})

    return {
        "duration": duration,
        "protocol_type": fl["proto"],
        "service": service,
        "src_bytes": fl["src_bytes"],
        "dst_bytes": fl["dst_bytes"],
        "flag": flag,
        "count": count,
        "srv_count": srv_count,
        "dst_host_count": dst_host_count,
        "dst_host_srv_count": dst_host_srv_count,
        "_src": fl["src"], "_dst": fl["dst"],  # for display only
    }


def safe_encode(encoder, value):
    """Transform a value with a fitted LabelEncoder, falling back if unseen."""
    try:
        return int(encoder.transform([value])[0])
    except ValueError:
        return 0  # unknown category -> same fallback as app.py


_SEV_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}
_rdns_cache = {}


def _origin(ip):
    """Classify an IP as INTERNAL (private/link-local/loopback) or EXTERNAL."""
    try:
        obj = ipaddress.ip_address(ip)
        if obj.is_private or obj.is_link_local or obj.is_loopback:
            return "INTERNAL"
        return "EXTERNAL"
    except ValueError:
        return "?"


def _rdns(ip):
    """Best-effort reverse-DNS lookup (cached, short timeout, never raises)."""
    if ip in _rdns_cache:
        return _rdns_cache[ip]
    socket.setdefaulttimeout(1.5)
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = "-"
    _rdns_cache[ip] = host
    return host


def print_source_report(attack_records, resolve=True):
    """
    Aggregate detected attacks by source IP and print an analyst-facing
    'who attacked' report: origin (internal/external), attack types, targets,
    worst severity, flow count, and (optionally) reverse-DNS — ranked by volume.
    """
    if not attack_records:
        print("\n[+] No attack sources to report (all traffic benign).")
        return

    agg = {}
    for r in attack_records:
        a = agg.setdefault(r["src"], {"flows": 0, "types": set(),
                                      "targets": set(), "sev": "INFO"})
        a["flows"] += 1
        a["types"].add(r["pred"])
        a["targets"].add(r["dst"])
        if _SEV_ORDER.get(r["severity"], 0) > _SEV_ORDER.get(a["sev"], 0):
            a["sev"] = r["severity"]

    ranked = sorted(agg.items(), key=lambda kv: kv[1]["flows"], reverse=True)
    print("\n" + "=" * 70)
    print(" ATTACK SOURCE IDENTIFICATION  (who is attacking)")
    print("=" * 70)
    for i, (ip, a) in enumerate(ranked, 1):
        origin = _origin(ip)
        types = ",".join(sorted(a["types"]))
        tlist = list(a["targets"])
        tgts = ",".join(tlist[:2]) + (f" +{len(tlist) - 2}" if len(tlist) > 2 else "")
        print(f" {i:>2}. {ip:<40} {origin:<8} {a['sev']:<8} "
              f"{a['flows']:>3} flow(s)  [{types}] -> {tgts}")
        if resolve and origin == "EXTERNAL":
            host = _rdns(ip)
            if host != "-":
                print(f"       rDNS: {host}")
    print("-" * 70)
    print(f" {len(ranked)} unique attacker source(s).")
    print(" Action: block/rate-limit EXTERNAL sources at the firewall;")
    print("         investigate INTERNAL sources for possible compromise.")
    print("=" * 70)


def load_model():
    try:
        model = joblib.load("model.pkl")
        encoders = joblib.load("encoders.pkl")
        return model, encoders
    except FileNotFoundError:
        sys.exit("[-] model.pkl / encoders.pkl not found. Run train_model.py first.")


def _encode_row(feat, encoders):
    """Build a single encoder-safe feature row from a feature dict."""
    row = {c: feat[c] for c in FEATURE_COLS}
    row["protocol_type"] = safe_encode(encoders["protocol_type"], row["protocol_type"])
    row["service"] = safe_encode(encoders["service"], row["service"])
    row["flag"] = safe_encode(encoders["flag"], row["flag"])
    return row


def _print_verdict(feat, pred, want_playbook, prefix=""):
    """Print one connection's verdict line (+ playbook if it's an attack)."""
    sev = get_severity(pred)
    tag = "OK " if pred == "Normal" else "!! "
    print(f"{prefix}{tag}{sev['color']} {pred:7s} [{sev['level']:8s}]  "
          f"{feat['_src']:>22} -> {feat['_dst']:<22}  "
          f"{feat['protocol_type']}/{feat['service']} flag={feat['flag']} "
          f"src={feat['src_bytes']}B dst={feat['dst_bytes']}B", flush=True)
    if pred != "Normal" and want_playbook:
        log = {c: feat[c] for c in FEATURE_COLS}
        print("-" * 70)
        print(generate_ir_playbook(log, pred))
        print("-" * 70, flush=True)


def predict_and_report(feats_list, model, encoders, want_playbook, resolve=True):
    """Run features through the model and print results + playbooks for attacks."""
    if not feats_list:
        print("[-] No IP flows found in the capture.")
        return

    X = pd.DataFrame([_encode_row(f, encoders) for f in feats_list], columns=FEATURE_COLS)
    preds = model.predict(X)

    attack_records = []
    print("\n" + "=" * 70)
    print(f" Auto-SOC — analysed {len(preds)} real connections")
    print("=" * 70)
    for f, pred in zip(feats_list, preds):
        _print_verdict(f, pred, want_playbook)
        if pred != "Normal":
            attack_records.append({"src": f["_src"], "dst": f["_dst"],
                                   "pred": pred, "severity": get_severity(pred)["level"]})

    print("=" * 70)
    print(f" Summary: {len(attack_records)} attack(s) / {len(preds)} connections")
    print("=" * 70)
    print_source_report(attack_records, resolve)


def run_pcap(path, model, encoders, want_playbook, resolve=True):
    print(f"[*] Reading capture file: {path}")
    packets = rdpcap(path)
    print(f"[*] {len(packets)} packets loaded.")
    flows = packets_to_flows(packets)
    history = deque(maxlen=HOST_WINDOW * 2)
    feats = [flow_to_features(fl, history) for fl in flows]
    predict_and_report(feats, model, encoders, want_playbook, resolve)


def run_live(iface, max_count, model, encoders, want_playbook, timeout=None, resolve=True):
    print(f"[*] Live sniffing on '{iface}' — up to {max_count} packets"
          f"{f' / {timeout}s' if timeout else ''}. Ctrl+C to stop early.")
    try:
        packets = sniff(iface=iface, count=max_count, timeout=timeout, store=True)
    except PermissionError:
        sys.exit("[-] Permission denied. Run this terminal as Administrator (Npcap needs it).")
    except OSError as e:
        sys.exit(f"[-] Capture failed: {e}\n    Is Npcap installed? Is the interface name correct? "
                 f"(use --list-ifaces)")
    print(f"[*] Captured {len(packets)} packets.")
    flows = packets_to_flows(packets)
    history = deque(maxlen=HOST_WINDOW * 2)
    feats = [flow_to_features(fl, history) for fl in flows]
    predict_and_report(feats, model, encoders, want_playbook, resolve)


def find_tshark():
    """Locate tshark.exe (Wireshark's CLI engine)."""
    p = shutil.which("tshark")
    if p:
        return p
    for guess in (r"C:\Program Files\Wireshark\tshark.exe",
                  r"C:\Program Files (x86)\Wireshark\tshark.exe"):
        if os.path.exists(guess):
            return guess
    return None


# tshark field order we request (one packet per line, '|' separated).
_TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
    "tcp.flags", "frame.len",
]


def _tshark_line_to_pkt(line):
    """Parse one '|'-separated tshark field line into a normalised packet dict."""
    f = line.rstrip("\n").split("|")
    if len(f) < len(_TSHARK_FIELDS):
        return None
    (t_epoch, ip4s, ip6s, ip4d, ip6d,
     tsport, usport, tdport, udport, tflags, flen) = f[:len(_TSHARK_FIELDS)]

    src = ip4s or ip6s
    dst = ip4d or ip6d
    if not src or not dst:
        return None  # non-IP (ARP, etc.)

    if tsport or tdport:
        proto, sport, dport = "tcp", int(tsport or 0), int(tdport or 0)
    elif usport or udport:
        proto, sport, dport = "udp", int(usport or 0), int(udport or 0)
    else:
        proto, sport, dport = "icmp", 0, 0

    try:
        ts = float(t_epoch)
    except ValueError:
        return None
    length = int(flen) if flen else 0
    flags = int(tflags, 16) if (proto == "tcp" and tflags) else 0
    return {"ts": ts, "src": src, "dst": dst, "proto": proto,
            "sport": sport, "dport": dport, "flags": flags, "len": length}


def _update_flow(flows, order, pkt):
    """Fold one parsed packet into the per-window flow table (in place)."""
    a, b = (pkt["src"], pkt["sport"]), (pkt["dst"], pkt["dport"])
    fwd = a <= b
    key = (pkt["proto"], a, b) if fwd else (pkt["proto"], b, a)
    if key not in flows:
        flows[key] = {
            "proto": pkt["proto"],
            "src": pkt["src"] if fwd else pkt["dst"],
            "dst": pkt["dst"] if fwd else pkt["src"],
            "dport": pkt["dport"] if fwd else pkt["sport"],
            "first_ts": pkt["ts"], "last_ts": pkt["ts"],
            "src_bytes": 0, "dst_bytes": 0,
            "syn": False, "synack": False, "fin": False, "rst": False,
        }
        order.append(key)
    fl = flows[key]
    fl["last_ts"] = pkt["ts"]
    if pkt["src"] == fl["src"]:
        fl["src_bytes"] += pkt["len"]
    else:
        fl["dst_bytes"] += pkt["len"]
    if pkt["proto"] == "tcp":
        fg = pkt["flags"]
        S, A, F, R = 0x02, 0x10, 0x01, 0x04
        if (fg & S) and not (fg & A):
            fl["syn"] = True
        if (fg & S) and (fg & A):
            fl["synack"] = True
        if fg & F:
            fl["fin"] = True
        if fg & R:
            fl["rst"] = True


def run_tshark_live(iface, model, encoders, want_playbook, duration=None, flush=5, resolve=True):
    """
    Real-time mode: stream packets from Wireshark's tshark engine, aggregate
    them into connections every `flush` seconds, classify each, and emit
    verdicts + IR playbooks live as traffic happens.
    """
    tshark = find_tshark()
    if not tshark:
        sys.exit("[-] tshark not found. Install Wireshark, or use --live (scapy engine).")

    cmd = [tshark, "-i", iface, "-l", "-n", "-T", "fields", "-E", "separator=|"]
    for fld in _TSHARK_FIELDS:
        cmd += ["-e", fld]
    if duration:
        cmd += ["-a", f"duration:{duration}"]

    print(f"[*] Auto-SOC <-> Wireshark (tshark) LIVE on '{iface}', "
          f"flushing every {flush}s{f', {duration}s total' if duration else ''}. Ctrl+C to stop.")
    print("=" * 70, flush=True)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, bufsize=1)

    history = deque(maxlen=HOST_WINDOW * 2)
    flows, order = {}, []
    window_start = None
    total_conns = 0
    session_attacks = []

    def flush_window():
        nonlocal flows, order, total_conns
        if not order:
            return
        stamp = time.strftime("%H:%M:%S")
        for key in order:
            feat = flow_to_features(flows[key], history)
            pred = model.predict(pd.DataFrame([_encode_row(feat, encoders)],
                                              columns=FEATURE_COLS))[0]
            _print_verdict(feat, pred, want_playbook, prefix=f"[{stamp}] ")
            total_conns += 1
            if pred != "Normal":
                session_attacks.append({"src": feat["_src"], "dst": feat["_dst"],
                                        "pred": pred, "severity": get_severity(pred)["level"]})
        flows, order = {}, []

    try:
        for line in proc.stdout:
            pkt = _tshark_line_to_pkt(line)
            if not pkt:
                continue
            if window_start is None:
                window_start = pkt["ts"]
            _update_flow(flows, order, pkt)
            if pkt["ts"] - window_start >= flush:
                flush_window()
                window_start = pkt["ts"]
    except KeyboardInterrupt:
        print("\n[*] Stopping...")
    finally:
        proc.terminate()
        flush_window()  # classify whatever is left in the last partial window

    print("=" * 70)
    print(f" Session: {len(session_attacks)} attack(s) / {total_conns} connections")
    print("=" * 70)
    print_source_report(session_attacks, resolve)


def list_capture_ifaces():
    """Return [(name, ips_str), ...] of usable capture interfaces (best-effort, for UIs)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        out = []
        for i in get_windows_if_list():
            ips = [ip for ip in (i.get("ips") or []) if ip]
            if ips:
                out.append((i.get("name"), ", ".join(ips[:2])))
        if out:
            return out
    except Exception:
        pass
    return [(n, "") for n in get_if_list()]


def capture_flows_live(iface, count, timeout):
    """Sniff live packets and return the per-connection feature dicts (no printing).
    Reusable by the Streamlit dashboard. Raises on capture/permission errors."""
    packets = sniff(iface=iface, count=count, timeout=timeout, store=True)
    flows = packets_to_flows(packets)
    history = deque(maxlen=HOST_WINDOW * 2)
    return [flow_to_features(fl, history) for fl in flows]


def classify_feats(feats, model, encoders):
    """Classify a list of feature dicts; return list of (feat, prediction) tuples."""
    if not feats:
        return []
    X = pd.DataFrame([_encode_row(f, encoders) for f in feats], columns=FEATURE_COLS)
    preds = model.predict(X)
    return list(zip(feats, preds))


def main():
    ap = argparse.ArgumentParser(description="Auto-SOC real-world IDS bridge")
    ap.add_argument("--pcap", help="Path to a .pcap/.pcapng file saved from Wireshark")
    ap.add_argument("--live", action="store_true", help="Sniff live traffic via scapy (needs Npcap + admin)")
    ap.add_argument("--tshark", action="store_true", help="Real-time mode: stream live from Wireshark's tshark engine")
    ap.add_argument("--iface", help="Interface name for --live/--tshark (see --list-ifaces)")
    ap.add_argument("--count", type=int, default=200, help="Packets to capture in --live mode")
    ap.add_argument("--timeout", type=int, default=None, help="Stop --live/--tshark after N seconds")
    ap.add_argument("--flush", type=int, default=5, help="--tshark: classify connections every N seconds")
    ap.add_argument("--list-ifaces", action="store_true", help="List capture interfaces and exit")
    ap.add_argument("--no-playbook", action="store_true", help="Skip LLM IR playbook output")
    ap.add_argument("--no-resolve", action="store_true", help="Skip reverse-DNS in the attack-source report")
    args = ap.parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for i in get_if_list():
            print("  ", i)
        return

    model, encoders = load_model()
    want_playbook = not args.no_playbook
    resolve = not args.no_resolve

    if args.pcap:
        run_pcap(args.pcap, model, encoders, want_playbook, resolve)
    elif args.tshark:
        if not args.iface:
            sys.exit("[-] --tshark needs --iface. Run --list-ifaces to see names.")
        run_tshark_live(args.iface, model, encoders, want_playbook, args.timeout, args.flush, resolve)
    elif args.live:
        if not args.iface:
            sys.exit("[-] --live needs --iface. Run --list-ifaces to see names.")
        run_live(args.iface, args.count, model, encoders, want_playbook, args.timeout, resolve)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
