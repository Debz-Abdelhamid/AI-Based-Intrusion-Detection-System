"""
IIoT Anomaly Detection Monitor
================================
Captures live packets on the Docker network, aggregates them into 5-second
and 10-second windows, extracts the 37 network features used by the trained
autoencoders, runs inference, and flags anomalies via OR ensemble.

Feature list (37, must match deployment_bundle_net38.pkl exactly):
  network_header-length_max, network_header-length_std_deviation,
  network_interval-packets, network_ip-flags_avg, network_ip-flags_max,
  network_ip-flags_min, network_ip-length_avg, network_ip-length_max,
  network_ip-length_std_deviation, network_ips_all_count,
  network_mss_max, network_mss_std_deviation,
  network_packet-size_avg, network_packet-size_min,
  network_packet-size_std_deviation, network_packets_all_count,
  network_payload-length_min, network_ports_all_count,
  network_ports_dst_count, network_protocols_all_count,
  network_protocols_dst_count, network_protocols_src_count,
  network_tcp-flags-ack_count, network_tcp-flags-fin_count,
  network_tcp-flags-rst_count, network_tcp-flags-syn_count,
  network_tcp-flags_avg, network_tcp-flags_max,
  network_time-delta_avg, network_time-delta_max,
  network_time-delta_min, network_time-delta_std_deviation,
  network_ttl_avg, network_ttl_max, network_ttl_min,
  network_window-size_max, network_window-size_min
"""

import os
import sys
import time
import pickle
import threading
import math
import numpy as np
from collections import deque

# ── Scapy ──────────────────────────────────────────────────────────────────
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

# ── TensorFlow / Keras ─────────────────────────────────────────────────────
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf

# ── Config ─────────────────────────────────────────────────────────────────
MODEL_DIR   = os.environ.get("MODEL_DIR", "/app/models")
IFACE       = os.environ.get("SNIFF_IFACE", None)   # None = auto-detect
SUBNET      = os.environ.get("SUBNET", "192.168.1.0/24")   # iiot net (DataSense scheme)
GADM_URL    = os.environ.get("GADM_URL", "")               # cloud alert sink
WINDOW_5S   = 5.0
WINDOW_10S  = 10.0

# Calibration: observe N windows of normal traffic, then set thresholds at
# the chosen percentile of observed MSE × a small safety margin. This adapts
# the DataSense-trained thresholds to the live Docker environment.
CALIBRATE        = os.environ.get("CALIBRATE", "1") == "1"
CALIB_WINDOWS    = int(os.environ.get("CALIB_WINDOWS", "30"))   # 30 × 5s = 2.5 min
CALIB_PERCENTILE = float(os.environ.get("CALIB_PERCENTILE", "99.0"))
CALIB_MARGIN     = float(os.environ.get("CALIB_MARGIN", "1.10"))  # +10% headroom

BUNDLE_PATH  = os.path.join(MODEL_DIR, "deployment_bundle_net38.pkl")
MODEL_5S_PATH  = os.path.join(MODEL_DIR, "ae_5s_net38.keras")
MODEL_10S_PATH = os.path.join(MODEL_DIR, "ae_10s_net38.keras")

# ── Load deployment bundle ─────────────────────────────────────────────────
print("[monitor] Loading deployment bundle …", flush=True)
with open(BUNDLE_PATH, "rb") as f:
    bundle = pickle.load(f)

FEATURES    = bundle["features"]          # list of 37 feature names
qt_5s       = bundle["qt_5s"]
qt_10s      = bundle["qt_10s"]
thresh_5s   = bundle["thresh_5s"]         # 0.035338
thresh_10s  = bundle["thresh_10s"]        # 0.043487
ENSEMBLE    = bundle.get("ensemble", "OR")

assert len(FEATURES) == 37, f"Expected 37 features, got {len(FEATURES)}"
print(f"[monitor] Features: {len(FEATURES)}  thresh_5s={thresh_5s:.6f}  thresh_10s={thresh_10s:.6f}  ensemble={ENSEMBLE}", flush=True)

# ── Load models ────────────────────────────────────────────────────────────
print("[monitor] Loading AE models …", flush=True)
model_5s  = tf.keras.models.load_model(MODEL_5S_PATH,  compile=False)
model_10s = tf.keras.models.load_model(MODEL_10S_PATH, compile=False)
print("[monitor] Models loaded.", flush=True)

# ── TCP flag bitmasks ──────────────────────────────────────────────────────
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_ACK = 0x10

# ── Packet store (thread-safe deque of dicts) ──────────────────────────────
# Each entry: {ts, ip_len, hdr_len, payload_len, pkt_size, proto,
#              src_ip, dst_ip, src_port, dst_port,
#              ttl, ip_flags, mss, tcp_flags, win_size}
_lock   = threading.Lock()
_pkts   = deque()       # all packets within last ~10s (pruned lazily)

# ── Feature extraction helpers ─────────────────────────────────────────────

def _safe_std(arr):
    return float(np.std(arr)) if len(arr) > 1 else 0.0

def _safe_min(arr, default=0.0):
    return float(min(arr)) if arr else default

def _safe_max(arr, default=0.0):
    return float(max(arr)) if arr else default

def extract_features(pkts):
    """
    Given a list of packet dicts, compute the 37 network features.
    Returns a dict keyed by feature name.
    """
    n = len(pkts)
    if n == 0:
        return {f: 0.0 for f in FEATURES}

    timestamps   = [p["ts"]          for p in pkts]
    ip_lengths   = [p["ip_len"]      for p in pkts]
    hdr_lengths  = [p["hdr_len"]     for p in pkts]
    payload_lens = [p["payload_len"] for p in pkts]
    pkt_sizes    = [p["pkt_size"]    for p in pkts]
    protos       = [p["proto"]       for p in pkts]
    src_ips      = [p["src_ip"]      for p in pkts]
    dst_ips      = [p["dst_ip"]      for p in pkts]
    src_ports    = [p["src_port"]    for p in pkts if p["src_port"] is not None]
    dst_ports    = [p["dst_port"]    for p in pkts if p["dst_port"] is not None]
    ttls         = [p["ttl"]         for p in pkts if p["ttl"] is not None]
    ip_flags_l   = [p["ip_flags"]    for p in pkts if p["ip_flags"] is not None]
    mss_l        = [p["mss"]         for p in pkts if p["mss"] is not None]
    tcp_flags_l  = [p["tcp_flags"]   for p in pkts if p["tcp_flags"] is not None]
    win_sizes    = [p["win_size"]    for p in pkts if p["win_size"] is not None]

    # Time deltas between consecutive packets
    sorted_ts = sorted(timestamps)
    if len(sorted_ts) > 1:
        deltas = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]
    else:
        deltas = [0.0]

    window_span = sorted_ts[-1] - sorted_ts[0] if len(sorted_ts) > 1 else 1.0
    if window_span <= 0:
        window_span = 1.0

    all_ports = src_ports + dst_ports
    all_ips   = src_ips + dst_ips

    feat = {
        # header length
        "network_header-length_max":           _safe_max(hdr_lengths),
        "network_header-length_std_deviation": _safe_std(hdr_lengths),

        # interval-packets = packets per second
        "network_interval-packets":            float(n) / window_span,

        # IP flags
        "network_ip-flags_avg":                float(np.mean(ip_flags_l)) if ip_flags_l else 0.0,
        "network_ip-flags_max":                _safe_max(ip_flags_l),
        "network_ip-flags_min":                _safe_min(ip_flags_l),

        # IP length
        "network_ip-length_avg":               float(np.mean(ip_lengths)) if ip_lengths else 0.0,
        "network_ip-length_max":               _safe_max(ip_lengths),
        "network_ip-length_std_deviation":     _safe_std(ip_lengths),

        # unique IPs
        "network_ips_all_count":               float(len(set(all_ips))),

        # MSS
        "network_mss_max":                     _safe_max(mss_l),
        "network_mss_std_deviation":           _safe_std(mss_l),

        # packet size
        "network_packet-size_avg":             float(np.mean(pkt_sizes)) if pkt_sizes else 0.0,
        "network_packet-size_min":             _safe_min(pkt_sizes),
        "network_packet-size_std_deviation":   _safe_std(pkt_sizes),

        # packet count
        "network_packets_all_count":           float(n),

        # payload length
        "network_payload-length_min":          _safe_min(payload_lens),

        # ports
        "network_ports_all_count":             float(len(set(all_ports))),
        "network_ports_dst_count":             float(len(set(dst_ports))),

        # protocols
        "network_protocols_all_count":         float(len(set(protos + src_ips + dst_ips))),
        "network_protocols_dst_count":         float(len(set(dst_ips))),
        "network_protocols_src_count":         float(len(set(src_ips))),

        # TCP flags individual counts
        "network_tcp-flags-ack_count":         float(sum(1 for f in tcp_flags_l if f & FLAG_ACK)),
        "network_tcp-flags-fin_count":         float(sum(1 for f in tcp_flags_l if f & FLAG_FIN)),
        "network_tcp-flags-rst_count":         float(sum(1 for f in tcp_flags_l if f & FLAG_RST)),
        "network_tcp-flags-syn_count":         float(sum(1 for f in tcp_flags_l if f & FLAG_SYN)),

        # TCP flags numeric stats
        "network_tcp-flags_avg":               float(np.mean(tcp_flags_l)) if tcp_flags_l else 0.0,
        "network_tcp-flags_max":               _safe_max(tcp_flags_l),

        # time delta
        "network_time-delta_avg":              float(np.mean(deltas)),
        "network_time-delta_max":              float(max(deltas)),
        "network_time-delta_min":              float(min(deltas)),
        "network_time-delta_std_deviation":    _safe_std(deltas),

        # TTL
        "network_ttl_avg":                     float(np.mean(ttls)) if ttls else 0.0,
        "network_ttl_max":                     _safe_max(ttls),
        "network_ttl_min":                     _safe_min(ttls),

        # Window size
        "network_window-size_max":             _safe_max(win_sizes),
        "network_window-size_min":             _safe_min(win_sizes),
    }
    return feat

def feat_dict_to_vector(feat_dict):
    """Return numpy array aligned to FEATURES list, NaN→0."""
    vec = np.array([feat_dict.get(f, 0.0) for f in FEATURES], dtype=np.float32)
    vec = np.nan_to_num(vec, nan=0.0, posinf=0.0, neginf=0.0)
    return vec

# ── Inference ──────────────────────────────────────────────────────────────

def run_inference(pkts_window, qt, model, thresh, label):
    if len(pkts_window) < 2:
        return False, 0.0
    feat_dict = extract_features(pkts_window)
    vec       = feat_dict_to_vector(feat_dict).reshape(1, -1)
    vec_t     = qt.transform(vec).astype(np.float32)
    recon     = model.predict(vec_t, verbose=0)
    mse       = float(np.mean((vec_t - recon) ** 2))
    anomaly   = mse > thresh
    return anomaly, mse

# ── Packet callback ────────────────────────────────────────────────────────

def packet_callback(pkt):
    if not pkt.haslayer(IP):
        return
    ip   = pkt[IP]
    now  = time.time()

    # Header length: IP header size in bytes
    hdr_len     = int(ip.ihl) * 4 if ip.ihl else 20

    # Payload length: total - header
    ip_len      = int(ip.len) if ip.len else len(pkt)
    payload_len = max(0, ip_len - hdr_len)

    # Packet size: full frame size
    pkt_size    = len(pkt)

    # Protocol number
    proto       = int(ip.proto)

    # IP flags (numeric: DF=2, MF=1, etc.)
    try:
        ip_flags = int(ip.flags)
    except Exception:
        ip_flags = 0

    # TTL
    ttl = int(ip.ttl) if ip.ttl is not None else None

    src_ip   = str(ip.src)
    dst_ip   = str(ip.dst)
    src_port = None
    dst_port = None
    tcp_flags = None
    win_size  = None
    mss       = None

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port  = int(tcp.sport)
        dst_port  = int(tcp.dport)
        tcp_flags = int(tcp.flags)
        win_size  = int(tcp.window)
        # Extract MSS from TCP options
        for opt_name, opt_val in (tcp.options or []):
            if opt_name == "MSS":
                try:
                    mss = int(opt_val)
                except Exception:
                    pass
    elif pkt.haslayer(UDP):
        udp      = pkt[UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    elif pkt.haslayer(ICMP):
        src_port = 0
        dst_port = int(pkt[ICMP].type)

    entry = {
        "ts":          now,
        "ip_len":      ip_len,
        "hdr_len":     hdr_len,
        "payload_len": payload_len,
        "pkt_size":    pkt_size,
        "proto":       proto,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "ttl":         ttl,
        "ip_flags":    ip_flags,
        "mss":         mss,
        "tcp_flags":   tcp_flags,
        "win_size":    win_size,
    }

    with _lock:
        _pkts.append(entry)

# ── Window evaluation loop ─────────────────────────────────────────────────

_alert_count = 0
_total_windows = 0

# Calibration state
_calibrating = CALIBRATE
_calib_mse5  = []
_calib_mse10 = []


def _push_to_gadm(payload):
    """Fire-and-forget POST to the cloud GADM sink. Never blocks alerting."""
    if not GADM_URL:
        return
    try:
        import json as _json, urllib.request as _u
        req = _u.Request(GADM_URL,
                         data=_json.dumps(payload).encode("utf-8"),
                         headers={"Content-Type": "application/json"},
                         method="POST")
        _u.urlopen(req, timeout=1.0).read()
    except Exception:
        pass  # cloud being down must never stall the edge detector

def _finish_calibration():
    """Compute new thresholds from collected normal-traffic MSE."""
    global thresh_5s, thresh_10s, _calibrating
    ds_5s, ds_10s = thresh_5s, thresh_10s   # DataSense originals (for the log)

    new_5s  = float(np.percentile(_calib_mse5,  CALIB_PERCENTILE)) * CALIB_MARGIN
    new_10s = float(np.percentile(_calib_mse10, CALIB_PERCENTILE)) * CALIB_MARGIN

    # Never go below the DataSense thresholds — only raise to fit the environment
    thresh_5s  = max(new_5s,  ds_5s)
    thresh_10s = max(new_10s, ds_10s)
    _calibrating = False

    print("=" * 78, flush=True)
    print("[CALIBRATION COMPLETE]", flush=True)
    print(f"  Observed normal MSE (5s):  mean={np.mean(_calib_mse5):.6f}  "
          f"p{CALIB_PERCENTILE:.0f}={np.percentile(_calib_mse5, CALIB_PERCENTILE):.6f}  "
          f"max={np.max(_calib_mse5):.6f}", flush=True)
    print(f"  Observed normal MSE (10s): mean={np.mean(_calib_mse10):.6f}  "
          f"p{CALIB_PERCENTILE:.0f}={np.percentile(_calib_mse10, CALIB_PERCENTILE):.6f}  "
          f"max={np.max(_calib_mse10):.6f}", flush=True)
    print(f"  DataSense thresholds:  5s={ds_5s:.6f}   10s={ds_10s:.6f}", flush=True)
    print(f"  NEW Docker thresholds: 5s={thresh_5s:.6f}   10s={thresh_10s:.6f}", flush=True)
    print(f"  (percentile={CALIB_PERCENTILE} × margin={CALIB_MARGIN})", flush=True)
    print("[monitor] Now actively detecting anomalies …", flush=True)
    print("=" * 78, flush=True)

def evaluation_loop():
    global _alert_count, _total_windows
    while True:
        time.sleep(WINDOW_5S)
        now = time.time()

        with _lock:
            # Prune packets older than 11s
            while _pkts and _pkts[0]["ts"] < now - 11.0:
                _pkts.popleft()
            pkts_5s  = [p for p in _pkts if p["ts"] >= now - WINDOW_5S]
            pkts_10s = [p for p in _pkts if p["ts"] >= now - WINDOW_10S]

        _total_windows += 1

        a5,  mse5  = run_inference(pkts_5s,  qt_5s,  model_5s,  thresh_5s,  "5s")
        a10, mse10 = run_inference(pkts_10s, qt_10s, model_10s, thresh_10s, "10s")

        # ── Calibration phase ───────────────────────────────────────────────
        if _calibrating:
            # Skip warm-up windows that aren't yet full (partial 10s window)
            if len(pkts_5s) < 5:
                print(f"[CALIB skip] warming up … pkts_5s={len(pkts_5s)}", flush=True)
                continue
            _calib_mse5.append(mse5)
            _calib_mse10.append(mse10)
            print(
                f"[CALIB {len(_calib_mse5):02d}/{CALIB_WINDOWS}] "
                f"pkts_5s={len(pkts_5s)} mse5={mse5:.6f} | "
                f"pkts_10s={len(pkts_10s)} mse10={mse10:.6f}",
                flush=True
            )
            if len(_calib_mse5) >= CALIB_WINDOWS:
                _finish_calibration()
            continue

        # ── Detection phase ─────────────────────────────────────────────────
        alert = a5 or a10

        if alert:
            _alert_count += 1
            print(
                f"[ALERT #{_alert_count}] "
                f"pkts_5s={len(pkts_5s)} mse5={mse5:.6f}(thr={thresh_5s:.6f}) a5={a5} | "
                f"pkts_10s={len(pkts_10s)} mse10={mse10:.6f}(thr={thresh_10s:.6f}) a10={a10}",
                flush=True
            )
            _push_to_gadm({
                "timestamp":   now,
                "alert_id":    _alert_count,
                "pkts_5s":     len(pkts_5s),  "mse5":  mse5,  "thresh_5s":  thresh_5s,  "a5":  bool(a5),
                "pkts_10s":    len(pkts_10s), "mse10": mse10, "thresh_10s": thresh_10s, "a10": bool(a10),
                "ensemble":    "OR",
                "source":      "edge_radm",
            })
        else:
            print(
                f"[OK    #{_total_windows:05d}] "
                f"pkts_5s={len(pkts_5s)} mse5={mse5:.6f} | "
                f"pkts_10s={len(pkts_10s)} mse10={mse10:.6f}",
                flush=True
            )

# ── Auto-detect interface ──────────────────────────────────────────────────

def detect_iface():
    import subprocess, re
    # Priority 1: br- interface with explicit route to the iiot subnet
    try:
        result = subprocess.run(["ip", "route", "show", SUBNET],
                                capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                iface = parts[parts.index("dev") + 1]
                print(f"[monitor] Found iiot_net route on: {iface}", flush=True)
                return iface
    except Exception:
        pass
    # Priority 2: any br- interface visible via ip link
    try:
        result = subprocess.run(["ip", "link", "show"],
                                capture_output=True, text=True, timeout=5)
        bridges = re.findall(r'\d+: (br-[a-f0-9]+):', result.stdout)
        if bridges:
            print(f"[monitor] Found bridge interface: {bridges[0]}", flush=True)
            return bridges[0]
    except Exception:
        pass
    # Priority 3: br- from scapy interface list
    from scapy.all import get_if_list
    for iface in get_if_list():
        if iface.startswith("br-"):
            print(f"[monitor] Found bridge via scapy: {iface}", flush=True)
            return iface
    print(f"[monitor] WARNING: falling back to eth0 — BPF filter will still restrict to {SUBNET}", flush=True)
    return "eth0"

# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    iface = IFACE or detect_iface()
    print(f"[monitor] Sniffing on interface: {iface}", flush=True)
    print(f"[monitor] Window sizes: {WINDOW_5S}s / {WINDOW_10S}s", flush=True)
    if CALIBRATE:
        print(f"[monitor] CALIBRATION MODE — observing {CALIB_WINDOWS} windows "
              f"(~{CALIB_WINDOWS * WINDOW_5S / 60:.1f} min) of normal traffic. "
              f"DO NOT attack during calibration.", flush=True)
    else:
        print(f"[monitor] OR ensemble — alert if mse5>{thresh_5s:.6f} OR mse10>{thresh_10s:.6f}", flush=True)
    print("[monitor] Waiting for packets …", flush=True)

    # Start evaluation thread
    t = threading.Thread(target=evaluation_loop, daemon=True)
    t.start()

    # Start packet capture (blocking)
    # BPF filter restricts to iiot_net subnet only — works even if iface is eth0
    bpf_subnet = SUBNET.replace("/24", "/24")  # passthrough for BPF "net" syntax
    sniff(
        iface=iface,
        filter=f"ip net {SUBNET}",
        prn=packet_callback,
        store=False,
    )
