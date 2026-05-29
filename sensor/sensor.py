import os, time, json, random, math
import paho.mqtt.client as mqtt

SENSOR_TYPE     = os.environ.get("SENSOR_TYPE", "weather")
SENSOR_ID       = os.environ.get("SENSOR_ID", "sensor_01")
MQTT_BROKER     = os.environ.get("MQTT_BROKER", "192.168.1.193")
PUBLISH_INTERVAL = float(os.environ.get("PUBLISH_INTERVAL", "2"))

TOPIC = f"iiot/{SENSOR_TYPE}/{SENSOR_ID}"

def make_payload():
    t = time.time()
    if SENSOR_TYPE == "weather":
        return {
            "temperature": round(20 + 10 * math.sin(t / 60) + random.gauss(0, 0.3), 2),
            "humidity":    round(55 + 15 * math.cos(t / 90) + random.gauss(0, 0.5), 2),
            "pressure":    round(1013 + random.gauss(0, 0.8), 2),
        }
    elif SENSOR_TYPE == "water":
        return {
            "flow_rate": round(max(0, 2.5 + random.gauss(0, 0.1)), 3),
            "level":     round(max(0, min(100, 60 + random.gauss(0, 1))), 2),
            "ph":        round(max(6, min(9, 7.1 + random.gauss(0, 0.05))), 2),
        }
    elif SENSOR_TYPE == "motion":
        return {
            "detected":   random.random() < 0.05,
            "zone":       random.choice(["zone_A", "zone_B", "zone_C"]),
            "confidence": round(random.uniform(0.7, 1.0), 3),
        }
    elif SENSOR_TYPE == "gas":
        return {
            "co2_ppm":  round(400 + random.gauss(0, 10), 1),
            "co_ppm":   round(max(0, 0.5 + random.gauss(0, 0.05)), 3),
            "ch4_ppm":  round(max(0, 1.8 + random.gauss(0, 0.1)), 3),
        }
    elif SENSOR_TYPE == "rfid":
        tags = ["TAG_A1B2", "TAG_C3D4", "TAG_E5F6", "TAG_G7H8", None]
        tag = random.choices(tags, weights=[10, 8, 5, 3, 74])[0]
        return {
            "tag_id":  tag,
            "rssi_db": round(random.uniform(-70, -30), 1) if tag else None,
            "read_ok": tag is not None,
        }
    elif SENSOR_TYPE == "flame":
        flame = random.random() < 0.01
        return {
            "flame_detected": flame,
            "ir_intensity":   round(random.uniform(0.8, 1.0) if flame else random.uniform(0.0, 0.1), 4),
            "temperature":    round(800 + random.gauss(0, 20) if flame else 22 + random.gauss(0, 0.5), 2),
        }
    elif SENSOR_TYPE == "soil":
        return {
            "moisture":    round(max(0, min(100, 45 + 8 * math.sin(t / 120) + random.gauss(0, 1.5))), 2),
            "temperature": round(18 + 3 * math.sin(t / 300) + random.gauss(0, 0.2), 2),
            "ph":          round(max(5, min(8.5, 6.8 + random.gauss(0, 0.05))), 2),
        }
    elif SENSOR_TYPE == "sound":
        burst = random.random() < 0.08
        return {
            "db":           round(40 + (random.uniform(30, 50) if burst else random.gauss(0, 2)), 1),
            "frequency_hz": round(random.choice([120, 250, 440, 880, 1500]) + random.gauss(0, 8), 1),
            "detected":     burst,
        }
    return {}

client = mqtt.Client(client_id=SENSOR_ID)

def on_connect(c, userdata, flags, rc):
    print(f"[{SENSOR_ID}] Connected to broker (rc={rc})", flush=True)

client.on_connect = on_connect

while True:
    try:
        client.connect(MQTT_BROKER, 1883, 60)
        break
    except Exception as e:
        print(f"[{SENSOR_ID}] Waiting for broker: {e}", flush=True)
        time.sleep(3)

client.loop_start()

print(f"[{SENSOR_ID}] Publishing to {TOPIC} every {PUBLISH_INTERVAL}s", flush=True)
while True:
    payload = make_payload()
    payload["sensor_id"] = SENSOR_ID
    payload["timestamp"] = time.time()
    client.publish(TOPIC, json.dumps(payload), qos=0)
    reading = {k: v for k, v in payload.items() if k not in ("sensor_id", "timestamp")}
    print(f"[{SENSOR_ID}] -> {TOPIC}  {reading}", flush=True)
    time.sleep(PUBLISH_INTERVAL)
