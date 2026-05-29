import os, time, random, json
from flask import Flask, jsonify, request, abort

PLUG_ID = os.environ.get("PLUG_ID", "plug_01")
app = Flask(__name__)

state = {
    "plug_id":       PLUG_ID,
    "relay":         "on",
    "power_w":       round(random.uniform(40, 200), 2),
    "voltage_v":     230.0,
    "current_a":     round(random.uniform(0.2, 0.9), 3),
    "energy_kwh":    round(random.uniform(0.1, 5.0), 4),
    "uptime_s":      0,
    "fw_version":    "1.4.2",
    "ssid":          "IIoT_Lab_Network",
    "rssi_dbm":      -58,
}
start_time = time.time()

def update_live():
    state["uptime_s"] = int(time.time() - start_time)
    if state["relay"] == "on":
        state["power_w"]   = round(random.uniform(40, 200), 2)
        state["current_a"] = round(state["power_w"] / state["voltage_v"], 3)
        state["energy_kwh"] = round(state["energy_kwh"] + state["power_w"] / 3600000, 6)
    else:
        state["power_w"]   = 0.0
        state["current_a"] = 0.0

@app.route("/")
def index():
    return f"""
    <html><body>
    <h2>Smart Plug — {PLUG_ID}</h2>
    <p>Status: <a href="/status">/status</a></p>
    <p>Control: POST /relay  body: {{"state":"on"|"off"}}</p>
    <p>Energy:  <a href="/energy">/energy</a></p>
    </body></html>
    """

@app.route("/status")
def status():
    update_live()
    return jsonify(state)

@app.route("/relay", methods=["GET", "POST"])
def relay():
    update_live()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        new_state = data.get("state", "").lower()
        if new_state not in ("on", "off"):
            abort(400)
        state["relay"] = new_state
        print(f"[{PLUG_ID}] Relay → {new_state}", flush=True)
    return jsonify({"relay": state["relay"], "plug_id": PLUG_ID})

@app.route("/energy")
def energy():
    update_live()
    return jsonify({
        "plug_id":    PLUG_ID,
        "energy_kwh": state["energy_kwh"],
        "power_w":    state["power_w"],
        "uptime_s":   state["uptime_s"],
    })

# Tuya-style emulation endpoint
@app.route("/v1.0/devices/<dev_id>/commands", methods=["POST"])
def tuya_command(dev_id):
    data = request.get_json(silent=True) or {}
    cmds = data.get("commands", [])
    for cmd in cmds:
        if cmd.get("code") == "switch_1":
            state["relay"] = "on" if cmd.get("value") else "off"
    update_live()
    return jsonify({"result": True, "success": True})

def heartbeat():
    while True:
        time.sleep(4)
        update_live()
        print(f"[{PLUG_ID}] relay={state['relay']}  power={state['power_w']}W  "
              f"current={state['current_a']}A  energy={state['energy_kwh']}kWh", flush=True)

if __name__ == "__main__":
    import threading
    print(f"[{PLUG_ID}] Smart plug service started on :8080", flush=True)
    threading.Thread(target=heartbeat, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, threaded=True)
