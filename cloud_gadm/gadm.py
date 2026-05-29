"""
GADM — Global Anomaly Detection Module (cloud layer).
Receives alerts from edge RADM monitor(s), persists them, and forwards
to the cloud Logger (ELK-equivalent). Provides a dashboard / API.
"""
import os, time, json, sqlite3, threading
from collections import deque
from flask import Flask, request, jsonify
import requests

CLOUD_LOGGER = os.environ.get("CLOUD_LOGGER", "http://10.0.0.20:5001")
DB = "/app/gadm.db"
app = Flask(__name__)
_recent = deque(maxlen=200)
_lock = threading.Lock()


def db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at REAL,
        edge_ts REAL,
        source TEXT,
        alert_id INTEGER,
        pkts_5s INTEGER, mse5 REAL, thresh_5s REAL, a5 INTEGER,
        pkts_10s INTEGER, mse10 REAL, thresh_10s REAL, a10 INTEGER,
        raw TEXT)""")
    return c


def forward_to_logger(payload):
    try:
        requests.post(f"{CLOUD_LOGGER}/ingest",
                      json={"source": "gadm", "kind": "alert", "data": payload},
                      timeout=1.0)
    except Exception:
        pass


@app.route("/alert", methods=["POST"])
def alert():
    p = request.get_json(silent=True) or {}
    rec_ts = time.time()
    c = db()
    c.execute("""INSERT INTO alerts (received_at, edge_ts, source, alert_id,
        pkts_5s, mse5, thresh_5s, a5, pkts_10s, mse10, thresh_10s, a10, raw)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rec_ts, p.get("timestamp"), p.get("source", "?"), p.get("alert_id"),
         p.get("pkts_5s"), p.get("mse5"), p.get("thresh_5s"), int(p.get("a5", False)),
         p.get("pkts_10s"), p.get("mse10"), p.get("thresh_10s"), int(p.get("a10", False)),
         json.dumps(p)))
    c.commit(); c.close()
    with _lock:
        _recent.append({"received_at": rec_ts, **p})
    forward_to_logger(p)
    return jsonify({"status": "received", "alert_id": p.get("alert_id")})


@app.route("/alerts")
def alerts_list():
    limit = int(request.args.get("limit", 50))
    c = db()
    rows = c.execute("""SELECT received_at, edge_ts, source, alert_id,
        pkts_5s, mse5, pkts_10s, mse10, a5, a10
        FROM alerts ORDER BY id DESC LIMIT ?""", (limit,)).fetchall()
    c.close()
    return jsonify([{
        "received_at": r[0], "edge_ts": r[1], "source": r[2], "alert_id": r[3],
        "pkts_5s": r[4], "mse5": r[5], "pkts_10s": r[6], "mse10": r[7],
        "a5": bool(r[8]), "a10": bool(r[9])} for r in rows])


@app.route("/")
def index():
    c = db()
    n = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    last = c.execute("SELECT received_at, source, alert_id FROM alerts "
                     "ORDER BY id DESC LIMIT 1").fetchone()
    c.close()
    return jsonify({"service": "GADM (Global Anomaly Detection Module)",
                    "total_alerts": n,
                    "last_alert": last,
                    "cloud_logger": CLOUD_LOGGER,
                    "endpoints": ["/alert (POST)", "/alerts?limit=N"]})


if __name__ == "__main__":
    print(f"[GADM] online on :5000  forwarding to {CLOUD_LOGGER}", flush=True)
    app.run(host="0.0.0.0", port=5000, threaded=True)
