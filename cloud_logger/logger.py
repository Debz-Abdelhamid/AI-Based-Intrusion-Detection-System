"""
Cloud Logger — DataSense ELK-equivalent.
Lightweight Flask + SQLite store for alerts and operational logs.
"""
import sqlite3, time, json
from flask import Flask, request, jsonify

DB = "/app/cloud_logger.db"
app = Flask(__name__)


def db():
    c = sqlite3.connect(DB)
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at REAL,
        source TEXT,
        kind TEXT,
        payload TEXT)""")
    return c


@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json(silent=True) or {}
    c = db()
    c.execute("INSERT INTO events (received_at, source, kind, payload) VALUES (?,?,?,?)",
              (time.time(), data.get("source", "?"), data.get("kind", "event"),
               json.dumps(data)))
    c.commit(); c.close()
    return jsonify({"status": "stored"})


@app.route("/events")
def events():
    limit = int(request.args.get("limit", 50))
    c = db()
    rows = c.execute("SELECT id, received_at, source, kind, payload FROM events "
                     "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    c.close()
    return jsonify([
        {"id": r[0], "received_at": r[1], "source": r[2], "kind": r[3],
         "payload": json.loads(r[4])} for r in rows
    ])


@app.route("/")
def index():
    c = db()
    n = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    alerts = c.execute("SELECT COUNT(*) FROM events WHERE kind='alert'").fetchone()[0]
    c.close()
    return jsonify({"service": "cloud_logger", "total_events": n,
                    "alerts": alerts, "endpoints": ["/ingest", "/events?limit=N"]})


if __name__ == "__main__":
    print("[cloud_logger] Elasticsearch-equivalent log store on :5001", flush=True)
    app.run(host="0.0.0.0", port=5001, threaded=True)
