"""
IIoT Edge Device — Management Portal (intentionally vulnerable, for research).
Simulates a real IIoT device admin panel backed by a SQLite database.
Contains deliberate SQL injection, reflected XSS, and path traversal flaws
so attacks have genuine, observable impact.
"""
import sqlite3
import os
import secrets
from flask import Flask, request, Response, jsonify, make_response

DB = "/app/iiot.db"
app = Flask(__name__)


# ── Deliberately weak "admin session" so XSS demos exfil real cookies ──
# httponly=False on purpose: document.cookie must be readable from JS for
# the stored-XSS lab exercise to actually demonstrate session theft.
ADMIN_SESSION_TOKEN = "admin-" + secrets.token_hex(8)
ADMIN_AUTH_BEARER   = ("Bearer.eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
                       "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW5pc3RyYXRvciJ9."
                       + secrets.token_hex(16))


def _with_admin_cookies(resp):
    """Attach a realistic admin session + bearer + role to any response."""
    resp.set_cookie("session",    ADMIN_SESSION_TOKEN, httponly=False, samesite="Lax")
    resp.set_cookie("auth_token", ADMIN_AUTH_BEARER,   httponly=False, samesite="Lax")
    resp.set_cookie("role",       "administrator",     httponly=False, samesite="Lax")
    return resp


def init_db():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("DROP TABLE IF EXISTS sensors")
    c.execute("""CREATE TABLE sensors (
        id INTEGER PRIMARY KEY,
        sensor_id TEXT, name TEXT, location TEXT,
        threshold REAL, publish_interval INTEGER, enabled INTEGER)""")
    c.executemany(
        "INSERT INTO sensors VALUES (?,?,?,?,?,?,?)",
        [
            (1, "weather_01", "Weather Station", "Rooftop",     40.0, 2, 1),
            (2, "water_01",   "Water Flow",      "Pump Room",   80.0, 3, 1),
            (3, "motion_01",  "Motion Sensor",   "Entrance",     1.0, 1, 1),
            (4, "gas_01",     "Gas Detector",    "Boiler Room", 500.0, 5, 1),
            (5, "rfid_01",    "RFID Reader",     "Main Gate",    0.0, 4, 1),
            (6, "flame_01",   "Flame Sensor",    "Generator",    0.5, 2, 1),
        ],
    )
    # A juicy credentials table — the classic SQLi exfiltration target
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    c.executemany(
        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
        [("admin", "admin123", "administrator"), ("operator", "op2024", "operator")],
    )
    con.commit()
    con.close()


@app.route("/")
def index():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    sensors = con.execute("SELECT * FROM sensors").fetchall()
    con.close()
    rows = "".join(
        f"<tr><td>{s['id']}</td><td>{s['sensor_id']}</td><td>{s['name']}</td>"
        f"<td>{s['location']}</td><td>{s['threshold']}</td>"
        f"<td>{s['publish_interval']}s</td><td>{'ON' if s['enabled'] else 'OFF'}</td></tr>"
        for s in sensors
    )
    html = f"""<html><head><title>IIoT Edge Device Portal</title></head>
    <body style="font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:30px">
    <h1 style="color:#00d4ff">&#x1F4E1; IIoT Edge Device — Sensor Management</h1>
    <p style="color:#888">Logged in as <b style="color:#00ff88">admin</b> (administrator)</p>
    <table border=1 cellpadding=6 style="border-collapse:collapse">
    <tr style="background:#0f3460"><th>ID</th><th>Sensor</th><th>Name</th>
    <th>Location</th><th>Threshold</th><th>Interval</th><th>Status</th></tr>{rows}
    </table>
    <h3>API endpoints</h3>
    <ul>
      <li><a href="/api/sensors?id=1">/api/sensors?id=1</a> — view sensor config</li>
      <li><a href="/api/update?id=1&threshold=50">/api/update?id=1&threshold=50</a> — change a threshold</li>
      <li><a href="/search?q=test">/search?q=test</a> — search</li>
      <li><a href="/files?name=portal.py">/files?name=portal.py</a> — download device file</li>
    </ul></body></html>"""
    return _with_admin_cookies(make_response(html))


# ── VULNERABLE: SQL injection via string concatenation ───────────────────────
@app.route("/api/sensors")
def api_sensors():
    sid = request.args.get("id", "1")
    query = ("SELECT id, sensor_id, name, location, threshold, "
             f"publish_interval, enabled FROM sensors WHERE id = {sid}")
    con = sqlite3.connect(DB)
    try:
        rows = con.execute(query).fetchall()
    except Exception as e:
        con.close()
        return jsonify({"query": query, "error": str(e)}), 500
    con.close()
    return jsonify({"query": query, "results": rows})


# ── VULNERABLE: SQL injection in UPDATE — REAL parameter modification ────────
@app.route("/api/update")
def api_update():
    sid = request.args.get("id", "1")
    threshold = request.args.get("threshold", "0")
    query = f"UPDATE sensors SET threshold = {threshold} WHERE id = {sid}"
    con = sqlite3.connect(DB)
    try:
        con.executescript(query)
        con.commit()
    except Exception as e:
        con.close()
        return jsonify({"query": query, "error": str(e)}), 500
    rows = con.execute("SELECT id, sensor_id, threshold, enabled FROM sensors").fetchall()
    con.close()
    return jsonify({"query": query, "status": "updated", "sensors": rows})


# ── VULNERABLE: reflected XSS (input echoed without escaping) ────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    return (f"<html><body style='font-family:sans-serif'>"
            f"<h2>Search results for: {q}</h2><p>No matching records.</p></body></html>")


# ── VULNERABLE: path traversal (no sanitization on file name) ────────────────
@app.route("/files")
def files():
    name = request.args.get("name", "portal.py")
    # Resolve relative names against the app dir, but do NOT sanitize traversal
    path = name if name.startswith("/") else os.path.join("/app", name)
    try:
        with open(path) as f:
            return Response(f.read(), mimetype="text/plain")
    except Exception as e:
        return Response(f"Error reading {path}: {e}", mimetype="text/plain", status=404)


@app.route("/api/status")
def status():
    return jsonify({"device": "iiot-edge-device", "status": "running", "uptime": 86400})


if __name__ == "__main__":
    init_db()
    print("[portal] IIoT management portal on :80 — SQLi/XSS/traversal demo endpoints live", flush=True)
    app.run(host="0.0.0.0", port=80, threaded=True)
