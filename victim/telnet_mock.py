"""
Lightweight Telnet server for the IIoT victim — replaces xinetd+telnetd which
is unreliable inside Docker without a real init system. Implements just enough
of RFC 854 / 1184 to make hydra and Mirai-style brute-forcers happy.

Valid credentials (deliberately weak, matches the bot wordlists):
    admin / admin123
    root  / toor
    user  / user

Everything else is rejected with "Login incorrect", just like a real telnetd.
"""
import socket
import threading

PORT = 23
VALID = {
    "admin": "admin123",
    "root":  "toor",
    "user":  "user",
}


def recv_line(sock, max_bytes=128):
    """Read until \\n or \\r, stripping telnet option negotiation (IAC bytes)."""
    buf = b""
    while len(buf) < max_bytes:
        try:
            c = sock.recv(1)
        except Exception:
            return ""
        if not c:
            return ""
        # Telnet IAC (0xFF) option negotiation: skip the next 2 bytes
        if c == b"\xff":
            try:
                sock.recv(2)
            except Exception:
                pass
            continue
        if c in (b"\n", b"\r"):
            if c == b"\r":
                # consume optional \n that follows
                try:
                    nxt = sock.recv(1)
                    if nxt and nxt != b"\n":
                        buf += nxt
                except Exception:
                    pass
            break
        buf += c
    return buf.decode("utf-8", errors="ignore").strip()


def handle(client, addr):
    try:
        # Basic telnet option negotiation — DO/DONT/WILL/WONT noise
        # IAC WILL ECHO + IAC WILL SUPPRESS-GO-AHEAD
        client.sendall(b"\xff\xfb\x01\xff\xfb\x03")
        client.sendall(b"\r\nIIoT Edge Device v3.1.4 (Debian)\r\n\r\n")
        client.sendall(b"login: ")
        user = recv_line(client, 64)
        client.sendall(b"Password: ")
        pwd  = recv_line(client, 64)

        if VALID.get(user) == pwd:
            client.sendall(
                b"\r\nWelcome to the IIoT Edge Device.\r\n"
                b"Last login: Tue Jan  7 14:32:17 2026 from 192.168.1.50\r\n"
                b"# "
            )
            # Keep the session alive briefly so hydra can confirm success
            try:
                client.recv(256)
            except Exception:
                pass
        else:
            client.sendall(b"\r\nLogin incorrect\r\n")
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(64)
    print(f"[telnet-mock] listening on 0.0.0.0:{PORT}", flush=True)
    while True:
        try:
            client, addr = s.accept()
        except Exception:
            continue
        threading.Thread(target=handle, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
