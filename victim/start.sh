#!/bin/bash
set -e

# SSH server
mkdir -p /var/run/sshd
service ssh start

# Lightweight in-container telnet server (port 23)
python3 /app/telnet_mock.py &

echo "[victim] Services started:"
echo "  HTTP portal -> :80  (vulnerable: SQLi / XSS / path traversal)"
echo "  SSH         -> :22  (users: root/toor, admin/admin123, iotuser/password)"
echo "  Telnet      -> :23  (mock: admin/admin123, root/toor, user/user)"

# Flask portal runs in foreground (keeps container alive)
exec python3 /app/portal.py
