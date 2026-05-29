#!/bin/bash
set -e

SUBNET="${SUBNET:-192.168.1.0/24}"
DURATION="${DURATION:-300}"      # seconds per pcap file (rotation period)
MAX_FILES="${MAX_FILES:-10}"     # ring-buffer size (oldest deleted after this)
SNAPLEN="${SNAPLEN:-0}"          # 0 = full packet

# Find the bridge interface serving the IIoT subnet (same logic as monitor)
IFACE=$(ip route show "$SUBNET" 2>/dev/null | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
if [ -z "$IFACE" ]; then
    IFACE=$(ip link show | grep -oE 'br-[a-f0-9]+' | head -1)
fi
if [ -z "$IFACE" ]; then
    IFACE="eth0"
fi

mkdir -p /captures
echo "[network_dump] iface=$IFACE  filter='net $SUBNET'"
echo "[network_dump] rotation: DURATION=${DURATION}s  MAX_FILES=${MAX_FILES}  SNAPLEN=${SNAPLEN}"
echo "[network_dump] writing to /captures/iiot_<ts>.pcap"

exec tcpdump -i "$IFACE" -nn -s "$SNAPLEN" \
    -G "$DURATION" -W "$MAX_FILES" \
    -w "/captures/iiot_%Y%m%d_%H%M%S.pcap" \
    "net $SUBNET"
