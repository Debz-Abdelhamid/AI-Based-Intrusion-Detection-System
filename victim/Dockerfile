FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    python3 \
    python3-flask \
    curl \
    iproute2 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Weak credentials (for simulation only)
RUN useradd -m -s /bin/bash admin && echo "admin:admin123" | chpasswd
RUN useradd -m -s /bin/bash iotuser && echo "iotuser:password" | chpasswd
RUN echo "root:toor" | chpasswd

# SSH config — allow root + password auth
RUN mkdir -p /var/run/sshd
COPY sshd_config /etc/ssh/sshd_config

# Vulnerable management portal
COPY portal.py /app/portal.py

# Lightweight in-container Telnet server (replaces xinetd+telnetd, which is
# unreliable in Docker without a real init system)
COPY telnet_mock.py /app/telnet_mock.py

# Generate SSH host keys
RUN ssh-keygen -A

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80 22 23
CMD ["/start.sh"]
