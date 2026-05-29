FROM kalilinux/kali-rolling

# Mirai-style C2: runs CnC server + has the full attacker's toolbox.
# Tools chosen to match DataSense's attack matrix (Table 4 of their paper).
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-scapy \
    hping3 \
    nmap \
    fping \
    hydra \
    sqlmap \
    nikto \
    ettercap-text-only \
    dsniff \
    slowhttptest \
    mosquitto-clients \
    netcat-traditional \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    procps \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY c2.py /c2.py
COPY attacks/ /attacks/
WORKDIR /attacks

CMD ["python3", "/c2.py"]
