FROM debian:bookworm-slim

# Matches DataSense's Raspbian (= Debian) bot OS choice.
# Carries the full attack toolbox so every attack class can be driven by C2.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-scapy \
    python3-paho-mqtt \
    hping3 \
    nmap \
    hydra \
    sqlmap \
    ettercap-text-only \
    dsniff \
    slowhttptest \
    mosquitto-clients \
    netcat-traditional \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    curl \
    perl \
    libnet-ssleay-perl \
    libwhisker2-perl \
    libio-socket-ssl-perl \
    libjson-perl \
    libxml-writer-perl \
    libtimedate-perl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nikto is no longer in Debian Bookworm main — install from upstream git.
# It is a pure-Perl tool, so a clone + symlink is enough.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Tiny default wordlists so 'brute' works out of the box without rockyou
RUN mkdir -p /wordlists && \
    printf "admin\nroot\nuser\nguest\noperator\n"                            > /wordlists/users.txt && \
    printf "admin\nadmin123\npassword\n123456\nroot\ntoor\nop2024\niot2024\nxc3511\nvizxv\n" \
                                                                              > /wordlists/pw.txt

COPY bot_agent.py /bot_agent.py
COPY attacks/ /attacks/
WORKDIR /attacks

CMD ["python3", "/bot_agent.py"]
