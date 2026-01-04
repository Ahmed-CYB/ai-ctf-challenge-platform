# Base Kali Image for PWN/Binary Exploitation Challenges
# Pre-installed tools: gdb, pwntools, ghidra, radare2
# Image size: ~1.2GB (ghidra is large)

FROM kalilinux/kali-rolling

LABEL maintainer="CTF Platform"
LABEL category="pwn-reverse-engineering"
LABEL description="Lightweight Kali with binary exploitation tools"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install base desktop environment
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    kali-desktop-xfce \
    xfce4 \
    xfce4-terminal \
    tigervnc-standalone-server \
    tigervnc-common \
    dbus-x11 \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install PWN/RE tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gdb \
    gdb-multiarch \
    gdbserver \
    ghidra \
    radare2 \
    binutils \
    binwalk \
    ltrace \
    strace \
    python3 \
    python3-pip \
    python3-pwntools \
    git \
    vim \
    nano \
    curl \
    wget \
    netcat-traditional \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install pwndbg (enhanced gdb)
RUN cd /opt && \
    git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh

# Setup VNC
RUN mkdir -p /root/.vnc && \
    echo "password" | vncpasswd -f > /root/.vnc/passwd && \
    chmod 600 /root/.vnc/passwd

# Create VNC startup script
RUN echo '#!/bin/bash\n\
xrdb $HOME/.Xresources\n\
startxfce4 &' > /root/.vnc/xstartup && \
    chmod +x /root/.vnc/xstartup

# Setup supervisor
RUN mkdir -p /var/log/supervisor && \
    echo '[supervisord]\n\
nodaemon=true\n\
logfile=/var/log/supervisor/supervisord.log\n\
pidfile=/var/run/supervisord.pid\n\
\n\
[program:vnc]\n\
command=/usr/bin/vncserver :1 -geometry 1280x720 -depth 24 -localhost no\n\
autostart=true\n\
autorestart=true\n\
stdout_logfile=/var/log/supervisor/vnc.log\n\
stderr_logfile=/var/log/supervisor/vnc_err.log' > /etc/supervisor/conf.d/supervisord.conf

# Expose VNC port
EXPOSE 5901

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
