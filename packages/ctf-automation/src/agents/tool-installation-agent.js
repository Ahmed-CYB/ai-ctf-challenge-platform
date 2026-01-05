/**
 * Tool Installation Agent
 * Intelligently installs tools based on challenge category and requirements
 * Reads base-images README.md to understand tool requirements
 */

import Anthropic from '@anthropic-ai/sdk';
import fs from 'fs/promises';
import path from 'path';
import { getToolInstallationMethod, learnMultipleTools } from '../tool-learning-service.js';
import {
  getPackageAliases,
  getServicePackageName,
  getAttackTools,
  getInvalidServiceNames,
  getBaseTools,
  getToolsByCategory,
  getToolPackageMapping,
  clearPackageMappingCache
} from '../package-mapping-db-manager.js';

/**
 * Resolve package name to correct package (using database)
 */
async function resolvePackageName(packageName, osType = 'all') {
  const normalized = packageName.toLowerCase().trim();
  const aliases = await getPackageAliases(osType);
  return aliases[normalized] || packageName;
}

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

/**
 * Generate Dockerfile from learned installation methods
 */
async function generateDockerfileFromLearnedMethods({ category, aptPackages, pipPackages, gemPackages, gitInstalls = [] }) {
  // Load base tools from database
  const baseTools = await getBaseTools('apt-get');
  const allAptPackages = [...new Set([...baseTools, ...aptPackages])];

  let dockerfile = `FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# CRITICAL: Always update package lists before installing
# Update and install base tools + SSH
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    ${allAptPackages.join(' \\\n    ')} \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

`;

  // Add pip packages if any
  if (pipPackages.length > 0) {
    dockerfile += `# Install Python packages via pip
RUN pip3 install --break-system-packages \\
    ${pipPackages.join(' \\\n    ')}

`;
  }

  // Add gem packages if any
  if (gemPackages.length > 0) {
    dockerfile += `# Install Ruby gems
RUN gem install ${gemPackages.join(' ')}

`;
  }

  // Add git-based installations
  if (gitInstalls.length > 0) {
    dockerfile += `# Install tools from GitHub\n`;
    for (const gitCmd of gitInstalls) {
      dockerfile += `RUN ${gitCmd}\n`;
    }
    dockerfile += '\n';
  }

  // SSH configuration
  dockerfile += `# Configure SSH server
RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ✅ FIX: Replace nmap wrapper to always use unprivileged mode
# The default /usr/bin/nmap wrapper tries to use --privileged which requires capabilities
# We replace it with a wrapper that always uses --unprivileged mode
RUN mv /usr/bin/nmap /usr/bin/nmap.original 2>/dev/null || true && \\
    echo '#!/bin/bash' > /usr/bin/nmap && \\
    echo '# Nmap wrapper - always use unprivileged mode (no CAP_NET_RAW required)' >> /usr/bin/nmap && \\
    echo 'exec /usr/lib/nmap/nmap --unprivileged "$@"' >> /usr/bin/nmap && \\
    chmod +x /usr/bin/nmap

# 🔒 SECURITY: Install iptables and iproute2 for network isolation
RUN apt-get update && \\
    apt-get install -y --no-install-recommends iptables iproute2 && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 🔒 SECURITY: Create network isolation script
# IMPORTANT: Allow Guacamole network (172.22.0.0/16) for SSH access - DO NOT BLOCK
# CRITICAL: Script must not fail container startup if network isolation fails
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo 'set +e' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Flush existing rules (ignore errors)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F OUTPUT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F INPUT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F FORWARD 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Set default policies (allow by default, then restrict)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P INPUT ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P FORWARD ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P OUTPUT ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow loopback' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow established and related connections' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Get gateway IP - try iproute2 first, fallback to hostname -I' >> /usr/local/bin/secure-network.sh && \\
    echo 'GATEWAY=""' >> /usr/local/bin/secure-network.sh && \\
    echo 'if command -v ip >/dev/null 2>&1; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  GATEWAY=$(ip route | grep default | awk '"'"'{print $3}'"'"' | head -1)' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  # Fallback: extract from interface IP (assume .1 is gateway)' >> /usr/local/bin/secure-network.sh && \\
    echo '  MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo '  if [ ! -z "$MY_IP" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '    GATEWAY=$(echo $MY_IP | cut -d. -f1-3).1' >> /usr/local/bin/secure-network.sh && \\
    echo '  fi' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block gateway access (except DNS on port 53) - only if gateway is valid' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$GATEWAY" ] && [ "$GATEWAY" != ".1" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "🔒 Blocking gateway access: $GATEWAY (except DNS)"' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'else' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "⚠️  Could not determine gateway, skipping gateway blocking"' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block infrastructure networks (OUTPUT only - allow INPUT for SSH from Guacamole)' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "🔒 Blocking infrastructure networks (OUTPUT only)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.20.0.0/16 -j DROP 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.21.0.0/16 -j DROP 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '# NOTE: 172.22.0.0/16 is Guacamole network - DO NOT BLOCK (needed for SSH access)' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow SSH from any source (for Guacamole access)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow all traffic within challenge network' >> /usr/local/bin/secure-network.sh && \\
    echo 'MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$MY_IP" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  NETWORK=$(echo $MY_IP | cut -d. -f1-3).0/24' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $NETWORK -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A INPUT -s $NETWORK -j ACCEPT 2>/dev/null || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "✅ Network isolation rules applied (Guacamole SSH access allowed)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'exit 0' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

# Create challenge directory
RUN mkdir -p /challenge && chmod 755 /challenge

EXPOSE 22

# 🔒 SECURITY: Apply network isolation on container start
RUN echo '#!/bin/bash' > /start-secure.sh && \\
    echo 'set +e' >> /start-secure.sh && \\
    echo '' >> /start-secure.sh && \\
    echo '# Apply network isolation rules (non-blocking)' >> /start-secure.sh && \\
    echo '/usr/local/bin/secure-network.sh || echo "⚠️  Network isolation failed, continuing anyway..."' >> /start-secure.sh && \\
    echo '' >> /start-secure.sh && \\
    echo '# Start SSH daemon (this must succeed)' >> /start-secure.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /start-secure.sh && \\
    chmod +x /start-secure.sh

CMD ["/start-secure.sh"]
`;

  return dockerfile;
}

/**
 * Read base-images README.md to understand tool categories
 */
async function readBaseImagesDocumentation() {
  try {
    const readmePath = path.join(process.cwd(), 'base-images', 'README.md');
    const content = await fs.readFile(readmePath, 'utf-8');
    return content;
  } catch (error) {
    console.warn('⚠️ Could not read base-images/README.md:', error.message);
    return null;
  }
}

/**
 * Tool installation prompt
 */
const TOOL_INSTALLATION_PROMPT = `You are a Linux system administration expert specializing in CTF challenge environments.

🔧 DOCKER CONFIGURATION REFERENCE - VULHUB:
- **Reference Vulhub** (https://github.com/vulhub/vulhub) for correct Dockerfile patterns and service configurations
- Vulhub provides WORKING Docker configurations that are tested and verified
- When generating Dockerfiles, ensure they match Vulhub's patterns for:
  * Correct service installations and configurations
  * Proper directory structures
  * Working service startup commands
  * Correct file permissions

Your task is to generate a comprehensive Dockerfile that:
1. Starts from kalilinux/kali-rolling base image
2. Updates system packages (apt-get update)
3. Installs ALL essential tools for the given challenge category
4. Includes SSH server for remote access
5. Sets up proper user accounts (root and kali user)
6. Configures services to start automatically
7. Installs Python packages via pip when needed
8. Cleans up apt cache to reduce image size

CRITICAL REQUIREMENTS:
✅ ALWAYS run "apt-get update" BEFORE any "apt-get install" command
✅ Every RUN command with apt-get install MUST start with "apt-get update &&"
✅ Always include: openssh-server, sudo, vim, nano, curl, wget, git, net-tools
✅ Install tools in optimal order (system packages first, then language-specific)
✅ Group related packages in single RUN commands for layer caching
✅ Clean apt cache: && apt-get clean && rm -rf /var/lib/apt/lists/*
✅ Configure SSH to allow root login and password authentication
✅ Set default passwords: root=toor, kali=kali
✅ Create /challenge directory for challenge files
✅ Install tools specific to challenge category (web, network, crypto, pwn)

EXAMPLE CORRECT FORMAT:
\`\`\`dockerfile
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    openssh-server \\
    nmap \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*
\`\`\`

TOOL CATEGORIES (from base-images/README.md):

**Web Exploitation Tools:**
- burpsuite, sqlmap, nikto, gobuster, ffuf, wfuzz, curl, wget
- Python3 with pip, python3-requests

**Network Analysis Tools:**
- nmap, masscan, wireshark, tshark, tcpdump, netcat-traditional
- hping3, arp-scan, netdiscover, traceroute, whois, dnsutils

**PWN/Reverse Engineering Tools:**
- gdb, gdb-peda, ghidra, radare2, objdump, ltrace, strace
- python3-pwntools, ropper, checksec, gcc, g++, make

**Cryptography Tools:**
- hashcat, john, openssl, hashid, hash-identifier
- python3-pycryptodome

**Common for All:**
- openssh-server (MANDATORY for connectivity)
- sudo, vim, nano, curl, wget, git, net-tools, iputils-ping
- python3, python3-pip

CRITICAL PACKAGE NAME CORRECTIONS:
❌ WRONG: volatility3 (via apt) - Package does not exist in apt
✅ RIGHT: Install volatility3 via pip3 AFTER apt packages

❌ WRONG: strings (as standalone package)
✅ RIGHT: binutils (provides strings, objdump, etc.)

❌ WRONG: exiftool (package name)
✅ RIGHT: libimage-exiftool-perl

INSTALLATION ORDER (CRITICAL):
1. apt-get update
2. apt-get install apt packages (openssh-server, binutils, libimage-exiftool-perl, etc.)
3. pip3 install volatility3 (AFTER apt install)

SSH SERVER CONFIGURATION (MANDATORY):
\`\`\`dockerfile
# Install and configure SSH server
RUN apt-get update && \\
    apt-get install -y openssh-server sudo && \\
    mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create challenge directory
RUN mkdir -p /challenge && chmod 755 /challenge

# 🔒 SECURITY: Install iptables and iproute2 for network isolation
RUN apt-get update && \\
    apt-get install -y --no-install-recommends iptables iproute2 && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 🔒 SECURITY: Create network isolation script
# IMPORTANT: Allow Guacamole network (172.22.0.0/16) for SSH access - DO NOT BLOCK
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo 'set -e' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Flush existing rules' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F OUTPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F INPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F FORWARD' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Set default policies' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P INPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P FORWARD ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P OUTPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow loopback' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -i lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -o lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow established and related connections' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Get gateway IP from default route' >> /usr/local/bin/secure-network.sh && \\
    echo 'GATEWAY=$(ip route | grep default | awk '"'"'{print $3}'"'"' | head -1)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo '  GATEWAY=$(echo $MY_IP | cut -d. -f1-3).1' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block gateway access (except DNS on port 53)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "🔒 Blocking gateway access: $GATEWAY (except DNS)"' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block infrastructure networks (OUTPUT only - allow INPUT for SSH from Guacamole)' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "🔒 Blocking infrastructure networks (OUTPUT only)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.20.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.21.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo '# NOTE: 172.22.0.0/16 is Guacamole network - DO NOT BLOCK (needed for SSH access)' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow SSH from any source (for Guacamole access)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow all traffic within challenge network' >> /usr/local/bin/secure-network.sh && \\
    echo 'MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'NETWORK=$(echo $MY_IP | cut -d. -f1-3).0/24' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -s $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "✅ Network isolation rules applied (Guacamole SSH access allowed)"' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

# Expose SSH port
EXPOSE 22

# 🔒 SECURITY: Create secure startup script
RUN echo '#!/bin/bash' > /start-secure.sh && \\
    echo 'set +e' >> /start-secure.sh && \\
    echo '/usr/local/bin/secure-network.sh || echo "⚠️  Network isolation failed, continuing anyway..."' >> /start-secure.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /start-secure.sh && \\
    chmod +x /start-secure.sh

# Start SSH service with network isolation
CMD ["/start-secure.sh"]
\`\`\`

OUTPUT FORMAT:
Return ONLY the complete Dockerfile content, no explanation or markdown formatting.

Example structure:
FROM kalilinux/kali-rolling

# Update and install base tools
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    openssh-server sudo vim nano curl wget git net-tools iputils-ping \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install category-specific tools (APT PACKAGES ONLY, NO PIP)
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    binutils nmap netcat-traditional tcpdump \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python packages via pip (SEPARATE STEP)
RUN pip3 install volatility3 --break-system-packages

# Configure SSH and users
RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create challenge directory
RUN mkdir -p /challenge && chmod 755 /challenge

# 🔒 SECURITY: Install iptables and iproute2 for network isolation
RUN apt-get update && \\
    apt-get install -y --no-install-recommends iptables iproute2 && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 🔒 SECURITY: Create network isolation script
# IMPORTANT: Allow Guacamole network (172.22.0.0/16) for SSH access - DO NOT BLOCK
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo 'set -e' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Flush existing rules' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F OUTPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F INPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F FORWARD' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Set default policies' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P INPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P FORWARD ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P OUTPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow loopback' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -i lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -o lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow established and related connections' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Get gateway IP from default route' >> /usr/local/bin/secure-network.sh && \\
    echo 'GATEWAY=$(ip route | grep default | awk '"'"'{print $3}'"'"' | head -1)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo '  GATEWAY=$(echo $MY_IP | cut -d. -f1-3).1' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block gateway access (except DNS on port 53)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "🔒 Blocking gateway access: $GATEWAY (except DNS)"' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block infrastructure networks (OUTPUT only - allow INPUT for SSH from Guacamole)' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "🔒 Blocking infrastructure networks (OUTPUT only)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.20.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.21.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo '# NOTE: 172.22.0.0/16 is Guacamole network - DO NOT BLOCK (needed for SSH access)' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow SSH from any source (for Guacamole access)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow all traffic within challenge network' >> /usr/local/bin/secure-network.sh && \\
    echo 'MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'NETWORK=$(echo $MY_IP | cut -d. -f1-3).0/24' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -s $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "✅ Network isolation rules applied (Guacamole SSH access allowed)"' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

EXPOSE 22

# 🔒 SECURITY: Create secure startup script
RUN echo '#!/bin/bash' > /start-secure.sh && \\
    echo 'set +e' >> /start-secure.sh && \\
    echo '/usr/local/bin/secure-network.sh || echo "⚠️  Network isolation failed, continuing anyway..."' >> /start-secure.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /start-secure.sh && \\
    chmod +x /start-secure.sh

CMD ["/start-secure.sh"]
`;

/**
 * Generate optimized Dockerfile with all necessary tools using learning system
 */
export async function generateToolInstallationDockerfile({ 
  category, 
  challengeType, 
  scenario, 
  requiredTools = [] 
}) {
  try {
    console.log(`🔧 Generating tool installation Dockerfile for ${category} challenge...`);
    console.log(`📚 Learning installation methods for ${requiredTools.length} tools...`);

    // Learn installation methods for all required tools
    const learnedMethods = await learnMultipleTools(requiredTools, category);
    
    // Group by installation method
    const aptPackages = [];
    const pipPackages = [];
    const gemPackages = [];
    const gitInstalls = [];
    const failedTools = [];

    for (const { toolName, result } of learnedMethods) {
      if (!result) {
        failedTools.push(toolName);
        console.warn(`⚠️ Could not learn installation for: ${toolName}`);
        continue;
      }

      if (result.method === 'apt') {
        aptPackages.push(result.package_name || result.packageName);
      } else if (result.method === 'pip') {
        pipPackages.push(result.package_name || result.packageName);
      } else if (result.method === 'gem') {
        gemPackages.push(result.package_name || result.packageName);
      } else if (result.method === 'git') {
        gitInstalls.push(result.install_command || result.command);
      }
    }

    console.log(`✅ Learned methods - APT: ${aptPackages.length}, PIP: ${pipPackages.length}, GEM: ${gemPackages.length}, GIT: ${gitInstalls.length}`);
    if (failedTools.length > 0) {
      console.warn(`❌ Failed to learn: ${failedTools.join(', ')}`);
    }

    // Generate Dockerfile with learned methods
    return await generateDockerfileFromLearnedMethods({
      category,
      aptPackages,
      pipPackages,
      gemPackages,
      gitInstalls
    });

  } catch (error) {
    console.error('Tool learning error:', error);
    // Fallback to old method
    console.log('⚠️ Falling back to AI-generated Dockerfile...');
    
    try {
      // Read base-images documentation
      const baseImagesDoc = await readBaseImagesDocumentation();

      const prompt = `Generate a complete Dockerfile for a ${category} CTF challenge.

Challenge Type: ${challengeType}
Scenario: ${scenario}
Required Tools: ${requiredTools.join(', ') || 'Automatic detection based on category'}

${baseImagesDoc ? `\nBase Images Documentation:\n${baseImagesDoc}` : ''}

CRITICAL PACKAGE NAME FIXES:
- Use "binutils" not "strings" (strings is part of binutils)
- Use "libimage-exiftool-perl" not "exiftool"
- NEVER include "volatility3" in apt install (doesn't exist)
- Install volatility3 via pip3 in a SEPARATE RUN command

REMEMBER:
1. Include openssh-server (MANDATORY)
2. Configure SSH with root login enabled
3. Set passwords: root=toor, kali=kali
4. Install ALL tools relevant to ${category} category
5. Include nmap, netcat-traditional, curl, wget, git (essential utilities)
6. Clean apt cache after each install
7. Create /challenge directory
8. Expose port 22 and start SSH service
9. Separate apt packages from pip packages (two separate RUN commands)

Generate the Dockerfile now.`;

      const response = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4000,
        temperature: 0.5,
        system: TOOL_INSTALLATION_PROMPT,
        messages: [{
          role: 'user',
          content: prompt
        }]
      });

      let dockerfile = response.content[0].text.trim();

      // Remove markdown code blocks if present
      dockerfile = dockerfile.replace(/```dockerfile\n?/g, '').replace(/```\n?/g, '');
      
      // CRITICAL: Ensure apt-get update is called before any apt-get install
      // If the Dockerfile doesn't have "apt-get update" before install, add it
      if (dockerfile.includes('apt-get install') && !dockerfile.match(/apt-get update\s*&&/)) {
        console.log('⚠️  Adding missing apt-get update before install...');
        dockerfile = dockerfile.replace(
          /(RUN\s+apt-get\s+install)/g,
          'RUN apt-get update && \\\n    apt-get install'
        );
      }

      // Validate essential components
      const validations = {
        'FROM kalilinux/kali-rolling': /FROM\s+kalilinux\/kali-rolling/,
        'openssh-server installed': /openssh-server/,
        'SSH configured': /PermitRootLogin\s+yes/,
        'SSH exposed': /EXPOSE\s+22/,
        'SSH CMD': /CMD.*sshd.*-D/,
        '/challenge directory': /mkdir.*\/challenge/
      };

      const missing = [];
      for (const [name, pattern] of Object.entries(validations)) {
        if (!pattern.test(dockerfile)) {
          missing.push(name);
        }
      }

      if (missing.length > 0) {
        console.warn(`⚠️ Dockerfile missing components: ${missing.join(', ')}`);
        console.warn('Adding missing SSH configuration...');
        dockerfile = ensureSSHConfiguration(dockerfile);
      }

      console.log(`✅ Generated Dockerfile with SSH server and ${category} tools`);
      return dockerfile;

    } catch (fallbackError) {
      console.error('Fallback AI generation failed:', fallbackError);
      // Return hardcoded fallback Dockerfile with SSH
      return generateFallbackDockerfile(category);
    }
  }
}

/**
 * Ensure SSH configuration is present in Dockerfile
 */
function ensureSSHConfiguration(dockerfile) {
  if (!dockerfile.includes('openssh-server')) {
    const baseInstall = `RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    openssh-server sudo vim nano curl wget git net-tools iputils-ping \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*\n\n`;
    
    dockerfile = dockerfile.replace(/FROM.*\n/, match => match + '\n' + baseInstall);
  }

  if (!dockerfile.includes('PermitRootLogin')) {
    const sshConfig = `\n# Configure SSH server
RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ✅ FIX: Replace nmap wrapper to always use unprivileged mode
RUN mv /usr/bin/nmap /usr/bin/nmap.original 2>/dev/null || true && \\
    echo '#!/bin/bash' > /usr/bin/nmap && \\
    echo 'exec /usr/lib/nmap/nmap --unprivileged "$@"' >> /usr/bin/nmap && \\
    chmod +x /usr/bin/nmap\n\n`;
    
    dockerfile += sshConfig;
  }

  if (!dockerfile.includes('/challenge')) {
    dockerfile += `\nRUN mkdir -p /challenge && chmod 755 /challenge\n`;
  }

  if (!dockerfile.includes('EXPOSE 22')) {
    dockerfile += `\nEXPOSE 22\n`;
  }

  // 🔒 SECURITY: Add network isolation if not already present
  if (!dockerfile.includes('secure-network.sh')) {
    dockerfile += `
# 🔒 SECURITY: Install iptables and iproute2 for network isolation
RUN apt-get update && \\
    apt-get install -y --no-install-recommends iptables iproute2 && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 🔒 SECURITY: Create network isolation script
# IMPORTANT: Allow Guacamole network (172.22.0.0/16) for SSH access - DO NOT BLOCK
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo 'set -e' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Flush existing rules' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F OUTPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F INPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F FORWARD' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Set default policies' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P INPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P FORWARD ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P OUTPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow loopback' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -i lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -o lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow established and related connections' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Get gateway IP from default route' >> /usr/local/bin/secure-network.sh && \\
    echo 'GATEWAY=$(ip route | grep default | awk '"'"'{print $3}'"'"' | head -1)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo '  GATEWAY=$(echo $MY_IP | cut -d. -f1-3).1' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block gateway access (except DNS on port 53)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "🔒 Blocking gateway access: $GATEWAY (except DNS)"' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block infrastructure networks (OUTPUT only - allow INPUT for SSH from Guacamole)' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "🔒 Blocking infrastructure networks (OUTPUT only)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.20.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.21.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo '# NOTE: 172.22.0.0/16 is Guacamole network - DO NOT BLOCK (needed for SSH access)' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow SSH from any source (for Guacamole access)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow all traffic within challenge network' >> /usr/local/bin/secure-network.sh && \\
    echo 'MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'NETWORK=$(echo $MY_IP | cut -d. -f1-3).0/24' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -s $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "✅ Network isolation rules applied (Guacamole SSH access allowed)"' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

# 🔒 SECURITY: Create secure startup script
RUN echo '#!/bin/bash' > /start-secure.sh && \\
    echo 'set +e' >> /start-secure.sh && \\
    echo '/usr/local/bin/secure-network.sh || echo "⚠️  Network isolation failed, continuing anyway..."' >> /start-secure.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /start-secure.sh && \\
    chmod +x /start-secure.sh
`;
  }

  if (!dockerfile.includes('CMD')) {
    dockerfile += `\nCMD ["/start-secure.sh"]\n`;
  } else if (dockerfile.includes('CMD ["/usr/sbin/sshd", "-D"]')) {
    // Replace existing SSH CMD with secure startup
    dockerfile = dockerfile.replace(/CMD \["\/usr\/sbin\/sshd", "-D"\]/g, 'CMD ["/start-secure.sh"]');
  }

  return dockerfile;
}

/**
 * Generate fallback Dockerfile with SSH for specific category
 */
function generateFallbackDockerfile(category) {
  const toolsByCategory = {
    web: 'sqlmap nikto gobuster ffuf curl wget python3-requests',
    network: 'nmap masscan wireshark tshark tcpdump netcat-traditional hping3 arp-scan netdiscover',
    crypto: 'hashcat john openssl hashid python3-pycryptodome',
    pwn: 'gdb ghidra radare2 ltrace strace python3-pwntools gcc g++ make'
  };

  const tools = toolsByCategory[category] || toolsByCategory.web;

  return `FROM kalilinux/kali-rolling

# Update and install base tools
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    openssh-server sudo vim nano curl wget git net-tools iputils-ping \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install ${category} tools
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    ${tools} \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*

${needsVolatility ? '# Install Volatility3 via pip\nRUN pip3 install volatility3 --break-system-packages\n' : ''}
# Configure SSH server
RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ✅ FIX: Replace nmap wrapper to always use unprivileged mode
# The default /usr/bin/nmap wrapper tries to use --privileged which requires capabilities
# We replace it with a wrapper that always uses --unprivileged mode
RUN mv /usr/bin/nmap /usr/bin/nmap.original 2>/dev/null || true && \\
    echo '#!/bin/bash' > /usr/bin/nmap && \\
    echo '# Nmap wrapper - always use unprivileged mode (no CAP_NET_RAW required)' >> /usr/bin/nmap && \\
    echo 'exec /usr/lib/nmap/nmap --unprivileged "$@"' >> /usr/bin/nmap && \\
    chmod +x /usr/bin/nmap

# Create challenge directory
RUN mkdir -p /challenge && chmod 755 /challenge

# 🔒 SECURITY: Install iptables and iproute2 for network isolation
RUN apt-get update && \\
    apt-get install -y --no-install-recommends iptables iproute2 && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 🔒 SECURITY: Create network isolation script
# IMPORTANT: Allow Guacamole network (172.22.0.0/16) for SSH access - DO NOT BLOCK
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo 'set -e' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Flush existing rules' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F OUTPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F INPUT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F FORWARD' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Set default policies' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P INPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P FORWARD ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P OUTPUT ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow loopback' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -i lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -o lo -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow established and related connections' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Get gateway IP from default route' >> /usr/local/bin/secure-network.sh && \\
    echo 'GATEWAY=$(ip route | grep default | awk '"'"'{print $3}'"'"' | head -1)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo '  GATEWAY=$(echo $MY_IP | cut -d. -f1-3).1' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block gateway access (except DNS on port 53)' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "🔒 Blocking gateway access: $GATEWAY (except DNS)"' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block infrastructure networks (OUTPUT only - allow INPUT for SSH from Guacamole)' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "🔒 Blocking infrastructure networks (OUTPUT only)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.20.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.21.0.0/16 -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo '# NOTE: 172.22.0.0/16 is Guacamole network - DO NOT BLOCK (needed for SSH access)' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow SSH from any source (for Guacamole access)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow all traffic within challenge network' >> /usr/local/bin/secure-network.sh && \\
    echo 'MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'NETWORK=$(echo $MY_IP | cut -d. -f1-3).0/24' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -s $NETWORK -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "✅ Network isolation rules applied (Guacamole SSH access allowed)"' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

EXPOSE 22

# 🔒 SECURITY: Create secure startup script
RUN echo '#!/bin/bash' > /start-secure.sh && \\
    echo 'set +e' >> /start-secure.sh && \\
    echo '/usr/local/bin/secure-network.sh || echo "⚠️  Network isolation failed, continuing anyway..."' >> /start-secure.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /start-secure.sh && \\
    chmod +x /start-secure.sh

CMD ["/start-secure.sh"]
`;
}

/**
 * Generate victim/target machine Dockerfile with SSH
 * Supports multiple OS images for multi-OS challenges
 */
/**
 * Service port mappings (for EXPOSE statements only)
 * Note: Service startup commands are now AI-generated via configuration.setup
 * This is only used for port exposure and decoy port generation
 */
const SERVICE_PORT_MAP = {
  'ftp': [21],
  'samba': [445, 139, 135], // Linux Samba (SMB protocol on Linux) - NO Windows SMB support
  'http': [80],
  'web': [80],
  'https': [443],
  'ssh': [22],
  'telnet': [23],
  'dns': [53],
  'mysql': [3306],
  'postgresql': [5432],
  'redis': [6379],
  'mongodb': [27017],
  'ldap': [389],
  'snmp': [161],
  'nfs': [2049]
};

/**
 * Note: Decoy ports are now AI-generated based on challenge difficulty
 * The AI will include decoyPorts array in the configuration object
 */

/**
 * Normalize service names (handle aliases)
 * Note: SMB is removed (Windows-only), Samba is Linux SMB implementation
 */
function normalizeServiceName(serviceName) {
  const normalized = serviceName.toLowerCase().trim();
  // Handle aliases
  if (normalized === 'web') return 'http';
  // Note: 'smb' is not supported (Windows-only) - use 'samba' for Linux SMB shares
  if (normalized === 'smb') {
    console.warn(`⚠️  'smb' service detected - converting to 'samba' (Linux SMB implementation). Windows SMB is not supported.`);
    return 'samba';
  }
  return normalized;
}

export async function generateVictimDockerfileWithSSH({ 
  category, 
  services = [], 
  scenario,
  osImage = 'ubuntu:22.04',
  packageManager = 'apt-get',
  machineName = 'victim',
  configurations = {}, // AI-generated service configurations (from content.configurations)
  difficulty = 'medium', // Challenge difficulty for decoy port exposure
  isAttacker = false // Whether this is an attacker machine (SSH should be exposed)
}) {
  // CRITICAL: Filter out tools from services - tools should only be on attacker machines!
  // Load attack tools from database
  const attackTools = await getAttackTools();
  const filteredServices = services.filter(s => {
    const normalized = s.toLowerCase().trim();
    return !attackTools.includes(normalized);
  });
  
  if (services.length !== filteredServices.length) {
    const removedTools = services.filter(s => attackTools.includes(s.toLowerCase().trim()));
    console.warn(`⚠️  Removed attack tools from victim machine ${machineName} services: ${removedTools.join(', ')}. Tools should only be on attacker machines.`);
  }
  
  // Load invalid service names from database
  const invalidServiceNames = await getInvalidServiceNames();
  const finalFilteredServices = filteredServices.filter(s => {
    const normalized = s.toLowerCase().trim();
    return !invalidServiceNames.includes(normalized);
  });
  
  // Get service package names from database (OS-specific)
  const validPackages = [];
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/1b985bb6-cc04-4a19-978d-5b8275873f6f',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'tool-installation-agent.js:520',message:'Package resolution start',data:{services:finalFilteredServices,packageManager,osImage},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
  // #endregion
  for (const serviceName of finalFilteredServices) {
    const packageName = await getServicePackageName(serviceName, packageManager);
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/1b985bb6-cc04-4a19-978d-5b8275873f6f',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'tool-installation-agent.js:525',message:'Service package resolved',data:{serviceName,packageName,packageManager},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
    // #endregion
    if (packageName) {
      // Apply package aliases for the specific OS
      let osType = 'debian'; // default
      if (packageManager === 'apk') osType = 'alpine';
      else if (packageManager === 'dnf' || packageManager === 'yum') osType = 'rhel';
      else if (packageManager === 'pacman') osType = 'arch';
      const resolvedPackage = await resolvePackageName(packageName, osType);
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/1b985bb6-cc04-4a19-978d-5b8275873f6f',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'tool-installation-agent.js:531',message:'Package alias resolved',data:{packageName,resolvedPackage,osType},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'A'})}).catch(()=>{});
      // #endregion
      validPackages.push(resolvedPackage);
    }
  }
  
  // Remove duplicates
  const uniquePackages = [...new Set(validPackages)];
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/1b985bb6-cc04-4a19-978d-5b8275873f6f',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'tool-installation-agent.js:536',message:'Unique packages before fixes',data:{uniquePackages,packageManager,osImage},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
  // #endregion
  
  // ✅ FIX: Alpine Linux doesn't have 'telnet' package - replace with 'busybox-extras'
  // This must be done AFTER package resolution but BEFORE joining
  const fixedPackages = uniquePackages.map(pkg => {
    if (packageManager === 'apk' && (pkg === 'telnet' || pkg === 'telnetd')) {
      console.log(`⚠️  Replacing '${pkg}' with 'busybox-extras' for Alpine Linux`);
      return 'busybox-extras';
    }
    // ✅ FIX: Remove xinetd for Rocky Linux 9 (deprecated, not available)
    if ((packageManager === 'dnf' || packageManager === 'yum') && pkg === 'xinetd') {
      console.log(`⚠️  Removing 'xinetd' for Rocky Linux/RHEL (deprecated, not available)`);
      return null; // Remove it
    }
    return pkg;
  }).filter(pkg => pkg !== null); // Remove nulls
  
  // Remove duplicates again after replacement
  const packages = [...new Set(fixedPackages)].join(' ');
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/1b985bb6-cc04-4a19-978d-5b8275873f6f',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'tool-installation-agent.js:550',message:'Final packages after fixes',data:{packages,packageManager,osImage},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'B'})}).catch(()=>{});
  // #endregion

  // IMPROVEMENT: Support multiple OS images (not just Kali for victims)
  // Determine installation commands based on package manager
  // Load base tools from database
  const baseToolsArray = await getBaseTools(packageManager);
  
  // ✅ FIX: Replace 'telnet' with 'busybox-extras' in base tools for Alpine
  const fixedBaseTools = baseToolsArray.map(tool => {
    if (packageManager === 'apk' && (tool === 'telnet' || tool === 'telnetd')) {
      console.log(`⚠️  Replacing base tool '${tool}' with 'busybox-extras' for Alpine Linux`);
      return 'busybox-extras';
    }
    return tool;
  });
  
  const baseTools = [...new Set(fixedBaseTools)].join(' ');
  
  // ✅ FIX: Remove xinetd from baseTools and packages for Rocky Linux/RHEL (final safety check)
  let finalBaseTools = baseTools;
  let finalPackages = packages;
  if (packageManager === 'dnf' || packageManager === 'yum') {
    // Remove xinetd from baseTools string
    finalBaseTools = finalBaseTools.replace(/\s+xinetd\s+/g, ' ').replace(/\s+xinetd$/g, '').replace(/^xinetd\s+/g, '').trim();
    // Remove xinetd from packages string
    if (finalPackages) {
      finalPackages = finalPackages.replace(/\s+xinetd\s+/g, ' ').replace(/\s+xinetd$/g, '').replace(/^xinetd\s+/g, '').trim();
    }
  }
  
  let installCommand = '';
  if (packageManager === 'apk') {
    // Alpine Linux
    installCommand = `RUN apk update && \\
    apk add --no-cache \\
    ${finalBaseTools}${finalPackages ? ' ' + finalPackages : ''} \\
    && rm -rf /var/cache/apk/*`;
  } else if (packageManager === 'dnf') {
    // Rocky Linux / Fedora / RHEL (uses dnf)
    installCommand = `RUN dnf install -y --setopt=install_weak_deps=False \\
    ${finalBaseTools} ${finalPackages ? finalPackages + ' ' : ''} \\
    && dnf clean all`;
  } else if (packageManager === 'pacman') {
    // Arch Linux
    installCommand = `RUN pacman -Sy --noconfirm \\
    ${finalBaseTools}${finalPackages ? ' ' + finalPackages : ''} \\
    && pacman -Scc --noconfirm`;
  } else {
    // Ubuntu/Debian (apt-get) - default
    installCommand = `RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    ${finalBaseTools} ${finalPackages ? finalPackages + ' ' : ''} \\
    && apt-get clean && rm -rf /var/lib/apt/lists/*`;
  }
  
  // #region agent log
  fetch('http://127.0.0.1:7242/ingest/1b985bb6-cc04-4a19-978d-5b8275873f6f',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'tool-installation-agent.js:595',message:'Final install command generated',data:{installCommand:installCommand.substring(0,200),packageManager,hasXinetd:installCommand.includes('xinetd')},timestamp:Date.now(),sessionId:'debug-session',runId:'run1',hypothesisId:'C'})}).catch(()=>{});
  // #endregion

  // IMPROVEMENT: For Samba (Linux SMB) machines, ensure Samba is installed
  // Note: Windows is NOT supported - all machines must be Linux
  let additionalServices = '';
  if (services.includes('samba') || machineName.toLowerCase().includes('samba')) {
    if (packageManager === 'apk') {
      additionalServices = 'samba samba-common';
    } else if (packageManager === 'dnf' || packageManager === 'yum') {
      additionalServices = 'samba samba-common';
    } else if (packageManager === 'pacman') {
      additionalServices = 'samba';
    } else {
      additionalServices = 'samba samba-common-bin';
    }
  }

  // Only set DEBIAN_FRONTEND for Debian-based systems (apt-get)
  const debianEnv = (packageManager === 'apt-get') ? 'ENV DEBIAN_FRONTEND=noninteractive\n\n' : '';

  // ✅ IMPROVEMENT: Build dynamic startup script using AI-generated service configurations
  // Extract AI-generated setup commands from configurations
  let aiGeneratedSetup = '';
  const servicePorts = new Set();
  const decoyPorts = new Set();
  
  // Collect AI-generated setup commands from all category configurations
  for (const category in configurations) {
    const config = configurations[category];
    if (config && config.setup) {
      // AI-generated setup commands (from network-content-agent, web-content-agent, etc.)
      // ✅ FIX: Clean and normalize the setup commands to prevent syntax errors
      let cleanSetup = config.setup.trim();
      
      // Remove any leading/trailing && operators that might cause issues
      cleanSetup = cleanSetup.replace(/^&&\s*/g, '').replace(/\s*&&$/g, '');
      
      // Ensure each command ends properly (add & for background services if needed)
      // Split by && to handle each command separately
      const commands = cleanSetup.split(/\s*&&\s*/).filter(cmd => cmd.trim().length > 0);
      const normalizedCommands = commands.map(cmd => {
        cmd = cmd.trim();
        // If command doesn't end with & and is a service start command, add &
        if ((cmd.includes('vsftpd') || cmd.includes('smbd') || cmd.includes('nmbd') || 
             cmd.includes('apache') || cmd.includes('nginx') || cmd.includes('httpd') ||
             cmd.includes('sshd')) && !cmd.endsWith('&') && !cmd.includes('service start')) {
          return cmd + ' &';
        }
        return cmd;
      });
      
      cleanSetup = normalizedCommands.join(' && ');
      
      aiGeneratedSetup += `\n# ${config.serviceType || category} service setup (AI-generated)\n`;
      aiGeneratedSetup += cleanSetup + '\n';
      
      // Extract service port from configuration if available
      if (config.servicePort) {
        servicePorts.add(config.servicePort);
      }
      
      // Extract AI-generated decoy ports (if provided by AI)
      if (config.decoyPorts && Array.isArray(config.decoyPorts)) {
        config.decoyPorts.forEach(port => decoyPorts.add(port));
      }
    }
  }
  
  // If no AI setup provided, use fallback: just start SSH (for attacker machines)
  // For victim machines, services should be started via AI-generated setup
  let startupScript = '#!/bin/bash\n';
  startupScript += 'set -e\n';
  
  if (isAttacker) {
    // Attacker machines: Always start SSH for Guacamole access
    startupScript += '# Start SSH server (required for Guacamole access)\n';
    startupScript += 'mkdir -p /var/run/sshd\n';
    startupScript += '/usr/sbin/sshd -D &\n';
  } else {
    // Victim machines: Use AI-generated setup commands (MANDATORY)
    if (aiGeneratedSetup) {
      startupScript += aiGeneratedSetup;
    } else {
      // CRITICAL: AI must always generate setup commands - this should not happen
      console.error(`❌ CRITICAL ERROR: No AI-generated setup found for ${machineName}. Services will not start!`);
      console.error(`   Services expected: ${finalFilteredServices.join(', ')}`);
      console.error(`   Categories: ${Object.keys(configurations).join(', ')}`);
      throw new Error(`AI failed to generate setup commands for ${machineName}. The 'setup' field in configuration is MANDATORY and must contain service startup commands.`);
    }
  }
  
  startupScript += '\n# Keep container running\n';
  startupScript += 'wait\n';

  // Generate EXPOSE ports dynamically
  const allPorts = new Set();
  
  // Add service ports from AI configuration
  servicePorts.forEach(port => allPorts.add(port));
  
  // Add ports from SERVICE_PORT_MAP for services in the services array
  const normalizedServices = finalFilteredServices.map(normalizeServiceName);
  const uniqueServices = [...new Set(normalizedServices)];
  for (const serviceName of uniqueServices) {
    const ports = SERVICE_PORT_MAP[serviceName];
    if (ports) {
      ports.forEach(port => allPorts.add(port));
    }
  }
  
  // Only expose SSH on attacker machines (for Guacamole access)
  if (isAttacker) {
    allPorts.add(22); // SSH for attacker
  }
  
  // Add AI-generated decoy ports (for victim machines only)
  if (!isAttacker) {
    decoyPorts.forEach(port => allPorts.add(port));
  }
  
  const exposePorts = Array.from(allPorts).sort((a, b) => a - b).join(' ');

  return `FROM ${osImage}

${debianEnv}# Update and install services
${installCommand}
${additionalServices ? `\n# Install Samba (Linux SMB/CIFS server)\nRUN ${packageManager === 'apk' ? 'apk add --no-cache' : packageManager === 'yum' ? 'yum install -y' : packageManager === 'dnf' ? 'dnf install -y' : packageManager === 'pacman' ? 'pacman -Sy --noconfirm' : 'apt-get update && apt-get install -y --no-install-recommends'} ${additionalServices}${packageManager === 'apk' ? '' : packageManager === 'yum' ? ' && yum clean all' : packageManager === 'dnf' ? ' && dnf clean all' : packageManager === 'pacman' ? ' && pacman -Scc --noconfirm' : ' && apt-get clean && rm -rf /var/lib/apt/lists/*'}\n` : ''}

# Configure SSH server
${packageManager === 'apk' ? `RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config` : packageManager === 'pacman' ? `RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config` : `RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali 2>/dev/null || true && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali 2>/dev/null || true && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config`}

# Create challenge directory
RUN mkdir -p /challenge && chmod 755 /challenge

# ✅ FIX: Copy challenge files into container (if they exist in build context)
# Note: Files are copied from the machine-specific directory (e.g., ftp-server/)
COPY . /challenge/

# ✅ FIX: Create startup script using echo (most reliable method, avoids heredoc/printf issues)
# Convert script to echo commands for maximum reliability
RUN echo '#!/bin/bash' > /start-services.sh${startupScript.split('\n').map(line => {
    // Escape single quotes and backslashes for echo
    const escaped = line.replace(/\\/g, '\\\\').replace(/'/g, "'\\''");
    return ` && \\\n    echo '${escaped}' >> /start-services.sh`;
  }).join('')} && \\
    chmod +x /start-services.sh && \\
    test -f /start-services.sh || (echo "ERROR: Failed to create /start-services.sh" && exit 1)

EXPOSE ${exposePorts}
CMD ["/start-services.sh"]
`;
}
