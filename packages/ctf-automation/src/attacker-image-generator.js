/**
 * Attacker Image Generator
 * Generates custom Kali Linux Dockerfiles with minimal tool sets
 * based on challenge type and required tools
 */

/**
 * Tool categories and their packages
 * Comprehensive mapping of tool names to Kali package names
 */
const TOOL_PACKAGES = {
  // Web exploitation tools
  'burpsuite': 'burpsuite',
  'sqlmap': 'sqlmap',
  'nikto': 'nikto',
  'gobuster': 'gobuster',
  'dirb': 'dirb',
  'dirbuster': 'dirbuster',
  'wfuzz': 'wfuzz',
  'ffuf': 'ffuf',
  'wpscan': 'wpscan',
  'commix': 'commix',
  'zaproxy': 'zaproxy',
  'mitmproxy': 'mitmproxy',
  'firefox-esr': 'firefox-esr',
  'chromium': 'chromium',
  'python3-requests': 'python3-requests',
  
  // Network tools
  'nmap': 'nmap',
  'masscan': 'masscan',
  'wireshark': 'wireshark',
  'tshark': 'tshark',
  'tcpdump': 'tcpdump',
  'netcat': 'netcat-traditional',
  'nc': 'netcat-traditional',
  'hping3': 'hping3',
  'arp-scan': 'arp-scan',
  'netdiscover': 'netdiscover',
  'ettercap': 'ettercap-text-only',
  'ettercap-text-only': 'ettercap-text-only',
  'responder': 'responder',
  'traceroute': 'traceroute',
  'whois': 'whois',
  'dnsutils': 'dnsutils',
  'ftp': 'ftp',
  'lftp': 'lftp',
  'tnftp': 'tnftp',
  'ncftp': 'ncftp',
  'telnet': 'telnet',
  'ssh': 'openssh-client',
  'ssh-client': 'openssh-client',
  'smbclient': 'smbclient',
  'cifs-utils': 'cifs-utils',
  'nfs-common': 'nfs-common',
  'tftp': 'tftp',
  'tftp-hpa': 'tftp-hpa',
  'snmp': 'snmp',
  'snmp-mibs-downloader': 'snmp-mibs-downloader',
  'hydra': 'hydra',
  'medusa': 'medusa',
  'net-tools': 'net-tools',
  'iproute2': 'iproute2',
  'iputils-ping': 'iputils-ping',
  'bind9-dnsutils': 'bind9-dnsutils',
  
  // Reverse engineering / PWN
  'gdb': 'gdb',
  'pwndbg': 'gdb',
  'gdb-peda': 'gdb-peda',
  'ghidra': 'ghidra',
  'radare2': 'radare2',
  'r2': 'radare2',
  'objdump': 'binutils',
  'ltrace': 'ltrace',
  'strace': 'strace',
  'valgrind': 'valgrind',
  'python3-pwntools': 'python3-pwntools',
  'pwntools': 'python3-pwntools',
  'ropper': 'ropper',
  'checksec': 'checksec',
  'gcc': 'gcc',
  'g++': 'g++',
  'make': 'make',
  'cmake': 'cmake',
  
  // Cryptography tools
  'hashcat': 'hashcat',
  'john': 'john',
  'johntheripper': 'john',
  'openssl': 'openssl',
  'hashid': 'hashid',
  'hash-identifier': 'hash-identifier',
  'python3-pycryptodome': 'python3-pycryptodome',
  
  // Exploitation frameworks
  'metasploit': 'metasploit-framework',
  'metasploit-framework': 'metasploit-framework',
  'msfconsole': 'metasploit-framework',
  
  // Common utilities
  'python3': 'python3 python3-pip',
  'python3-pip': 'python3-pip',
  'curl': 'curl',
  'wget': 'wget',
  'git': 'git',
  'vim': 'vim',
  'nano': 'nano',
  'jq': 'jq',
  'unzip': 'unzip',
  'zip': 'zip',
  'tar': 'tar',
  'gzip': 'gzip',
  'bzip2': 'bzip2'
};

/**
 * GitHub-based tools (not available in apt or require latest version)
 * Maps tool name to trusted GitHub repository
 * Format: 'tool-name': { repo: 'owner/repo', install: 'install command', description: 'what it does' }
 */
const GITHUB_TOOLS = {
  // GDB enhancements
  'pwndbg': {
    repo: 'pwndbg/pwndbg',
    install: 'cd /opt/pwndbg && ./setup.sh',
    description: 'GDB plugin for exploit development'
  },
  'gef': {
    repo: 'hugsy/gef',
    install: 'bash -c "$(curl -fsSL https://gef.blah.cat/sh)"',
    description: 'GDB Enhanced Features for exploit devs'
  },
  'peda': {
    repo: 'longld/peda',
    install: 'echo "source /opt/peda/peda.py" >> ~/.gdbinit',
    description: 'Python Exploit Development Assistance for GDB'
  },
  
  // Web exploitation
  'feroxbuster': {
    repo: 'epi052/feroxbuster',
    install: 'curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash',
    description: 'Fast content discovery tool'
  },
  'httpx': {
    repo: 'projectdiscovery/httpx',
    install: 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
    description: 'Fast HTTP toolkit'
  },
  
  // Reverse engineering
  'pwntools': {
    method: 'pip',
    package: 'pwntools',
    description: 'CTF framework and exploit development library'
  },
  'angr': {
    method: 'pip',
    package: 'angr',
    description: 'Binary analysis framework'
  },
  
  // Steganography
  'stegsolve': {
    repo: 'zardus/ctf-tools',
    install: 'wget -O /opt/stegsolve.jar https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar && echo "#!/bin/bash\njava -jar /opt/stegsolve.jar" > /usr/local/bin/stegsolve && chmod +x /usr/local/bin/stegsolve',
    description: 'Steganography analysis tool (Java)'
  },
  'zsteg': {
    method: 'gem',
    package: 'zsteg',
    description: 'PNG/BMP steganography detection tool'
  },
  'stegseek': {
    repo: 'RickdeJager/stegseek',
    install: 'wget https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb && dpkg -i stegseek_0.6-1.deb && rm stegseek_0.6-1.deb',
    description: 'Lightning fast steghide cracker'
  }
};

/**
 * Base tool sets for different challenge categories
 * Comprehensive tool lists to ensure users have everything they need
 */
const CATEGORY_BASE_TOOLS = {
  web: [
    // HTTP/Web tools
    'curl', 'wget', 'python3', 'python3-requests',
    // Scanners & Fuzzers
    'burpsuite', 'sqlmap', 'nikto', 'gobuster', 'ffuf', 'dirb', 'wfuzz',
    // Proxies & Interceptors
    'zaproxy', 'mitmproxy',
    // Utilities
    'git', 'nano', 'vim', 'jq', 'netcat',
    // Browser automation
    'firefox-esr', 'chromium'
  ],
  network: [
    // Port scanners
    'nmap', 'masscan', 'arp-scan', 'netdiscover',
    // Packet analysis
    'wireshark', 'tshark', 'tcpdump',
    // Network tools
    'netcat', 'hping3', 'traceroute', 'whois', 'dnsutils',
    // Service clients
    'ftp', 'tnftp', 'telnet', 'ssh', 'smbclient', 'nfs-common',
    // Sniffing & MITM
    'ettercap-text-only', 'responder',
    // Utilities
    'curl', 'wget', 'python3', 'git', 'nano'
  ],
  pwn: [
    // Debuggers
    'gdb', 'gdb-peda', 'pwndbg',
    // Disassemblers
    'ghidra', 'radare2', 'objdump',
    // Dynamic analysis
    'ltrace', 'strace', 'valgrind',
    // Exploit dev
    'python3-pwntools', 'ropper', 'checksec',
    // Compilers
    'gcc', 'g++', 'make', 'cmake',
    // Utilities
    'python3', 'git', 'vim', 'curl', 'netcat'
  ],
  crypto: [
    // Hash/Crypto tools
    'hashcat', 'john', 'openssl',
    // Python crypto libraries
    'python3', 'python3-pip', 'python3-pycryptodome',
    // Analysis tools
    'hashid', 'hash-identifier',
    // Utilities
    'git', 'nano', 'curl', 'wget', 'xxd'
  ],
  reverse: [
    // Disassemblers
    'ghidra', 'radare2', 'r2', 'objdump',
    // Debuggers
    'gdb', 'gdb-peda', 'ltrace', 'strace',
    // Binary analysis
    'strings', 'file', 'binwalk', 'checksec',
    // Hex editors
    'hexedit', 'xxd',
    // Utilities
    'python3', 'git', 'vim', 'curl'
  ],
  misc: [
    // Network basics
    'nmap', 'netcat', 'curl', 'wget',
    // Analysis
    'strings', 'file', 'binwalk',
    // Utilities
    'python3', 'git', 'nano', 'vim', 'jq', 'unzip'
  ]
};

/**
 * Helper function to generate GitHub and pip tool installation commands
 * @param {string[]} requiredTools - List of required tools
 * @returns {string} Installation commands for Dockerfile
 */
function generateGitHubToolsSection(requiredTools) {
  const pipTools = requiredTools.filter(t => GITHUB_TOOLS[t]?.method === 'pip');
  const gemTools = requiredTools.filter(t => GITHUB_TOOLS[t]?.method === 'gem');
  const gitTools = requiredTools.filter(t => GITHUB_TOOLS[t]?.repo);
  
  if (pipTools.length === 0 && gemTools.length === 0 && gitTools.length === 0) {
    return '# No GitHub-based tools required';
  }
  
  let section = '';
  
  // Install pip-based tools
  if (pipTools.length > 0) {
    const uniquePipPackages = [...new Set(pipTools.map(t => GITHUB_TOOLS[t].package))];
    section += `\n# Install Python packages via pip\n`;
    section += `RUN pip3 install --no-cache-dir --break-system-packages ${uniquePipPackages.join(' ')} && \\\n`;
    section += `    echo '✅ Python tools installed: ${uniquePipPackages.join(', ')}'\n`;
  }
  
  // Install gem-based tools
  if (gemTools.length > 0) {
    const uniqueGemPackages = [...new Set(gemTools.map(t => GITHUB_TOOLS[t].package))];
    section += `\n# Install Ruby gems\n`;
    section += `RUN gem install ${uniqueGemPackages.join(' ')} && \\\n`;
    section += `    echo '✅ Ruby gems installed: ${uniqueGemPackages.join(', ')}'\n`;
  }
  
  // Install GitHub repository-based tools
  if (gitTools.length > 0) {
    gitTools.forEach(tool => {
      const config = GITHUB_TOOLS[tool];
      section += `\n# Install ${tool} - ${config.description}\n`;
      section += `RUN ${config.install} && \\\n`;
      section += `    echo '✅ ${tool} installed from GitHub'\n`;
    });
  }
  
  return section;
}

/**
 * Generate a custom attacker Dockerfile based on challenge requirements
 * @param {string|Array<string>} challengeType - Category or array of categories: web, network, pwn, crypto, misc
 * @param {Array<string>} requiredTools - Specific tools needed
 * @param {string} challengeName - Name of the challenge (for container naming)
 * @returns {string} Complete Dockerfile content
 */
export function generateAttackerDockerfile(challengeType = 'misc', requiredTools = [], challengeName = 'challenge') {
  // Support multiple categories
  const categories = Array.isArray(challengeType) ? challengeType : [challengeType];
  
  // Merge tools from all categories
  let baseTools = [];
  for (const category of categories) {
    const categoryTools = CATEGORY_BASE_TOOLS[category] || CATEGORY_BASE_TOOLS.misc;
    baseTools = [...baseTools, ...categoryTools];
  }
  
  // Deduplicate base tools
  baseTools = [...new Set(baseTools)];
  
  // Merge with explicitly required tools (deduplicate)
  const allTools = [...new Set([...baseTools, ...requiredTools])];
  
  // Convert tool names to package names
  const packages = allTools
    .map(tool => TOOL_PACKAGES[tool.toLowerCase()] || tool)
    .filter((value, index, self) => self.indexOf(value) === index); // dedupe
  
  // Split packages into chunks for better Docker layer caching
  const essentialPackages = packages.filter(p => 
    ['kali-desktop-xfce', 'xfce4', 'tigervnc-standalone-server', 'dbus-x11', 'supervisor'].includes(p)
  );
  
  const toolPackages = packages.filter(p => !essentialPackages.includes(p));
  
  // Generate Dockerfile
  return `# Custom Kali Linux Attacker Machine
# Challenge: ${challengeName}
# Type: ${challengeType}
# Generated with minimal toolset

FROM kalilinux/kali-rolling

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update and install SSH server + essential Kali tools (ALWAYS update first!)
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    openssh-server \\
    sudo \\
    net-tools \\
    iproute2 \\
    iputils-ping \\
    dnsutils \\
    traceroute \\
    whois \\
    netcat-traditional \\
    nmap \\
    masscan \\
    tcpdump \\
    arp-scan \\
    nikto \\
    sqlmap \\
    dirb \\
    gobuster \\
    hydra \\
    john \\
    hashcat \\
    vim \\
    nano \\
    less \\
    man-db \\
    procps \\
    psmisc \\
    lsof \\
    htop \\
    wget \\
    curl \\
    git \\
    unzip \\
    zip \\
    tar \\
    gzip \\
    bzip2 \\
    file \\
    tree \\
    ca-certificates \\
    openssl \\
    python3 \\
    python3-pip \\
    python3-requests \\
    && apt-get clean \\
    && rm -rf /var/lib/apt/lists/*

# ✅ FIX: Replace nmap wrapper to always use unprivileged mode
# The default /usr/bin/nmap wrapper tries to use --privileged which requires capabilities
# We replace it with a wrapper that always uses --unprivileged mode
RUN mv /usr/bin/nmap /usr/bin/nmap.original && \\
    echo '#!/bin/bash' > /usr/bin/nmap && \\
    echo '# Nmap wrapper - always use unprivileged mode (no CAP_NET_RAW required)' >> /usr/bin/nmap && \\
    echo 'exec /usr/lib/nmap/nmap --unprivileged "$@"' >> /usr/bin/nmap && \\
    chmod +x /usr/bin/nmap && \\
    echo '# Note: Nmap configured for unprivileged mode (TCP connect scans)' >> /root/.bashrc && \\
    echo '# This works for CTF challenges without requiring Docker capabilities' >> /root/.bashrc

# Install challenge-specific tools
${toolPackages.length > 0 ? `RUN apt-get update && \\
    apt-get install -y --no-install-recommends --fix-missing \\
${toolPackages.map(pkg => `    ${pkg}`).join(' \\\n')} \\
    || (echo "⚠️ Some packages failed, retrying..." && \\
        apt-get update && \\
        apt-get install -y --fix-missing \\
${toolPackages.map(pkg => `        ${pkg}`).join(' \\\n')} \\
    ) && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*` : '# No additional tools required'}

${generateGitHubToolsSection(requiredTools)}

# ✅ FIX: Disable systemd/journald metadata logging (prevents annoying metadata in terminal)
RUN touch ~/.hushlogin && \\
    touch /home/kali/.hushlogin 2>/dev/null || true && \\
    echo 'export SYSTEMD_LOG_LEVEL=err' >> /root/.bashrc && \\
    echo 'export SYSTEMD_LOG_LEVEL=err' >> /home/kali/.bashrc 2>/dev/null || true && \\
    echo 'unset SYSTEMD_LOG_TARGET' >> /root/.bashrc && \\
    echo 'unset SYSTEMD_LOG_TARGET' >> /home/kali/.bashrc 2>/dev/null || true

# Configure SSH server for Guacamole access
RUN mkdir -p /var/run/sshd && \\
    echo 'root:kali' | chpasswd && \\
    useradd -m -s /bin/bash kali 2>/dev/null || true && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali 2>/dev/null || true && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \\
    echo > /etc/motd && \\
    chmod -x /etc/update-motd.d/* 2>/dev/null || true && \\
    echo 'export PS1="\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ "' >> /root/.bashrc && \\
    echo 'export PS1="\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ "' >> /home/kali/.bashrc 2>/dev/null || true && \\
    echo 'export TERM=xterm-256color' >> /root/.bashrc && \\
    echo 'export TERM=xterm-256color' >> /home/kali/.bashrc 2>/dev/null || true && \\
    sed -i 's/session    optional     pam_motd.so/# session    optional     pam_motd.so/' /etc/pam.d/sshd && \\
    sed -i 's/session    optional     pam_mail.so/# session    optional     pam_mail.so/' /etc/pam.d/sshd

# SECURITY: Create startup script to block gateway access (prevent platform attacks)
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo '# Block all traffic to Docker gateway except DNS' >> /usr/local/bin/secure-network.sh && \\
    echo 'GATEWAY=$(ip route | grep default | awk '\"'\"'{print $3}'\"'\"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'if [ ! -z "$GATEWAY" ]; then' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "🔒 Securing network: Blocking gateway access to $GATEWAY"' >> /usr/local/bin/secure-network.sh && \\
    echo '  # Allow DNS queries (UDP 53)' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT' >> /usr/local/bin/secure-network.sh && \\
    echo '  # Block all other traffic to gateway' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP' >> /usr/local/bin/secure-network.sh && \\
    echo '  echo "✅ Gateway access blocked. Challenge network isolated."' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '# Start SSH server' >> /usr/local/bin/secure-network.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

# Expose SSH port
EXPOSE 22

# Set working directory
WORKDIR /root

# Start with network security script
CMD ["/usr/local/bin/secure-network.sh"]
`;
}

/**
 * Generate docker-compose.yml with custom attacker image and private IP addresses
 * @param {string} challengeName - Name of the challenge
 * @param {string} challengeType - Category
 * @param {Array<string>} requiredTools - Tools needed
 * @param {boolean} hasDatabase - Whether challenge includes database
 * @param {object} subnet - Subnet allocation (REQUIRED - always use private IPs)
 * @returns {object} Docker compose configuration
 */
export function generateDockerCompose(challengeName, challengeType = 'misc', requiredTools = [], hasDatabase = false, subnet = null) {
  // ALWAYS use private IPs - subnet parameter is required
  if (!subnet) {
    throw new Error('Subnet parameter is required. All challenges must use private IP addressing.');
  }
  const usePrivateIPs = true;  // Always true - no port mappings allowed

  const services = {
    victim: {
      build: {
        context: '.',
        dockerfile: 'Dockerfile'
      },
      container_name: `ctf-${challengeName}-victim`,
      hostname: 'victim',
      networks: usePrivateIPs ? {
        'ctf-network': {
          ipv4_address: subnet.ips.victim
        }
      } : ['ctf-network']
    },
    attacker: {
      build: {
        context: './attacker',
        dockerfile: 'Dockerfile.attacker'
      },
      container_name: `ctf-${challengeName}-attacker`,
      hostname: 'attacker',
      // ✅ FIX: Add NET_RAW and NET_ADMIN capabilities for nmap binary execution
      // Even with unprivileged mode wrapper, the binary needs capabilities to execute
      cap_add: [
        'NET_RAW',
        'NET_ADMIN'
      ],
      networks: usePrivateIPs ? {
        'ctf-network': {
          ipv4_address: subnet.ips.attacker
        },
        'ctf-instances-network': {}  // Connect to Guacamole network
      } : ['ctf-network', 'ctf-instances-network']
    }
  };

  // ALWAYS use private IPs - no port mappings
  // Removed port mapping code - all challenges use private IP addressing

  // Add database if needed
  if (hasDatabase) {
    services.database = {
      image: 'postgres:15-alpine',
      container_name: `ctf-${challengeName}-database`,
      hostname: 'database',
      networks: usePrivateIPs ? {
        'ctf-network': {
          ipv4_address: subnet.ips.database
        }
      } : ['ctf-network'],
      environment: [
        'POSTGRES_PASSWORD=weakpassword123',
        'POSTGRES_USER=admin',
        'POSTGRES_DB=myapp'
      ],
      volumes: ['./init.sql:/docker-entrypoint-initdb.d/init.sql']
    };
    
    // No port mappings - always use private IPs
    
    // Update victim to depend on database
    services.victim.depends_on = ['database'];
    services.victim.environment = [
      'DB_HOST=database',
      'DB_PORT=5432'
    ];
  }

  // Configure network with subnet if provided
  const networkConfig = usePrivateIPs ? {
    driver: 'bridge',
    ipam: {
      config: [{
        subnet: subnet.subnet,
        gateway: subnet.gateway
      }]
    }
  } : {
    driver: 'bridge'
  };

  return {
    // ✅ FIX: Remove obsolete version attribute (docker compose v2 doesn't need it)
    services,
    networks: {
      'ctf-network': networkConfig,
      'ctf-instances-network': {
        external: true,
        name: 'ctf-instances-network'
      }
    }
  };
}

/**
 * Get tool suggestions based on challenge description
 * Uses keyword matching to suggest tools
 * @param {string} description - Challenge description
 * @returns {Array<string>} Suggested tools
 */
export function suggestTools(description) {
  const suggestions = [];
  const lowerDesc = description.toLowerCase();
  
  // Web exploitation - comprehensive coverage
  if (lowerDesc.match(/\b(sql|injection|database|sqli|mysql|postgres|mongodb)\b/)) {
    suggestions.push('sqlmap', 'burpsuite', 'curl', 'wget');
  }
  if (lowerDesc.match(/\b(xss|cross-site|script|javascript|dom)\b/)) {
    suggestions.push('burpsuite', 'curl', 'python3');
  }
  if (lowerDesc.match(/\b(directory|path|enum|brute.*force|wordlist|fuzzing)\b/)) {
    suggestions.push('gobuster', 'ffuf', 'dirb', 'wfuzz');
  }
  if (lowerDesc.match(/\b(web|http|https|website|api|rest|json)\b/)) {
    suggestions.push('curl', 'wget', 'burpsuite', 'nikto');
  }
  if (lowerDesc.match(/\b(upload|file.*upload|avatar|image.*upload)\b/)) {
    suggestions.push('burpsuite', 'curl', 'python3');
  }
  if (lowerDesc.match(/\b(wordpress|wp|cms|joomla|drupal)\b/)) {
    suggestions.push('wpscan', 'nikto', 'gobuster');
  }
  if (lowerDesc.match(/\b(ssrf|server.*side|internal|localhost|127\.0\.0\.1)\b/)) {
    suggestions.push('curl', 'burpsuite', 'python3');
  }
  if (lowerDesc.match(/\b(xxe|xml|entity|dtd)\b/)) {
    suggestions.push('burpsuite', 'curl', 'python3');
  }
  if (lowerDesc.match(/\b(command.*injection|rce|remote.*code|shell)\b/)) {
    suggestions.push('netcat', 'curl', 'python3', 'burpsuite');
  }
  if (lowerDesc.match(/\b(ftp|file.*transfer)\b/)) {
    suggestions.push('ftp', 'tnftp', 'curl', 'nmap');
  }
  if (lowerDesc.match(/\b(smb|samba|cifs|share)\b/)) {
    suggestions.push('smbclient', 'nmap', 'netcat');
  }
  
  // Network - comprehensive
  if (lowerDesc.match(/\b(port|scan|network|ip|host|service|banner)\b/)) {
    suggestions.push('nmap', 'masscan', 'netcat');
  }
  if (lowerDesc.match(/\b(packet|traffic|capture|pcap|sniff)\b/)) {
    suggestions.push('wireshark', 'tcpdump', 'tshark');
  }
  if (lowerDesc.match(/\b(connect|socket|tcp|udp|listener|bind)\b/)) {
    suggestions.push('netcat', 'nmap', 'python3');
  }
  if (lowerDesc.match(/\b(ssh|telnet|ftp|smtp|pop3|imap)\b/)) {
    suggestions.push('nmap', 'netcat', 'ftp', 'telnet', 'ssh');
  }
  if (lowerDesc.match(/\b(arp|mac|layer.*2|ethernet)\b/)) {
    suggestions.push('arp-scan', 'netdiscover', 'wireshark');
  }
  if (lowerDesc.match(/\b(dns|domain|subdomain|zone.*transfer)\b/)) {
    suggestions.push('nmap', 'curl', 'python3', 'dnsutils');
  }
  
  // PWN/RE - comprehensive
  if (lowerDesc.match(/\b(binary|executable|elf|exploit|overflow)\b/)) {
    suggestions.push('gdb', 'radare2', 'python3-pwntools', 'objdump', 'strings');
  }
  if (lowerDesc.match(/\b(reverse|disassem|decompil|assembly|asm)\b/)) {
    suggestions.push('ghidra', 'radare2', 'gdb', 'objdump');
  }
  if (lowerDesc.match(/\b(buffer|overflow|pwn|rop|shellcode)\b/)) {
    suggestions.push('gdb', 'python3-pwntools', 'radare2');
  }
  if (lowerDesc.match(/\b(debug|breakpoint|trace|strace|ltrace)\b/)) {
    suggestions.push('gdb', 'strace', 'ltrace');
  }
  
  // Crypto - comprehensive
  if (lowerDesc.match(/\b(hash|md5|sha|crack|password|rainbow)\b/)) {
    suggestions.push('hashcat', 'john', 'python3');
  }
  if (lowerDesc.match(/\b(encrypt|decrypt|cipher|crypto|aes|rsa|des)\b/)) {
    suggestions.push('openssl', 'python3', 'hashcat');
  }
  if (lowerDesc.match(/\b(base64|encode|decode|obfuscat)\b/)) {
    suggestions.push('python3', 'curl');
  }
  
  // Exploitation frameworks
  if (lowerDesc.match(/\b(metasploit|msfconsole|exploit|payload|meterpreter)\b/)) {
    suggestions.push('metasploit-framework', 'nmap', 'netcat');
  }
  if (lowerDesc.match(/\b(eternal.*blue|smb|ms17|vulnerability|cve)\b/)) {
    suggestions.push('metasploit-framework', 'nmap', 'python3');
  }
  
  // Always include essentials
  suggestions.push('python3', 'curl', 'wget', 'git', 'nano');
  
  return [...new Set(suggestions)];
}

/**
 * Detect challenge categories from description
 * Analyzes description to determine if challenge spans multiple categories
 * @param {string} description - Challenge description
 * @returns {Array<string>} Array of detected categories
 */
export function detectCategories(description) {
  const categories = new Set();
  const lowerDesc = description.toLowerCase();
  
  // Web category detection
  if (lowerDesc.match(/\b(web|http|sql|xss|ssrf|xxe|api|rest|upload|wordpress|cms|injection|csrf)\b/)) {
    categories.add('web');
  }
  
  // Network category detection
  if (lowerDesc.match(/\b(network|port|scan|nmap|packet|ftp|ssh|telnet|smb|service|banner|tcp|udp)\b/)) {
    categories.add('network');
  }
  
  // Forensics category removed
  
  // PWN category detection
  if (lowerDesc.match(/\b(pwn|binary|exploit|overflow|buffer|shellcode|rop|executable|elf)\b/)) {
    categories.add('pwn');
  }
  
  // Crypto category detection
  if (lowerDesc.match(/\b(crypto|hash|encrypt|decrypt|cipher|aes|rsa|des|md5|sha|base64)\b/)) {
    categories.add('crypto');
  }
  
  // Reverse engineering category detection
  if (lowerDesc.match(/\b(reverse|disassem|decompil|assembly|asm|ghidra|radare|ida)\b/)) {
    categories.add('reverse');
  }
  
  // Default to misc if no categories detected or as fallback
  if (categories.size === 0) {
    categories.add('misc');
  }
  
  return Array.from(categories);
}
