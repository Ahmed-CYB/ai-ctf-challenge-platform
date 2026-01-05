/**
 * Dockerfile Generator - Generates perfect Dockerfiles
 * 
 * Responsibilities:
 * - Generate Dockerfiles using proven templates
 * - Resolve package names correctly per OS
 * - Ensure syntax correctness
 * - Include complete setup commands
 */

import { Logger } from '../core/logger.js';
import { linuxOnlyValidator } from '../core/linux-only-validator.js';
import { getOSImageInfo } from '../os-image-validator.js';
import { getPackageMapping } from '../package-mapping-db-manager.js';

export class DockerfileGenerator {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Generate Dockerfiles for all machines
   */
  async generate(structure) {
    try {
      this.logger.info('DockerfileGenerator', 'Generating Dockerfiles', { 
        machineCount: structure.machines.length 
      });

      // 🔥 NEW: Check if Vulhub template is available
      const vulhubTemplate = structure.vulhubTemplate || null;
      if (vulhubTemplate) {
        this.logger.info('DockerfileGenerator', 'Using Vulhub template', {
          name: vulhubTemplate.originalVulhub?.name
        });
      }

      const dockerfiles = [];

      for (const machine of structure.machines) {
        // 🔒 CRITICAL: Validate machine OS is Linux-based before generating Dockerfile
        if (linuxOnlyValidator.isWindowsOS(machine.os)) {
          this.logger.error('DockerfileGenerator', 'Windows OS detected in machine', {
            machine: machine.name,
            os: machine.os
          });
          throw new Error(
            `Machine "${machine.name}" has Windows OS: "${machine.os}". ` +
            `Only Linux-based OS are supported (e.g., ubuntu:22.04, rockylinux:9, alpine:latest, kalilinux/kali-rolling:latest)`
          );
        }

        // 🔥 NEW: Use Vulhub template for victim machines if available
        let dockerfile;
        if (machine.role === 'victim' && vulhubTemplate && vulhubTemplate.dockerfile) {
          this.logger.info('DockerfileGenerator', 'Using Vulhub Dockerfile template', { machine: machine.name });
          dockerfile = await this.adaptVulhubDockerfile(vulhubTemplate.dockerfile, machine, structure, vulhubTemplate);
        } else {
          dockerfile = await this.generateForMachine(machine, structure);
        }
        
        // 🔒 CRITICAL: Validate generated Dockerfile for Windows content
        const dockerfileValidation = linuxOnlyValidator.validateDockerfile(dockerfile.content);
        if (!dockerfileValidation.valid) {
          this.logger.error('DockerfileGenerator', 'Windows content detected in Dockerfile', {
            machine: machine.name,
            errors: dockerfileValidation.errors
          });
          throw new Error(
            `Dockerfile for machine "${machine.name}" contains Windows-specific content: ` +
            dockerfileValidation.errors.join('; ')
          );
        }

        dockerfiles.push({
          machineName: machine.name,
          dockerfile: dockerfile.content,
          path: dockerfile.path
        });
      }

      this.logger.success('DockerfileGenerator', 'Dockerfiles generated', { 
        count: dockerfiles.length 
      });

      return {
        success: true,
        data: dockerfiles
      };

    } catch (error) {
      this.logger.error('DockerfileGenerator', 'Generation failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Generate Dockerfile for a single machine
   */
  async generateForMachine(machine, structure) {
    // Get OS info
    const osInfo = await getOSImageInfo(machine.os);
    const packageManager = osInfo.manager || osInfo.packageManager;

    // Build Dockerfile based on role
    if (machine.role === 'attacker') {
      // Use dynamic tool allocation if available
      if (structure.attackerTools && structure.attackerTools.length > 0) {
        return await this.generateAttackerDockerfileDynamic(machine, osInfo, structure);
      }
      // Fallback to static template
      return await this.generateAttackerDockerfile(machine, osInfo);
    } else {
      return await this.generateVictimDockerfile(machine, osInfo, structure);
    }
  }

  /**
   * Generate attacker Dockerfile with dynamic tools
   */
  async generateAttackerDockerfileDynamic(machine, osInfo, structure) {
    try {
      const { generateToolInstallationDockerfile } = await import('../agents/tool-installation-agent.js');
      
      // Get categories from structure
      const categories = structure.categories || [];
      const challengeType = structure.type || 'misc';
      const scenario = structure.description || '';
      const requiredTools = structure.attackerTools || [];
      
      this.logger.info('DockerfileGenerator', 'Generating dynamic attacker Dockerfile', {
        category: categories[0] || 'misc',
        toolCount: requiredTools.length
      });
      
      const dockerfileContent = await generateToolInstallationDockerfile({
        category: categories[0] || 'misc',
        challengeType,
        scenario,
        requiredTools
      });
      
      return {
        content: dockerfileContent,
        path: `${machine.name}/Dockerfile`
      };
    } catch (error) {
      this.logger.warn('DockerfileGenerator', 'Dynamic tool allocation failed, using static template', {
        error: error.message
      });
      // Fallback to static template
      return await this.generateAttackerDockerfile(machine, osInfo);
    }
  }

  /**
   * Generate attacker Dockerfile (static template - fallback)
   */
  async generateAttackerDockerfile(machine, osInfo) {
    const os = osInfo.image || osInfo.os || machine.os;
    const packageManager = osInfo.manager || osInfo.packageManager;

    // Attacker always uses Kali Linux
    const dockerfile = `FROM kalilinux/kali-rolling:latest

# Update and install tools
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\
    openssh-server \\
    sudo \\
    vim \\
    nano \\
    curl \\
    wget \\
    git \\
    net-tools \\
    nmap \\
    wireshark-common \\
    tcpdump \\
    && apt-get clean \\
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Configure nmap for unprivileged mode
RUN echo '#!/bin/bash\\n/usr/bin/nmap --unprivileged "$@"' > /usr/local/bin/nmap && \\
    chmod +x /usr/local/bin/nmap

# Suppress systemd metadata
RUN touch ~/.hushlogin && \\
    echo 'export PS1="\\u@\\h:\\w\\$ "' >> ~/.bashrc && \\
    echo 'export TERM=xterm' >> ~/.bashrc

# 🔒 SECURITY: Install iptables for network isolation
RUN apt-get update && \\
    apt-get install -y --no-install-recommends iptables && \\
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 🔒 SECURITY: Create network isolation script to block gateway and infrastructure access
# IMPORTANT: Allows SSH INPUT for Guacamole access via challenge network
RUN echo '#!/bin/bash' > /usr/local/bin/secure-network.sh && \\
    echo 'set +e' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Flush existing rules' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F OUTPUT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F INPUT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -F FORWARD || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Set default policies' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P INPUT ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P FORWARD ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -P OUTPUT ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow loopback' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -i lo -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -o lo -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow established and related connections' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
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
    echo '  iptables -A OUTPUT -d $GATEWAY -p udp --dport 53 -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo '  iptables -A OUTPUT -d $GATEWAY -j DROP || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'fi' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Block infrastructure networks (OUTPUT only - allow INPUT for SSH from Guacamole)' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "🔒 Blocking infrastructure networks (OUTPUT only)"' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.20.0.0/16 -j DROP || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d 172.21.0.0/16 -j DROP || true' >> /usr/local/bin/secure-network.sh && \\
    echo '# NOTE: Guacamole (guacd) connects to challenge network, not 172.22.0.0/16' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow SSH from any source (for Guacamole access via challenge network)' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo '# Allow all traffic within challenge network' >> /usr/local/bin/secure-network.sh && \\
    echo 'MY_IP=$(hostname -I | awk '"'"'{print $1}'"'"')' >> /usr/local/bin/secure-network.sh && \\
    echo 'NETWORK=$(echo $MY_IP | cut -d. -f1-3).0/24' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A OUTPUT -d $NETWORK -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo 'iptables -A INPUT -s $NETWORK -j ACCEPT || true' >> /usr/local/bin/secure-network.sh && \\
    echo '' >> /usr/local/bin/secure-network.sh && \\
    echo 'echo "✅ Network isolation rules applied (Guacamole SSH access allowed)"' >> /usr/local/bin/secure-network.sh && \\
    chmod +x /usr/local/bin/secure-network.sh

EXPOSE 22

# 🔒 SECURITY: Apply network isolation on container start
RUN echo '#!/bin/bash' > /start-secure.sh && \\
    echo 'set +e' >> /start-secure.sh && \\
    echo '' >> /start-secure.sh && \\
    echo '# Apply network isolation rules (non-blocking)' >> /start-secure.sh && \\
    echo '/usr/local/bin/secure-network.sh || echo "⚠️  Network isolation failed, continuing anyway..."' >> /start-secure.sh && \\
    echo '' >> /start-secure.sh && \\
    echo '# Start SSH daemon' >> /start-secure.sh && \\
    echo 'exec /usr/sbin/sshd -D' >> /start-secure.sh && \\
    chmod +x /start-secure.sh

CMD ["/start-secure.sh"]
`;

    return {
      content: dockerfile,
      path: `${machine.name}/Dockerfile`
    };
  }

  /**
   * Generate victim Dockerfile
   */
  async generateVictimDockerfile(machine, osInfo, structure) {
    const os = osInfo.image || osInfo.os || machine.os;
    const packageManager = osInfo.manager || osInfo.packageManager;

    // Ensure services array exists and is not empty
    if (!machine.services || machine.services.length === 0) {
      this.logger.warn('DockerfileGenerator', 'No services specified for victim machine, adding SSH as default', {
        machineName: machine.name
      });
      machine.services = ['ssh'];
    }

    // Resolve packages for this OS
    const packages = await this.resolvePackages(machine.services, packageManager, os);

    // Build install command based on package manager
    const installCommand = this.buildInstallCommand(packages, packageManager);

    // Build setup script
    const setupScript = this.buildSetupScript(machine, structure);

    // Generate Dockerfile
    const dockerfile = this.buildDockerfileTemplate({
      os,
      packageManager,
      installCommand,
      setupScript,
      machine,
      exposePorts: this.getExposePorts(machine.services)
    });

    return {
      content: dockerfile,
      path: `${machine.name}/Dockerfile`
    };
  }

  /**
   * Resolve package names for specific OS
   */
  async resolvePackages(services, packageManager, os) {
    const packages = new Set();

    // Base tools
    packages.add('openssh-server');
    packages.add('sudo');
    packages.add('net-tools');

    // Service-specific packages
    for (const service of services) {
      const servicePackages = this.getServicePackages(service, packageManager);
      servicePackages.forEach(pkg => packages.add(pkg));
    }

    // Resolve package names
    const resolvedPackages = [];
    for (const pkg of packages) {
      const resolved = await getPackageMapping(pkg, packageManager, os);
      resolvedPackages.push(resolved || pkg);
    }

    return resolvedPackages;
  }

  /**
   * Get packages for a service
   */
  getServicePackages(service, packageManager) {
    const servicePackageMap = {
      'ftp': ['vsftpd'],
      'samba': ['samba'],
      'ssh': ['openssh-server'],
      'http': packageManager === 'apk' ? ['apache2'] : ['apache2'],
      'mysql': packageManager === 'apk' ? ['mariadb'] : ['mariadb-server'],
      'postgresql': ['postgresql']
    };

    return servicePackageMap[service.toLowerCase()] || [];
  }

  /**
   * Build install command
   */
  buildInstallCommand(packages, packageManager) {
    const packageList = packages.join(' ');

    switch (packageManager) {
      case 'apt-get':
        return `RUN apt-get update && \\
    apt-get install -y --no-install-recommends ${packageList} && \\
    apt-get clean && \\
    rm -rf /var/lib/apt/lists/*`;

      case 'dnf':
      case 'yum':
        return `RUN dnf install -y --setopt=install_weak_deps=False ${packageList} && \\
    dnf clean all`;

      case 'apk':
        return `RUN apk add --no-cache ${packageList}`;

      case 'pacman':
        return `RUN pacman -Sy --noconfirm ${packageList} && \\
    pacman -Scc --noconfirm`;

      default:
        throw new Error(`Unsupported package manager: ${packageManager}`);
    }
  }

  /**
   * Build setup script
   */
  buildSetupScript(machine, structure) {
    // This will be enhanced with AI-generated setup commands
    // For now, create a basic script
    let script = '#!/bin/bash\n';
    script += 'set -e\n\n';

    // Add service-specific setup
    for (const service of machine.services) {
      script += this.getServiceSetup(service, machine);
    }

    // Add SSH setup
    script += this.getSSHSetup();

    // Keep container running
    script += '\n# Keep container running\n';
    script += 'wait\n';

    return script;
  }

  /**
   * Get service-specific setup
   */
  getServiceSetup(service, machine) {
    const serviceLower = service.toLowerCase();

    if (serviceLower === 'ftp') {
      return `# FTP Service Setup
# Create FTP user if it doesn't exist (required for chown)
useradd -r -s /bin/false -d /var/ftp ftp 2>/dev/null || true
if [ -f /challenge/vsftpd.conf ]; then
  cp /challenge/vsftpd.conf /etc/vsftpd.conf
fi
mkdir -p /var/run/vsftpd/empty /var/ftp/data/classified
chmod 555 /var/ftp
chmod 755 /var/ftp/data /var/ftp/data/classified
if [ -f /challenge/flag.txt ]; then
  cp /challenge/flag.txt /var/ftp/data/classified/flag.txt
  chmod 644 /var/ftp/data/classified/flag.txt
  chown ftp:ftp /var/ftp/data/classified/flag.txt 2>/dev/null || chown root:root /var/ftp/data/classified/flag.txt
fi
/usr/sbin/vsftpd /etc/vsftpd.conf &
`;

    } else if (serviceLower === 'samba' || serviceLower === 'smb') {
      return `# Samba Service Setup
mkdir -p /var/lib/samba/private /var/run/samba
if [ -f /challenge/smb.conf ]; then
  cp /challenge/smb.conf /etc/samba/smb.conf
else
  # Create basic Samba config if not provided
  mkdir -p /etc/samba
  cat > /etc/samba/smb.conf << 'EOF'
[global]
workgroup = WORKGROUP
server string = Samba Server
security = user
map to guest = Bad User
guest ok = yes
guest account = nobody

[share]
path = /tmp/share
browseable = yes
writable = yes
guest ok = yes
EOF
fi
mkdir -p /tmp/share
chmod 777 /tmp/share
/usr/sbin/smbd -D &
/usr/sbin/nmbd -D &
`;

    } else if (serviceLower === 'http') {
      return `# HTTP Service Setup
if [ -f /challenge/apache2.conf ]; then
  cp /challenge/apache2.conf /etc/apache2/apache2.conf
fi
/usr/sbin/apache2ctl -D FOREGROUND &
`;

    }

    return '';
  }

  /**
   * Get SSH setup
   */
  getSSHSetup() {
    return `# SSH Service Setup
mkdir -p /var/run/sshd
/usr/sbin/sshd -D &
`;
  }

  /**
   * Get expose ports for services
   */
  getExposePorts(services) {
    const portMap = {
      'ftp': 21,
      'ssh': 22,
      'http': 80,
      'https': 443,
      'samba': 445,
      'mysql': 3306,
      'postgresql': 5432
    };

    const ports = services.map(s => portMap[s.toLowerCase()]).filter(Boolean);
    return ports.length > 0 ? ports.join(' ') : '22';
  }

  /**
   * Build Dockerfile template
   */
  buildDockerfileTemplate({ os, packageManager, installCommand, setupScript, machine, exposePorts }) {
    // Convert script to echo commands (most reliable method)
    // Split script into lines and escape for echo
    const scriptLines = setupScript.split('\n');
    
    // Build echo commands for each line
    const echoCommands = scriptLines
      .map(line => {
        // Escape single quotes and backslashes for echo
        const escaped = line
          .replace(/\\/g, '\\\\')
          .replace(/'/g, "'\\''");
        return `echo '${escaped}' >> /start-services.sh`;
      })
      .join(' && \\\n    ');

    return `FROM ${os}

# Update and install packages
${installCommand}

# Configure SSH
${this.getSSHConfig(packageManager)}

${machine.services && machine.services.some(s => s.toLowerCase() === 'ftp') ? '# Create FTP user if FTP service is present (required for chown commands)\nRUN useradd -r -s /bin/false -d /var/ftp ftp 2>/dev/null || true\n' : ''}
# Create challenge directory
RUN mkdir -p /challenge && chmod 755 /challenge

# Copy challenge files
COPY . /challenge/

# Create startup script using echo (most reliable method, avoids heredoc issues)
RUN echo '#!/bin/bash' > /start-services.sh && \\
    ${echoCommands} && \\
    chmod +x /start-services.sh && \\
    test -f /start-services.sh || (echo "ERROR: Failed to create /start-services.sh" && exit 1)

EXPOSE ${exposePorts}
CMD ["/start-services.sh"]
`;
  }

  /**
   * Get SSH configuration based on package manager
   */
  getSSHConfig(packageManager) {
    if (packageManager === 'apk' || packageManager === 'pacman') {
      return `RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config`;
    } else {
      return `RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali 2>/dev/null || true && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali 2>/dev/null || true && \\
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config`;
    }
  }

  /**
   * Adapt Vulhub Dockerfile for CTF challenge
   * Ensures flag placement, Guacamole compatibility, and user requirements
   */
  async adaptVulhubDockerfile(vulhubDockerfile, machine, structure, vulhubTemplate) {
    try {
      // Get flag location from template or use default
      const flagLocation = vulhubTemplate.flagLocation || this.getDefaultFlagLocation(machine.services);
      const flag = vulhubTemplate.flag || `CTF{${structure.name || 'challenge'}_${Date.now()}}`;

      // Ensure flag is added to Dockerfile
      let adaptedDockerfile = vulhubDockerfile;

      // Add flag if not already present
      if (!adaptedDockerfile.includes('flag') && !adaptedDockerfile.includes('FLAG')) {
        // Find a good place to add flag (after COPY commands, before CMD)
        const lines = adaptedDockerfile.split('\n');
        let insertIndex = lines.length - 1;
        
        // Find last RUN or COPY command
        for (let i = lines.length - 1; i >= 0; i--) {
          if (lines[i].trim().startsWith('RUN') || lines[i].trim().startsWith('COPY')) {
            insertIndex = i + 1;
            break;
          }
        }

        // Insert flag creation
        const flagDir = flagLocation.substring(0, flagLocation.lastIndexOf('/'));
        lines.splice(insertIndex, 0, 
          `# CTF Flag`,
          `RUN mkdir -p ${flagDir} && echo "${flag}" > ${flagLocation} && chmod 644 ${flagLocation}`
        );
        adaptedDockerfile = lines.join('\n');
      }

      // Ensure SSH is configured for attacker machines (for Guacamole)
      if (machine.role === 'attacker' && !adaptedDockerfile.includes('sshd')) {
        // Add SSH setup if missing
        const sshSetup = `
# Configure SSH for Guacamole access
RUN mkdir -p /var/run/sshd && \\
    echo 'root:toor' | chpasswd && \\
    useradd -m -s /bin/bash kali 2>/dev/null || true && \\
    echo 'kali:kali' | chpasswd && \\
    usermod -aG sudo kali 2>/dev/null || true && \\
    sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \\
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || \\
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

EXPOSE 22
`;
        
        // Insert before CMD
        adaptedDockerfile = adaptedDockerfile.replace(/(CMD|ENTRYPOINT)/, `${sshSetup}\n$1`);
      }

      return {
        content: adaptedDockerfile,
        path: `${machine.name}/Dockerfile`
      };

    } catch (error) {
      this.logger.error('DockerfileGenerator', 'Failed to adapt Vulhub Dockerfile', error.stack);
      // Fallback to regular generation
      return await this.generateForMachine(machine, structure);
    }
  }

  /**
   * Get default flag location based on services
   */
  getDefaultFlagLocation(services) {
    if (!services || services.length === 0) {
      return '/root/flag.txt';
    }

    const service = services[0].toLowerCase();
    const locations = {
      'ftp': '/var/ftp/data/flag.txt',
      'samba': '/tmp/share/flag.txt',
      'smb': '/tmp/share/flag.txt',
      'http': '/var/www/html/flag.txt',
      'web': '/var/www/html/flag.txt',
      'ssh': '/root/flag.txt'
    };

    return locations[service] || '/root/flag.txt';
  }
}


