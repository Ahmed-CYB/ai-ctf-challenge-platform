import Docker from 'dockerode';
import { subnetAllocator } from './subnet-allocator.js';
import { portManager } from './port-manager.js';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs/promises';
import yaml from 'js-yaml';

dotenv.config();

const DEFAULT_CTF_PORT = process.env.DEFAULT_CTF_PORT || '8080';
const KALI_VNC_PORT = '6901';

export class DockerManager {
  constructor() {
    this.docker = new Docker();
  }

  async buildImage(challengePath, imageName) {
    try {
      console.log(`Building Docker image: ${imageName}`);
      console.log(`Build context: ${challengePath}`);

      const stream = await this.docker.buildImage(
        {
          context: challengePath,
          src: ['Dockerfile', '.']
        },
        {
          t: imageName
        }
      );

      // Wait for build to complete
      await new Promise((resolve, reject) => {
        this.docker.modem.followProgress(
          stream,
          (err, result) => (err ? reject(err) : resolve(result)),
          (event) => {
            if (event.stream) {
              process.stdout.write(event.stream);
            }
          }
        );
      });

      console.log(`Successfully built image: ${imageName}`);
      return true;
    } catch (error) {
      console.error('Error building image:', error);
      throw new Error(`Failed to build Docker image: ${error.message}`);
    }
  }

  /**
   * @deprecated This method uses port mappings. Use deployFromCompose() with private IPs instead.
   * Runs a single container with port mapping (OLD METHOD - NOT RECOMMENDED)
   */
  async runContainer(imageName, containerName) {
    try {
      console.log(`Running container: ${containerName}`);

      // Find a random available port between 8080-65535
      const findAvailablePort = async (minPort = 8080, maxPort = 65535, maxAttempts = 100) => {
        const net = await import('net');
        
        const getRandomPort = () => {
          return Math.floor(Math.random() * (maxPort - minPort + 1)) + minPort;
        };
        
        const testPort = (port) => {
          return new Promise((resolve) => {
            const server = net.createServer();
            server.listen(port, () => {
              const assignedPort = server.address().port;
              server.close(() => resolve(assignedPort));
            });
            server.on('error', () => {
              resolve(null); // Port is not available
            });
          });
        };
        
        // Try random ports until we find an available one
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          const randomPort = getRandomPort();
          const availablePort = await testPort(randomPort);
          if (availablePort !== null) {
            return availablePort;
          }
        }
        
        // Fallback: if random didn't work, try sequential from 8080
        throw new Error('Could not find available port after maximum attempts');
      };

      const availablePort = await findAvailablePort();
      console.log(`Using host port: ${availablePort}`);

      // Create and start container with specific port
      const container = await this.docker.createContainer({
        Image: imageName,
        name: containerName,
        ExposedPorts: {
          [`${DEFAULT_CTF_PORT}/tcp`]: {}
        },
        HostConfig: {
          PortBindings: {
            [`${DEFAULT_CTF_PORT}/tcp`]: [{ HostPort: availablePort.toString() }]
          }
        }
      });

      await container.start();
      console.log(`Container ${containerName} started successfully`);

      const hostPort = availablePort.toString();
      console.log(`Container accessible at: http://localhost:${hostPort}`);

      return {
        containerId: container.id,
        containerName,
        hostPort,
        containerPort: DEFAULT_CTF_PORT,
        url: `http://localhost:${hostPort}`
      };
    } catch (error) {
      console.error('Error running container:', error);
      throw new Error(`Failed to run container: ${error.message}`);
    }
  }

  async stopContainer(containerName) {
    try {
      const container = this.docker.getContainer(containerName);
      await container.stop();
      console.log(`Stopped container: ${containerName}`);
      return true;
    } catch (error) {
      console.error('Error stopping container:', error);
      throw new Error(`Failed to stop container: ${error.message}`);
    }
  }

  async removeContainer(containerName) {
    try {
      const container = this.docker.getContainer(containerName);
      await container.remove({ force: true });
      console.log(`Removed container: ${containerName}`);
      return true;
    } catch (error) {
      console.error('Error removing container:', error);
      throw new Error(`Failed to remove container: ${error.message}`);
    }
  }

  async getContainerInfo(containerName) {
    try {
      const container = this.docker.getContainer(containerName);
      const info = await container.inspect();
      
      const hostPort = info.NetworkSettings.Ports[`${DEFAULT_CTF_PORT}/tcp`]?.[0]?.HostPort;
      
      return {
        id: info.Id,
        name: info.Name.replace('/', ''),
        status: info.State.Status,
        running: info.State.Running,
        hostPort,
        url: hostPort ? `http://localhost:${hostPort}` : null
      };
    } catch (error) {
      console.error('Error getting container info:', error);
      return null;
    }
  }

  async listRunningContainers() {
    try {
      const containers = await this.docker.listContainers();
      return containers.map(container => ({
        id: container.Id,
        name: container.Names[0].replace('/', ''),
        image: container.Image,
        status: container.Status,
        ports: container.Ports
      }));
    } catch (error) {
      console.error('Error listing containers:', error);
      throw new Error(`Failed to list containers: ${error.message}`);
    }
  }

  /**
   * Check if challenge is already deployed
   * IMPROVEMENT: Check for running containers before deploying
   * @param {string} challengeName - Challenge name to check
   * @returns {Promise<{isDeployed: boolean, containers: Array}>}
   */
  async isChallengeDeployed(challengeName) {
    try {
      const containers = await this.docker.listContainers({ all: false }); // Only running containers
      const challengeContainers = containers.filter(container => {
        const name = container.Names[0]?.replace('/', '') || '';
        return name.includes(`ctf-${challengeName}-`) || name.includes(`${challengeName}-`);
      });

      return {
        isDeployed: challengeContainers.length > 0,
        containers: challengeContainers.map(c => ({
          id: c.Id,
          name: c.Names[0]?.replace('/', '') || '',
          image: c.Image,
          status: c.Status
        }))
      };
    } catch (error) {
      console.error('Error checking deployment status:', error);
      // Return false on error to allow deployment to proceed
      return { isDeployed: false, containers: [], error: error.message };
    }
  }

  async deployMultiContainer(challengeName, progressCallback = null) {
    try {
      console.log(`\n🚀 Deploying multi-container setup for: ${challengeName}`);
      if (progressCallback) progressCallback({ step: 'docker-start', message: '🐳 Setting up Docker environment...' });

      // Read docker-compose.yml from challenge directory
      const CLONE_PATH = process.env.CLONE_PATH || path.join(process.cwd(), 'challenges-repo');
      const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
      const composeFilePath = path.join(challengePath, 'docker-compose.yml');

      // Check if docker-compose.yml exists
      try {
        await fs.access(composeFilePath);
      } catch (error) {
        console.log('⚠️  No docker-compose.yml found, creating one...');
        await this.generateDockerCompose(challengePath, challengeName);
      }

      // Parse docker-compose.yml
      const composeContent = await fs.readFile(composeFilePath, 'utf8');
      const composeConfig = yaml.load(composeContent);

      // Create network
      const networkName = `ctf-${challengeName}-network`;
      await this.createNetwork(networkName);

      // Find available ports
      const findAvailablePort = async (minPort = 8080, maxPort = 65535, maxAttempts = 100) => {
        const net = await import('net');
        const getRandomPort = () => Math.floor(Math.random() * (maxPort - minPort + 1)) + minPort;
        const testPort = (port) => {
          return new Promise((resolve) => {
            const server = net.createServer();
            server.listen(port, () => {
              const assignedPort = server.address().port;
              server.close(() => resolve(assignedPort));
            });
            server.on('error', () => resolve(null));
          });
        };
        for (let attempt = 0; attempt < maxAttempts; attempt++) {
          const randomPort = getRandomPort();
          const availablePort = await testPort(randomPort);
          if (availablePort !== null) return availablePort;
        }
        throw new Error('Could not find available port');
      };

      const victimPort = await findAvailablePort();
      const attackerPort = await findAvailablePort(victimPort + 1); // Start search after victim port

      console.log(`📦 Victim port: ${victimPort}`);
      console.log(`🥷 Attacker (Kali) port: ${attackerPort}`);
      if (progressCallback) progressCallback({ step: 'ports-assigned', message: `  📌 Assigned ports - Victim: ${victimPort}, Kali: ${attackerPort}` });

      // Deploy victim container
      const victimContainerName = `ctf-${challengeName}-victim`;
      const victimImageName = `ctf-${challengeName}:latest`;

      // Build victim image
      if (progressCallback) progressCallback({ step: 'build-victim', message: '  🔨 Building victim Docker image...' });
      await this.buildImage(challengePath, victimImageName);

      // Run victim container
      const victimContainer = await this.docker.createContainer({
        Image: victimImageName,
        name: victimContainerName,
        Hostname: 'victim',
        ExposedPorts: {
          [`${DEFAULT_CTF_PORT}/tcp`]: {}
        },
        HostConfig: {
          PortBindings: {
            [`${DEFAULT_CTF_PORT}/tcp`]: [{ HostPort: victimPort.toString() }]
          },
          NetworkMode: networkName
        }
      });

      await victimContainer.start();
      console.log(`✅ Victim container started: ${victimContainerName}`);
      if (progressCallback) progressCallback({ step: 'victim-started', message: `  ✅ Victim container started` });

      // Deploy attacker (Kali Linux) container
      const attackerContainerName = `ctf-${challengeName}-attacker`;
      const kaliImage = 'kasmweb/kali-rolling-desktop:1.15.0'; // Kali Linux with web-based VNC

      console.log(`🥷 Pulling Kali Linux image (this may take a while on first run)...`);
      if (progressCallback) progressCallback({ step: 'kali-pull', message: '  🥷 Pulling Kali Linux image (~2GB, first time only)...' });
      
      // Pull Kali image if not exists
      try {
        await this.docker.getImage(kaliImage).inspect();
        console.log(`✓ Kali image already exists`);
      } catch (error) {
        console.log(`📥 Pulling Kali image...`);
        await this.pullImage(kaliImage);
      }

      // Run attacker container
      const attackerContainer = await this.docker.createContainer({
        Image: kaliImage,
        name: attackerContainerName,
        Hostname: 'attacker',
        ExposedPorts: {
          '6901/tcp': {},
          '6902/tcp': {}
        },
        Env: [
          'VNC_PW=password',
          'KASM_PORT=6901',
          `VNC_PORT=${attackerPort}`
        ],
        HostConfig: {
          PortBindings: {
            '6901/tcp': [{ HostIp: '0.0.0.0', HostPort: attackerPort.toString() }]
          },
          NetworkMode: networkName,
          ShmSize: 536870912, // 512MB shared memory for GUI
          Privileged: false
        }
      });

      await attackerContainer.start();
      console.log(`✅ Attacker container started: ${attackerContainerName}`);
      if (progressCallback) progressCallback({ step: 'kali-started', message: `  ✅ Kali Linux container started` });

      return {
        victimUrl: `http://localhost:${victimPort}`,
        attackerUrl: `http://localhost:${attackerPort}`, // Kali uses HTTP for VNC on port 6901
        victimContainerName,
        attackerContainerName,
        victimPort,
        attackerPort,
        networkName,
        victimContainerId: victimContainer.id,
        attackerContainerId: attackerContainer.id
      };

    } catch (error) {
      console.error('Error deploying multi-container setup:', error);
      throw new Error(`Failed to deploy multi-container: ${error.message}`);
    }
  }

  async createNetwork(networkName) {
    try {
      // Check if network already exists
      const networks = await this.docker.listNetworks({ filters: { name: [networkName] } });
      
      if (networks.length > 0) {
        console.log(`✓ Network already exists: ${networkName}`);
        return networks[0];
      }

      // Create new network without specifying subnet (let Docker handle it)
      const network = await this.docker.createNetwork({
        Name: networkName,
        Driver: 'bridge',
        EnableIPv6: false
      });

      console.log(`✅ Created network: ${networkName}`);
      return network;
    } catch (error) {
      console.error('Error creating network:', error);
      throw new Error(`Failed to create network: ${error.message}`);
    }
  }

  async getNetworkInfo(networkName) {
    try {
      const networks = await this.docker.listNetworks({ filters: { name: [networkName] } });
      if (networks.length === 0) return null;

      const network = this.docker.getNetwork(networks[0].Id);
      const info = await network.inspect();
      
      return {
        id: info.Id,
        name: info.Name,
        driver: info.Driver,
        containers: info.Containers || {}
      };
    } catch (error) {
      console.error('Error getting network info:', error);
      return null;
    }
  }

  async pullImage(imageName) {
    try {
      const stream = await this.docker.pull(imageName);
      
      await new Promise((resolve, reject) => {
        this.docker.modem.followProgress(
          stream,
          (err, result) => (err ? reject(err) : resolve(result)),
          (event) => {
            if (event.status) {
              process.stdout.write(`\r  ${event.status}${event.progress || ''}`);
            }
          }
        );
      });
      
      console.log(`\n✅ Image pulled: ${imageName}`);
      return true;
    } catch (error) {
      console.error('Error pulling image:', error);
      throw new Error(`Failed to pull image: ${error.message}`);
    }
  }

  /**
   * Deploy multi-container challenge using 'docker compose up --build' command
   * This is the PREFERRED method - same as the insecure-ftp-server example
   */
  async deployFromCompose(challengeName, userId = 'default', progressCallback = null) {
    try {
      console.log(`\n🚀 Deploying from docker-compose.yml for: ${challengeName}`);
      if (progressCallback) progressCallback({ step: 'compose-start', message: '🐳 Using docker compose up --build...' });

      // Read docker-compose.yml from challenge directory
      const CLONE_PATH = process.env.CLONE_PATH || path.join(process.cwd(), 'challenges-repo');
      const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
      const composeFilePath = path.join(challengePath, 'docker-compose.yml');

      // Check if docker-compose.yml exists
      try {
        await fs.access(composeFilePath);
      } catch (error) {
        console.log('⚠️  No docker-compose.yml found, cannot deploy');
        throw new Error(`docker-compose.yml not found at ${composeFilePath}`);
      }

      console.log(`📋 Using docker-compose.yml at: ${composeFilePath}`);
      
      if (progressCallback) {
        progressCallback({ 
          step: 'docker-compose-start', 
          message: '🚀 Running docker compose up --build...' 
        });
      }

      // Import child_process for running shell commands
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execPromise = promisify(exec);

      // ✅ FIX: Disconnect guacd from any existing challenge networks before deployment
      // This prevents "network has active endpoints" errors when docker compose tries to remove/recreate networks
      try {
        const guacdContainer = this.docker.getContainer('ctf-guacd-new');
        const guacdInfo = await guacdContainer.inspect();
        const connectedNetworks = Object.keys(guacdInfo.NetworkSettings.Networks || {});
        
        // Find challenge-specific networks (not ctf-instances-network)
        // Docker Compose creates networks with pattern: {directory}_{network-name}
        // Example: corporate-data-breach-investigation_ctf-corporate-data-breach-investigation-net
        const challengeNameVariants = [
          challengeName,
          challengeName.replace(/-/g, '_'),
          challengeName.toLowerCase(),
          challengeName.toLowerCase().replace(/-/g, '_'),
          `ctf-${challengeName}`,
          `ctf-${challengeName.replace(/-/g, '_')}`,
          `ctf-${challengeName.toLowerCase()}`,
          `ctf-${challengeName.toLowerCase().replace(/-/g, '_')}`
        ];
        
        // Docker Compose network naming: {directory-with-underscores}_{network-name-with-hyphens}
        // Example: corporate-data-breach-investigation → corporate_data_breach_investigation_ctf-corporate-data-breach-investigation-net
        const composeNetworkPrefix = challengeName.replace(/-/g, '_'); // Directory name with underscores
        const composeNetworkSuffix = `ctf-${challengeName}-net`; // Network name with hyphens
        const composeNetworkPattern = `${composeNetworkPrefix}_${composeNetworkSuffix}`;
        
        const challengeNetworks = connectedNetworks.filter(net => {
          if (net === 'ctf-instances-network') return false;
          const netLower = net.toLowerCase();
          // Check for exact Docker Compose pattern match
          if (netLower === composeNetworkPattern.toLowerCase()) return true;
          // Check if network name contains any variant of challenge name
          return challengeNameVariants.some(variant => 
            netLower.includes(variant.toLowerCase())
          );
        });
        
        // Also check all networks that might be related to this challenge
        // Docker Compose creates networks with patterns like: challenge_name_network-name
        const allNetworks = await this.docker.listNetworks();
        const relatedNetworks = allNetworks
          .map(n => n.Name)
          .filter(net => {
            if (net === 'ctf-instances-network') return false;
            const netLower = net.toLowerCase();
            // Check for exact Docker Compose pattern match
            if (netLower === composeNetworkPattern.toLowerCase()) return true;
            // Check for partial match (contains both prefix and suffix)
            if (netLower.includes(composeNetworkPrefix.toLowerCase()) && 
                netLower.includes(composeNetworkSuffix.toLowerCase())) return true;
            // Check for any variant match
            return challengeNameVariants.some(variant => 
              netLower.includes(variant.toLowerCase())
            );
          });
        
        // Combine and deduplicate
        const networksToDisconnect = [...new Set([...challengeNetworks, ...relatedNetworks])];
        
        console.log(`🔍 Found ${networksToDisconnect.length} challenge-related networks to disconnect guacd from:`, networksToDisconnect);
        
        // Disconnect guacd from all challenge-related networks
        for (const networkName of networksToDisconnect) {
          try {
            // Get network by name (not ID)
            const networks = await this.docker.listNetworks({ filters: { name: [networkName] } });
            if (networks.length > 0) {
              const network = this.docker.getNetwork(networks[0].Id);
              await network.disconnect({ Container: 'ctf-guacd-new', Force: false });
              console.log(`🔌 Disconnected guacd from network: ${networkName}`);
            }
          } catch (disconnectError) {
            // Network might not exist or already disconnected - ignore
            if (!disconnectError.message.includes('not connected') && 
                !disconnectError.message.includes('404')) {
              console.log(`⚠️  Could not disconnect guacd from ${networkName}: ${disconnectError.message}`);
            }
          }
        }
      } catch (guacdError) {
        // Guacd container might not exist - continue anyway
        if (!guacdError.message.includes('404')) {
          console.log(`⚠️  Could not check guacd networks: ${guacdError.message}`);
        }
      }

      // Run docker compose up --build with streaming if callback provided
      console.log(`\n🐳 Executing: docker compose up --build -d`);
      console.log(`📂 Working directory: ${challengePath}`);
      
      let stdout = '';
      let stderr = '';
      
      try {
        if (progressCallback) {
          // Use spawn for real-time streaming
          const { spawn } = await import('child_process');
          
          await new Promise((resolve, reject) => {
            const dockerProcess = spawn('docker', ['compose', 'up', '--build', '-d'], {
              cwd: challengePath,
              shell: true
            });

            dockerProcess.stdout.on('data', (data) => {
              const output = data.toString();
              stdout += output;
              process.stdout.write(output);
              progressCallback({ 
                step: 'docker-build', 
                message: output,
                isRealtime: true 
              });
            });

            dockerProcess.stderr.on('data', (data) => {
              const output = data.toString();
              stderr += output;
              process.stderr.write(output);
              progressCallback({ 
                step: 'docker-build', 
                message: output,
                isRealtime: true 
              });
            });

            dockerProcess.on('close', (code) => {
              // ✅ FIX: Handle network removal errors gracefully
              // If the error is about active endpoints (guacd connected), it's not fatal
              // The containers are built and started, we just need to reconnect guacd
              if (code === 0) {
                resolve();
              } else {
                // Check if error is about network removal with active endpoints
                const errorOutput = (stdout + stderr).toLowerCase();
                const isNetworkRemovalError = (
                  errorOutput.includes('active endpoints') && 
                  (errorOutput.includes('network') || errorOutput.includes('removing network')) &&
                  (errorOutput.includes('removed') || errorOutput.includes('removing') || errorOutput.includes('error while removing'))
                ) || (
                  errorOutput.includes('has active endpoints') &&
                  errorOutput.includes('ctf-guacd-new')
                );
                
                if (isNetworkRemovalError) {
                  console.log(`\n⚠️  Network removal warning (guacd connected) - this is expected, continuing...`);
                  console.log(`   Containers are built and running, guacd will be reconnected automatically`);
                  // This is not fatal - containers are built and running
                  // We'll reconnect guacd after deployment
                  resolve(); // Treat as success
                } else {
                  reject(new Error(`Docker compose failed with exit code ${code}`));
                }
              }
            });

            dockerProcess.on('error', reject);
          });
        } else {
          // Fallback to exec without streaming
          const result = await execPromise(
            'docker compose up --build -d',
            { 
              cwd: challengePath,
              maxBuffer: 10 * 1024 * 1024  // 10MB buffer for large outputs
            }
          );
          stdout = result.stdout;
          stderr = result.stderr;
        }
        
        if (stdout && !progressCallback) {
          console.log('\n📋 Docker Compose Output:');
          console.log(stdout);
        }
        
        // ✅ FIX: Check for network removal errors and handle gracefully
        const fullOutput = (stdout + stderr).toLowerCase();
        const isNetworkRemovalError = (
          fullOutput.includes('active endpoints') && 
          (fullOutput.includes('network') || fullOutput.includes('removing network')) &&
          (fullOutput.includes('removed') || fullOutput.includes('removing') || fullOutput.includes('error while removing'))
        ) || (
          fullOutput.includes('has active endpoints') &&
          fullOutput.includes('ctf-guacd-new')
        );
        
        if (isNetworkRemovalError) {
          console.log(`\n⚠️  Network removal warning detected (guacd connected to network)`);
          console.log(`   This is expected - containers are built and running`);
          console.log(`   Guacd will be reconnected to the new network automatically`);
        }
        
        if (stderr && stderr.trim() && !progressCallback && !isNetworkRemovalError) {
          console.log('\n⚠️  Docker Compose Warnings:');
          console.log(stderr);
        }
        
        console.log(`\n✅ Docker compose up completed successfully`);
        
        if (progressCallback) {
          progressCallback({ 
            step: 'docker-compose-complete', 
            message: '✅ Containers built and started' 
          });
        }

        // Read docker-compose.yml to extract IP addresses
        const composeContent = await fs.readFile(composeFilePath, 'utf8');
        const composeConfig = yaml.load(composeContent);
        
        // ✅ FIX: Extract IPs by inspecting actual containers (more reliable than parsing docker-compose.yml)
        // Docker Compose network names differ from docker-compose.yml network names
        const services = composeConfig.services || {};
        let victimIP = null;
        let attackerIP = null;
        let subnet = null;
        
        // ✅ FIX: Get container names - service names ARE container names in docker-compose.yml
        // In universal-structure-agent, container_name is set to serviceName (which is ctf-{challenge}-{machine})
        const attackerServiceName = Object.keys(services).find(name => name.includes('attacker'));
        // Container name is either from container_name field or defaults to service name
        const attackerContainerName = attackerServiceName 
          ? (services[attackerServiceName]?.container_name || attackerServiceName)
          : `ctf-${challengeName}-attacker`;
        
        // ✅ FIX: Find ALL victim services (all non-attacker, non-database services)
        // Service names in docker-compose.yml are: ctf-{challengeName}-{machineName}
        // Container names are the same as service names (set in universal-structure-agent.js)
        const victimServiceNames = Object.keys(services).filter(name => 
          !name.includes('attacker') && !name.includes('database')
        );
        
        // Get first victim service for primary victim IP
        const victimServiceName = victimServiceNames[0];
        // Container name is either from container_name field or defaults to service name
        // In universal-structure-agent.js, container_name is set to serviceName, so they match
        const victimContainerName = victimServiceName
          ? (services[victimServiceName]?.container_name || victimServiceName)
          : `ctf-${challengeName}-victim`;
        
        console.log(`🔍 Victim service names found: ${victimServiceNames.join(', ')}`);
        console.log(`🔍 Using primary victim container: ${victimContainerName}`);
        
        // Get subnet from network config
        const networkNames = Object.keys(composeConfig.networks || {});
        const challengeNetworkName = networkNames.find(name => name !== 'ctf-instances-network');
        if (challengeNetworkName && composeConfig.networks[challengeNetworkName]?.ipam?.config?.[0]) {
          subnet = composeConfig.networks[challengeNetworkName].ipam.config[0].subnet;
        }
        
        // ✅ FIX: Inspect actual containers to get real IPs from challenge network
        try {
          // Get attacker IP from challenge network (not ctf-instances-network)
          const attackerContainer = this.docker.getContainer(attackerContainerName);
          const attackerInfo = await attackerContainer.inspect();
          const attackerNetworks = attackerInfo.NetworkSettings.Networks || {};
          
          // Find challenge network (not ctf-instances-network)
          const attackerChallengeNetwork = Object.keys(attackerNetworks).find(
            net => net !== 'ctf-instances-network'
          );
          if (attackerChallengeNetwork && attackerNetworks[attackerChallengeNetwork]) {
            attackerIP = attackerNetworks[attackerChallengeNetwork].IPAddress;
            console.log(`✅ Attacker IP from container: ${attackerIP} (network: ${attackerChallengeNetwork})`);
          }
        } catch (attackerError) {
          console.warn(`⚠️  Could not inspect attacker container: ${attackerError.message}`);
          // Fallback to docker-compose.yml
          if (attackerServiceName && services[attackerServiceName]?.networks) {
            const networkName = Object.keys(services[attackerServiceName].networks).find(
              net => net !== 'ctf-instances-network'
            );
            if (networkName) {
              attackerIP = services[attackerServiceName].networks[networkName]?.ipv4_address;
            }
          }
        }
        
        try {
          // Get victim IP from challenge network
          const victimContainer = this.docker.getContainer(victimContainerName);
          const victimInfo = await victimContainer.inspect();
          const victimNetworks = victimInfo.NetworkSettings.Networks || {};
          
          // ✅ FIX: Find challenge network (exclude ctf-instances-network if present)
          const victimNetworkName = Object.keys(victimNetworks).find(
            net => net !== 'ctf-instances-network'
          ) || Object.keys(victimNetworks)[0];
          
          if (victimNetworkName && victimNetworks[victimNetworkName]) {
            victimIP = victimNetworks[victimNetworkName].IPAddress;
            console.log(`✅ Victim IP from container: ${victimIP} (network: ${victimNetworkName})`);
          } else {
            console.warn(`⚠️  Victim container found but no IP assigned on network`);
          }
        } catch (victimError) {
          console.warn(`⚠️  Could not inspect victim container "${victimContainerName}": ${victimError.message}`);
          
          // ✅ IMPROVED: Try to find victim container by listing all containers
          try {
            const allContainers = await this.docker.listContainers({ all: true });
            const matchingContainers = allContainers.filter(c => {
              const name = c.Names[0]?.replace('/', '') || '';
              return name.includes(challengeName) && 
                     !name.includes('attacker') && 
                     !name.includes('database');
            });
            
            if (matchingContainers.length > 0) {
              const foundContainerName = matchingContainers[0].Names[0]?.replace('/', '');
              console.log(`🔍 Found victim container via search: ${foundContainerName}`);
              const victimContainer = this.docker.getContainer(foundContainerName);
              const victimInfo = await victimContainer.inspect();
              const victimNetworks = victimInfo.NetworkSettings.Networks || {};
              const victimNetworkName = Object.keys(victimNetworks).find(
                net => net !== 'ctf-instances-network'
              ) || Object.keys(victimNetworks)[0];
              if (victimNetworkName && victimNetworks[victimNetworkName]) {
                victimIP = victimNetworks[victimNetworkName].IPAddress;
                console.log(`✅ Victim IP from found container: ${victimIP} (network: ${victimNetworkName})`);
              }
            }
          } catch (searchError) {
            console.warn(`⚠️  Container search also failed: ${searchError.message}`);
          }
          
          // Fallback to docker-compose.yml
          if (victimServiceName && services[victimServiceName]?.networks) {
            const networkName = Object.keys(services[victimServiceName].networks).find(
              net => net !== 'ctf-instances-network'
            ) || Object.keys(services[victimServiceName].networks)[0];
            if (networkName) {
              victimIP = services[victimServiceName].networks[networkName]?.ipv4_address;
              console.log(`✅ Victim IP from docker-compose.yml: ${victimIP}`);
            }
          }
        }
        
        console.log(`\n✅ Deployment complete!`);
        console.log(`🔒 Isolated subnet: ${subnet || 'default'}`);
        console.log(`📍 Victim IP: ${victimIP || 'unknown'}`);
        console.log(`📍 Attacker IP: ${attackerIP || 'unknown'}`);
        
        // ✅ IMPROVED: Use challenge network IP (.3) and connect guacd to challenge network
        // This is better because:
        // 1. Simpler - attacker always at .3 (consistent)
        // 2. Direct connection on challenge network (no need for ctf-instances-network)
        // 3. Better isolation - each challenge network is independent
        // Note: We use attackerIP directly - no separate guacamoleAttackerIP needed
        
        // Connect guacd to challenge network so it can reach attacker at .3
        try {
          // ✅ IMPROVED: Find actual Docker network name by inspecting attacker container
          // Docker Compose creates networks with prefix: {directory}_{network_name}
          const attackerContainerName = `ctf-${challengeName}-attacker`;
          let actualNetworkName = null;
          
          try {
            const attackerContainer = this.docker.getContainer(attackerContainerName);
            const attackerInfo = await attackerContainer.inspect();
            
            // Find the challenge network (not ctf-instances-network)
            const networks = attackerInfo.NetworkSettings.Networks || {};
            actualNetworkName = Object.keys(networks).find(
              name => name !== 'ctf-instances-network'
            );
            
            if (actualNetworkName) {
              console.log(`🔍 Found challenge network: ${actualNetworkName}`);
            }
          } catch (containerError) {
            console.warn(`⚠️  Could not inspect attacker container: ${containerError.message}`);
          }
          
          // Fallback: Try compose network name if we couldn't find actual name
          if (!actualNetworkName) {
            actualNetworkName = Object.keys(composeConfig.networks || {}).find(
              name => name !== 'ctf-instances-network'
            );
            if (actualNetworkName) {
              // Docker Compose network format: {directory}_{network_name}
              const composeNetworkName = actualNetworkName;
              // Try to find actual network by listing networks
              const allNetworks = await this.docker.listNetworks();
              const matchingNetwork = allNetworks.find(net => 
                net.Name.includes(challengeName.replace(/-/g, '_')) && 
                net.Name.includes(composeNetworkName.replace(/-/g, '_'))
              );
              if (matchingNetwork) {
                actualNetworkName = matchingNetwork.Name;
                console.log(`🔍 Found network via search: ${actualNetworkName}`);
              }
            }
          }
          
          if (actualNetworkName) {
            const guacdContainer = this.docker.getContainer('ctf-guacd-new');
            const guacdInfo = await guacdContainer.inspect();
            
            // Check if guacd is already on this network
            if (!guacdInfo.NetworkSettings.Networks[actualNetworkName]) {
              console.log(`🔗 Connecting guacd to challenge network: ${actualNetworkName}`);
              const network = this.docker.getNetwork(actualNetworkName);
              await network.connect({ Container: 'ctf-guacd-new' });
              console.log(`✅ Guacd connected to ${actualNetworkName}`);
              console.log(`   Guacamole can now reach attacker at ${attackerIP} (challenge network)`);
            } else {
              console.log(`✅ Guacd already connected to ${actualNetworkName}`);
            }
          } else {
            console.warn(`⚠️  Could not determine challenge network name`);
          }
          
          console.log(`🔗 Guacamole connection IP: ${attackerIP} (challenge network - direct connection)`);
        } catch (error) {
          console.warn(`⚠️  Could not connect guacd to challenge network: ${error.message}`);
          console.warn(`   Will try to use challenge IP: ${attackerIP}`);
          // Continue anyway - guacd might be able to route
        }
        
        // ✅ NEW: Post-deployment validation - check victim accessibility
        // Use dedicated victim validation agent for comprehensive validation and auto-fix
        let validationResult;
        try {
          const { validateAndFixVictimMachine } = await import('../victim-validation-agent.js');
          if (validateAndFixVictimMachine) {
            console.log(`\n🔍 Using dedicated Victim Validation Agent...`);
            const victimServices = composeConfig.services ? 
              Object.keys(composeConfig.services).filter(s => !s.includes('attacker')) : [];
            
            const agentResult = await validateAndFixVictimMachine({
              challengeName,
              victimContainerName,
              attackerContainerName,
              attackerIP,
              expectedServices: victimServices,
              composeConfig
            });
            
            // Convert agent result to validation format
            validationResult = {
              victimContainerRunning: agentResult.finalStatus.victimIP ? true : false,
              victimIPAssigned: !!agentResult.finalStatus.victimIP,
              connectivityTest: false, // Will be tested separately
              servicesRunning: agentResult.finalStatus.servicesRunning || false,
              errors: agentResult.errors,
              warnings: agentResult.warnings,
              autoFixed: agentResult.fixed,
              fixMessage: agentResult.fixes.map(f => f.message).join('; ')
            };
            
            // Update victimIP if agent fixed it
            if (agentResult.finalStatus.victimIP) {
              victimIP = agentResult.finalStatus.victimIP;
            }
          } else {
            // Fallback to original validation
            validationResult = await this.validateVictimAccessibility(
              challengeName,
              attackerContainerName,
              victimContainerName,
              attackerIP,
              victimIP,
              composeConfig
            );
          }
        } catch (agentError) {
          console.warn(`⚠️  Victim validation agent failed, using fallback: ${agentError.message}`);
          // Fallback to original validation
          validationResult = await this.validateVictimAccessibility(
            challengeName,
            attackerContainerName,
            victimContainerName,
            attackerIP,
            victimIP,
            composeConfig
          );
        }
        
        return {
          victimUrl: victimIP ? `http://${victimIP}:8080` : null,
          victimIP: victimIP,
          attackerUrl: attackerIP ? `http://${attackerIP}:6901` : null,
          attackerIP: attackerIP, // IP for Guacamole SSH connection (challenge network .3)
          subnet: subnet,
          networkName: Object.keys(composeConfig.networks || {})[0],
          victimContainerName: victimContainerName,
          attackerContainerName: attackerContainerName,
          validation: validationResult, // Add validation results
          dockerOutput: {
            stdout: stdout,
            stderr: stderr,
            exitCode: 0,
            fullOutput: `STDOUT:\n${stdout}\n\nSTDERR:\n${stderr}`
          }
        };
        
      } catch (execError) {
        console.error('❌ Docker compose command failed:', execError);
        
        // Collect all output (stdout + stderr) for error analysis
        const errorOutput = {
          stdout: stdout || execError.stdout || '',
          stderr: stderr || execError.stderr || '',
          exitCode: execError.code || 1,
          fullOutput: `STDOUT:\n${stdout || execError.stdout || ''}\n\nSTDERR:\n${stderr || execError.stderr || ''}`
        };
        
        const error = new Error(`Docker compose failed: ${execError.message}\n${stderr || execError.stderr || ''}`);
        error.dockerOutput = errorOutput;
        throw error;

      }

    } catch (error) {
      console.error('Error deploying from docker-compose:', error);
      throw new Error(`Failed to deploy from compose: ${error.message}`);
    }
  }

  // DEPRECATED: This method used port mappings. Now we only use private IPs via subnet-allocator.js
  // All docker-compose.yml files are generated by attacker-image-generator.js with private IPs
  async generateDockerCompose(challengePath, challengeName, additionalServices = []) {
    throw new Error('This method is deprecated. Use attacker-image-generator.js with subnet allocation instead.');
    
    const composeConfig = {
      version: '3.8',
      services,
      networks: {
        'ctf-network': {
          driver: 'bridge',
          driver_opts: {
            'com.docker.network.bridge.enable_icc': 'true',
            'com.docker.network.bridge.enable_ip_masquerade': 'true'
          },
          internal: false
        }
      }
    };

    const yamlContent = yaml.dump(composeConfig, { indent: 2, lineWidth: -1 });
    const composeFilePath = path.join(challengePath, 'docker-compose.yml');
    
    await fs.writeFile(composeFilePath, yamlContent, 'utf8');
    console.log(`✅ Generated docker-compose.yml with ${Object.keys(services).length} services`);
  }

  /**
   * ✅ NEW: Validate victim machine accessibility after deployment
   * Checks if victim container is running, has IP, and is reachable from attacker
   */
  async validateVictimAccessibility(challengeName, attackerContainerName, victimContainerName, attackerIP, victimIP, composeConfig) {
    const validation = {
      victimContainerRunning: false,
      victimIPAssigned: false,
      connectivityTest: false,
      servicesRunning: false,
      errors: [],
      warnings: []
    };

    try {
      console.log(`\n🔍 Validating victim machine accessibility...`);
      
      // 1. Check if victim container is running
      try {
        const victimContainer = this.docker.getContainer(victimContainerName);
        const victimInfo = await victimContainer.inspect();
        validation.victimContainerRunning = victimInfo.State.Running === true;
        
        if (validation.victimContainerRunning) {
          console.log(`✅ Victim container is running: ${victimContainerName}`);
        } else {
          validation.errors.push(`Victim container ${victimContainerName} is not running (Status: ${victimInfo.State.Status})`);
          console.error(`❌ Victim container is not running: ${victimInfo.State.Status}`);
        }
      } catch (containerError) {
        validation.errors.push(`Could not find victim container: ${containerError.message}`);
        console.error(`❌ Could not inspect victim container: ${containerError.message}`);
        return validation; // Can't continue if container doesn't exist
      }

      // 2. Check if victim IP is assigned
      if (victimIP) {
        validation.victimIPAssigned = true;
        console.log(`✅ Victim IP assigned: ${victimIP}`);
      } else {
        validation.errors.push('Victim IP is not assigned');
        console.error(`❌ Victim IP is missing`);
        return validation; // Can't continue without IP
      }

      // 3. Test connectivity from attacker to victim (ping)
      if (validation.victimContainerRunning && attackerContainerName && attackerIP) {
        try {
          const attackerContainer = this.docker.getContainer(attackerContainerName);
          
          // Wait a bit for network to stabilize
          await new Promise(resolve => setTimeout(resolve, 2000));
          
          // Test ping from attacker to victim
          const pingResult = await attackerContainer.exec({
            Cmd: ['ping', '-c', '2', '-W', '2', victimIP],
            AttachStdout: true,
            AttachStderr: true
          });
          
          const pingStream = await pingResult.start({ hijack: true, stdin: false });
          let pingOutput = '';
          pingStream.on('data', (chunk) => {
            pingOutput += chunk.toString();
          });
          
          await new Promise((resolve) => {
            pingStream.on('end', resolve);
            setTimeout(resolve, 5000); // 5 second timeout
          });
          
          if (pingOutput.includes('2 packets transmitted') && pingOutput.includes('2 received')) {
            validation.connectivityTest = true;
            console.log(`✅ Connectivity test passed: Attacker can ping victim at ${victimIP}`);
          } else {
            validation.warnings.push(`Ping test inconclusive. Output: ${pingOutput.substring(0, 100)}`);
            console.warn(`⚠️  Ping test inconclusive. Victim may still be accessible via services.`);
          }
        } catch (pingError) {
          validation.warnings.push(`Ping test failed: ${pingError.message}. Services may still be accessible.`);
          console.warn(`⚠️  Could not test ping connectivity: ${pingError.message}`);
        }
      }

      // 4. Check if services are running on victim (check common ports)
      if (validation.victimContainerRunning && victimIP) {
        try {
          const victimContainer = this.docker.getContainer(victimContainerName);
          
          // Get expected services from docker-compose.yml or metadata
          const services = composeConfig.services || {};
          const victimService = Object.keys(services).find(name => 
            !name.includes('attacker') && !name.includes('database')
          );
          
          if (victimService) {
            // Check if services are listening (using netstat or ss)
            const netstatResult = await victimContainer.exec({
              Cmd: ['sh', '-c', 'netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "netstat/ss not available"'],
              AttachStdout: true,
              AttachStderr: true
            });
            
            const netstatStream = await netstatResult.start({ hijack: true, stdin: false });
            let netstatOutput = '';
            netstatStream.on('data', (chunk) => {
              netstatOutput += chunk.toString();
            });
            
            await new Promise((resolve) => {
              netstatStream.on('end', resolve);
              setTimeout(resolve, 3000);
            });
            
            // Check for common service ports
            const commonPorts = [21, 22, 80, 443, 445, 23]; // FTP, SSH, HTTP, HTTPS, SMB, Telnet
            const listeningPorts = commonPorts.filter(port => 
              netstatOutput.includes(`:${port}`) || netstatOutput.includes(`0.0.0.0:${port}`)
            );
            
            if (listeningPorts.length > 0) {
              validation.servicesRunning = true;
              console.log(`✅ Services detected listening on ports: ${listeningPorts.join(', ')}`);
            } else {
              validation.warnings.push('No common service ports detected as listening. Services may not have started yet.');
              console.warn(`⚠️  No common service ports detected. Services may need time to start.`);
            }
          }
        } catch (serviceError) {
          validation.warnings.push(`Could not check services: ${serviceError.message}`);
          console.warn(`⚠️  Could not check service status: ${serviceError.message}`);
        }
      }

      // Summary
      if (validation.errors.length === 0) {
        console.log(`\n✅ Victim accessibility validation: PASSED`);
        if (validation.warnings.length > 0) {
          console.log(`⚠️  Warnings: ${validation.warnings.length}`);
        }
      } else {
        console.log(`\n❌ Victim accessibility validation: FAILED`);
        console.log(`   Errors: ${validation.errors.join('; ')}`);
        
        // ✅ NEW: Attempt automatic fixes
        console.log(`\n🔧 Attempting automatic fixes...`);
        const fixResult = await this.autoFixVictimAccessibility(
          challengeName,
          attackerContainerName,
          victimContainerName,
          attackerIP,
          victimIP,
          validation,
          composeConfig
        );
        
        if (fixResult.fixed) {
          console.log(`✅ Auto-fix successful: ${fixResult.message}`);
          validation.autoFixed = true;
          validation.fixMessage = fixResult.message;
          
          // Re-validate after fix
          console.log(`\n🔍 Re-validating after fix...`);
          const revalidation = await this.validateVictimAccessibility(
            challengeName,
            attackerContainerName,
            victimContainerName,
            attackerIP,
            victimIP,
            composeConfig
          );
          
          // Update validation with revalidation results
          validation.victimContainerRunning = revalidation.victimContainerRunning;
          validation.victimIPAssigned = revalidation.victimIPAssigned;
          validation.connectivityTest = revalidation.connectivityTest;
          validation.servicesRunning = revalidation.servicesRunning;
          validation.errors = revalidation.errors;
          validation.warnings = revalidation.warnings;
          
          if (validation.errors.length === 0) {
            console.log(`✅ Re-validation passed after auto-fix!`);
          } else {
            console.log(`⚠️  Re-validation still has issues: ${validation.errors.join('; ')}`);
          }
        } else {
          console.log(`⚠️  Auto-fix failed: ${fixResult.message}`);
          validation.autoFixed = false;
          validation.fixMessage = fixResult.message;
        }
      }

    } catch (error) {
      validation.errors.push(`Validation error: ${error.message}`);
      console.error(`❌ Validation error: ${error.message}`);
    }

    return validation;
  }

  /**
   * ✅ NEW: Auto-fix victim accessibility issues
   * Attempts to automatically resolve common problems
   */
  async autoFixVictimAccessibility(challengeName, attackerContainerName, victimContainerName, attackerIP, victimIP, validation, composeConfig) {
    const fixResult = {
      fixed: false,
      message: '',
      actions: []
    };

    try {
      // Fix 1: If container is not running, start it
      if (!validation.victimContainerRunning) {
        try {
          console.log(`🔧 Fix 1: Starting victim container...`);
          const victimContainer = this.docker.getContainer(victimContainerName);
          await victimContainer.start();
          fixResult.actions.push('Started victim container');
          console.log(`✅ Victim container started`);
          
          // Wait for container to be ready
          await new Promise(resolve => setTimeout(resolve, 3000));
          fixResult.fixed = true;
        } catch (startError) {
          fixResult.message += `Failed to start container: ${startError.message}. `;
          console.error(`❌ Could not start victim container: ${startError.message}`);
        }
      }

      // Fix 2: If services are not running, restart the container or start services
      if (validation.victimContainerRunning && !validation.servicesRunning) {
        try {
          console.log(`🔧 Fix 2: Attempting to start services on victim...`);
          const victimContainer = this.docker.getContainer(victimContainerName);
          
          // Try to execute the startup script if it exists
          const startScriptResult = await victimContainer.exec({
            Cmd: ['sh', '-c', 'if [ -f /start-services.sh ]; then /start-services.sh &; fi'],
            AttachStdout: true,
            AttachStderr: true
          });
          
          const startScriptStream = await startScriptResult.start({ hijack: true, stdin: false });
          let startScriptOutput = '';
          startScriptStream.on('data', (chunk) => {
            startScriptOutput += chunk.toString();
          });
          
          await new Promise((resolve) => {
            startScriptStream.on('end', resolve);
            setTimeout(resolve, 2000);
          });
          
          fixResult.actions.push('Attempted to start services');
          console.log(`✅ Service startup script executed`);
          
          // Wait a bit for services to start
          await new Promise(resolve => setTimeout(resolve, 3000));
          fixResult.fixed = true;
        } catch (serviceError) {
          // If startup script doesn't exist or fails, try restarting container
          try {
            console.log(`🔧 Fix 2b: Restarting victim container to start services...`);
            const victimContainer = this.docker.getContainer(victimContainerName);
            await victimContainer.restart({ t: 10 });
            fixResult.actions.push('Restarted victim container');
            console.log(`✅ Victim container restarted`);
            
            // Wait for container to be ready
            await new Promise(resolve => setTimeout(resolve, 5000));
            fixResult.fixed = true;
          } catch (restartError) {
            fixResult.message += `Failed to restart container: ${restartError.message}. `;
            console.error(`❌ Could not restart victim container: ${restartError.message}`);
          }
        }
      }

      // Fix 3: If IP is not assigned, check network connection
      if (!validation.victimIPAssigned && validation.victimContainerRunning) {
        try {
          console.log(`🔧 Fix 3: Checking network configuration...`);
          const victimContainer = this.docker.getContainer(victimContainerName);
          const victimInfo = await victimContainer.inspect();
          const victimNetworks = victimInfo.NetworkSettings.Networks || {};
          
          // Find challenge network
          const challengeNetworkName = Object.keys(composeConfig.networks || {}).find(
            name => name !== 'ctf-instances-network'
          );
          
          if (challengeNetworkName) {
            // Try to reconnect to network
            const allNetworks = await this.docker.listNetworks();
            const actualNetwork = allNetworks.find(net => 
              net.Name.includes(challengeName.replace(/-/g, '_')) && 
              net.Name.includes(challengeNetworkName.replace(/-/g, '_'))
            );
            
            if (actualNetwork && !victimNetworks[actualNetwork.Name]) {
              console.log(`🔧 Reconnecting victim to network: ${actualNetwork.Name}`);
              const network = this.docker.getNetwork(actualNetwork.Name);
              await network.connect({ Container: victimContainerName });
              fixResult.actions.push('Reconnected victim to network');
              console.log(`✅ Victim reconnected to network`);
              
              // Wait for IP assignment
              await new Promise(resolve => setTimeout(resolve, 2000));
              fixResult.fixed = true;
            }
          }
        } catch (networkError) {
          fixResult.message += `Failed to fix network: ${networkError.message}. `;
          console.error(`❌ Could not fix network: ${networkError.message}`);
        }
      }

      // Fix 4: If connectivity test failed but container is running, wait and retry
      if (validation.victimContainerRunning && validation.victimIPAssigned && !validation.connectivityTest) {
        try {
          console.log(`🔧 Fix 4: Waiting for network to stabilize and retrying connectivity...`);
          await new Promise(resolve => setTimeout(resolve, 5000));
          fixResult.actions.push('Waited for network stabilization');
          fixResult.fixed = true; // Connectivity may improve after waiting
        } catch (waitError) {
          fixResult.message += `Failed to wait for network: ${waitError.message}. `;
        }
      }

      if (fixResult.fixed && fixResult.actions.length > 0) {
        fixResult.message = `Applied fixes: ${fixResult.actions.join(', ')}`;
      } else if (!fixResult.fixed && fixResult.message === '') {
        fixResult.message = 'No automatic fixes could be applied';
      }

    } catch (error) {
      fixResult.message = `Auto-fix error: ${error.message}`;
      console.error(`❌ Auto-fix error: ${error.message}`);
    }

    return fixResult;
  }

  async cleanupMultiContainer(challengeName) {
    try {
      console.log(`🧹 Cleaning up multi-container setup for: ${challengeName}`);

      const CLONE_PATH = process.env.CLONE_PATH || path.join(process.cwd(), 'challenges-repo');
      const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
      const composeFilePath = path.join(challengePath, 'docker-compose.yml');

      // Check if docker-compose.yml exists
      try {
        await fs.access(composeFilePath);
        
        // Use docker compose down command
        console.log(`\n🐳 Executing: docker compose down`);
        console.log(`📂 Working directory: ${challengePath}`);
        
        const { exec } = await import('child_process');
        const { promisify } = await import('util');
        const execPromise = promisify(exec);
        
        const { stdout, stderr } = await execPromise(
          'docker compose down',
          { 
            cwd: challengePath,
            maxBuffer: 10 * 1024 * 1024
          }
        );
        
        if (stdout) {
          console.log('\n📋 Docker Compose Down Output:');
          console.log(stdout);
        }
        
        if (stderr && stderr.trim()) {
          console.log('\n⚠️  Warnings:');
          console.log(stderr);
        }
        
        console.log(`✅ Cleanup completed using docker compose down`);
        
        // 🔥 NEW: Also explicitly remove networks by name to ensure cleanup
        await this.deleteChallengeNetworks(challengeName);
        
        return true;
        
      } catch (fileError) {
        // Fallback to manual cleanup if docker-compose.yml not found
        console.log(`  ⚠️  docker-compose.yml not found, using fallback cleanup`);
        
        // 🔥 NEW: Delete networks by name in fallback too
        await this.deleteChallengeNetworks(challengeName);
        
        const networkName = `ctf-${challengeName}-network`;
        const containersToRemove = [
          `ctf-${challengeName}-victim`,
          `ctf-${challengeName}-attacker`,
          `ctf-${challengeName}-database`
        ];

        // Stop and remove all containers
        for (const containerName of containersToRemove) {
          try {
            const container = this.docker.getContainer(containerName);
            const info = await container.inspect();
            
            if (info.State.Running) {
              console.log(`  ⏹️  Stopping: ${containerName}`);
              await container.stop({ t: 10 });
            }
            
            await container.remove({ force: true });
            console.log(`  ✓ Removed: ${containerName}`);
          } catch (error) {
            if (!error.message.includes('404')) {
              console.log(`  ⚠️  Could not remove ${containerName}: ${error.message}`);
            }
          }
        }

        // Remove network
        try {
          const networks = await this.docker.listNetworks({ filters: { name: [networkName] } });
          if (networks.length > 0) {
            const network = this.docker.getNetwork(networks[0].Id);
            await network.remove();
            console.log(`  ✓ Removed network: ${networkName}`);
          }
        } catch (error) {
          if (!error.message.includes('404')) {
            console.log(`  ⚠️  Could not remove network: ${error.message}`);
          }
        }

        console.log(`✅ Fallback cleanup completed`);
        return true;
      }
      
    } catch (error) {
      console.error('Error cleaning up:', error);
      return false;
    }
  }

  /**
   * Delete all networks associated with a challenge
   * Called during cleanup to ensure networks are removed
   */
  async deleteChallengeNetworks(challengeName) {
    try {
      console.log(`🧹 Deleting networks for challenge: ${challengeName}`);
      
      const { execSync } = await import('child_process');
      
      // Get all networks
      const networksOutput = execSync('docker network ls --format "{{.Name}}"', { encoding: 'utf8' });
      const allNetworks = networksOutput.trim().split('\n').filter(n => n && n.trim());
      
      // Find networks matching challenge name patterns
      const networkPatterns = [
        `ctf-${challengeName}-net`, // Standard format
        `${challengeName.replace(/-/g, '_')}_ctf-${challengeName}-net`, // Docker Compose format
        `${challengeName}_ctf-${challengeName}-net`, // Alternative format
        `ctf-${challengeName}-default-net` // Default format
      ];
      
      let deletedCount = 0;
      
      for (const networkName of allNetworks) {
        // Check if network matches any pattern
        const matches = networkPatterns.some(pattern => {
          return networkName === pattern || networkName.includes(challengeName);
        });
        
        // Don't delete infrastructure networks
        if (matches && 
            !networkName.includes('ctf-instances-network') && 
            !networkName.includes('ctf-network') &&
            !networkName.includes('bridge') &&
            !networkName.includes('host') &&
            !networkName.includes('none')) {
          try {
            console.log(`  🗑️  Removing network: ${networkName}`);
            
            // First, disconnect all containers
            try {
              const inspectOutput = execSync(
                `docker network inspect ${networkName} --format "{{range .Containers}}{{.Name}} {{end}}"`, 
                { encoding: 'utf8', stdio: 'pipe' }
              ).trim();
              
              const containers = inspectOutput.split(' ').filter(c => c && c.trim());
              for (const container of containers) {
                try {
                  execSync(`docker network disconnect ${networkName} ${container} --force`, { stdio: 'ignore' });
                } catch (disconnectError) {
                  // Continue
                }
              }
            } catch (inspectError) {
              // Network might not exist or be in use, continue to removal attempt
            }
            
            // Remove network
            execSync(`docker network rm ${networkName}`, { stdio: 'ignore' });
            console.log(`  ✅ Removed network: ${networkName}`);
            deletedCount++;
          } catch (rmError) {
            console.log(`  ⚠️  Could not remove network ${networkName}: ${rmError.message}`);
          }
        }
      }
      
      if (deletedCount > 0) {
        console.log(`✅ Deleted ${deletedCount} network(s) for challenge: ${challengeName}`);
      } else {
        console.log(`  ℹ️  No networks found to delete for challenge: ${challengeName}`);
      }
      
      return deletedCount;
    } catch (error) {
      console.error(`❌ Error deleting networks for ${challengeName}:`, error.message);
      return 0;
    }
  }
}

export const dockerManager = new DockerManager();
