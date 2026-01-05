/**
 * Deployer - Orchestrates challenge deployment
 * 
 * Responsibilities:
 * - Coordinate deployment process
 * - Manage deployment lifecycle
 * - Handle errors and retries
 * - Return deployment results
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { fileURLToPath } from 'url';
import Docker from 'dockerode';
import { ContainerManager } from './container-manager.js';
import { NetworkManager } from './network-manager.js';
import { HealthChecker } from './health-checker.js';
import { Logger } from '../core/logger.js';
import { guacamoleService } from '../services/guacamole-service.js';
import { deploymentErrorFixer } from '../agents/deployment-error-fixer.js';

const execPromise = promisify(exec);

// Get project root directory (3 levels up from this file: src/deployment/ -> src/ -> packages/ctf-automation/ -> packages/ -> project root)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

export class Deployer {
  constructor() {
    this.docker = new Docker();
    this.containerManager = new ContainerManager();
    this.networkManager = new NetworkManager();
    this.healthChecker = new HealthChecker();
    this.logger = new Logger();
  }

  /**
   * Deploy a challenge
   */
  async deploy(challengeName, sessionId) {
    try {
      this.logger.info('Deployer', 'Starting deployment', { challengeName });

      // CRITICAL: Pull latest changes from GitHub before deployment
      this.logger.info('Deployer', 'Pulling latest changes from GitHub', { challengeName });
      const { gitManager } = await import('../git-manager.js');
      await gitManager.ensureRepository();
      this.logger.success('Deployer', '✅ Repository synced with GitHub - latest changes pulled');

      const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
      
      // Verify challenge directory exists after pull
      const fs = await import('fs/promises');
      try {
        await fs.access(challengePath);
        this.logger.debug('Deployer', 'Challenge directory verified', { challengePath });
      } catch (accessError) {
        this.logger.error('Deployer', 'Challenge directory not found after pull', { 
          challengePath,
          error: accessError.message
        });
        throw new Error(`Challenge "${challengeName}" not found. It may not exist in the repository. Please create it first.`);
      }

      // Step 1: Prepare environment
      await this.prepareEnvironment(challengeName);

      // Step 2: Deploy containers
      const deploymentResult = await this.deployContainers(challengePath, challengeName);

      if (!deploymentResult.success) {
        return deploymentResult;
      }

      // Step 3: Wait for containers to fully start and get IPs
      this.logger.info('Deployer', 'Waiting for containers to start and get IP addresses');
      await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds for containers to start

      // Step 4: Get container information (with retry for IP assignment)
      let containers = await this.containerManager.getContainerInfo(challengeName);
      
      // Check if containers are running
      const runningContainers = [
        ...(containers.attacker?.running ? [containers.attacker] : []),
        ...containers.victims.filter(v => v.running)
      ];
      
      if (runningContainers.length === 0 && (containers.attacker || containers.victims.length > 0)) {
        this.logger.warn('Deployer', 'Containers found but none are running', {
          attacker: containers.attacker ? { name: containers.attacker.name, status: containers.attacker.status } : null,
          victims: containers.victims.map(v => ({ name: v.name, status: v.status }))
        });
        
        // Try to start stopped containers
        this.logger.info('Deployer', 'Attempting to start stopped containers...');
        for (const victim of containers.victims) {
          if (!victim.running) {
            try {
              await this.containerManager.startContainer(victim.name);
              this.logger.info('Deployer', 'Started container', { name: victim.name });
            } catch (startError) {
              this.logger.warn('Deployer', 'Failed to start container', { name: victim.name, error: startError.message });
            }
          }
        }
        if (containers.attacker && !containers.attacker.running) {
          try {
            await this.containerManager.startContainer(containers.attacker.name);
            this.logger.info('Deployer', 'Started attacker container', { name: containers.attacker.name });
          } catch (startError) {
            this.logger.warn('Deployer', 'Failed to start attacker container', { error: startError.message });
          }
        }
        
        // Wait and refresh
        await new Promise(resolve => setTimeout(resolve, 5000));
        containers = await this.containerManager.getContainerInfo(challengeName);
      }
      
      // Retry getting container info if IPs are missing
      if ((!containers.attacker?.ip || containers.victims.some(v => !v.ip)) && (containers.attacker || containers.victims.length > 0)) {
        this.logger.warn('Deployer', 'Some containers missing IPs, retrying...', {
          attackerIP: containers.attacker?.ip || 'MISSING',
          victimIPs: containers.victims.map(v => v.ip || 'MISSING')
        });
        await new Promise(resolve => setTimeout(resolve, 5000)); // Wait another 5 seconds
        containers = await this.containerManager.getContainerInfo(challengeName);
      }
      
      this.logger.debug('Deployer', 'Container info retrieved', {
        attacker: containers.attacker ? { name: containers.attacker.name, ip: containers.attacker.ip, running: containers.attacker.running } : null,
        victims: containers.victims.map(v => ({ name: v.name, ip: v.ip, running: v.running }))
      });

      // Step 5: Setup networks
      await this.networkManager.setupNetworks(challengeName, containers);

      // Step 6: Refresh container info after network setup (IPs might be assigned now)
      if (!containers.attacker?.ip || containers.victims.some(v => !v.ip)) {
        this.logger.info('Deployer', 'Refreshing container info after network setup');
        await new Promise(resolve => setTimeout(resolve, 3000));
        containers = await this.containerManager.getContainerInfo(challengeName);
      }

      // Step 7: Health check
      const healthStatus = await this.healthChecker.checkAll(challengeName, containers);

      // Step 8: Setup Guacamole (only if attacker has IP)
      let guacamole = null;
      if (containers.attacker?.ip) {
        guacamole = await guacamoleService.setupConnection(
          challengeName,
          containers.attacker,
          sessionId
        );
      } else {
        this.logger.warn('Deployer', 'Attacker container has no IP, skipping Guacamole setup', {
          attacker: containers.attacker
        });
      }

      // Log final container status
      this.logger.info('Deployer', 'Final container status', {
        attacker: containers.attacker ? {
          name: containers.attacker.name,
          ip: containers.attacker.ip || 'NO IP',
          running: containers.attacker.running
        } : 'NOT FOUND',
        victims: containers.victims.map(v => ({
          name: v.name,
          ip: v.ip || 'NO IP',
          running: v.running
        }))
      });

      this.logger.success('Deployer', 'Deployment completed', { challengeName });

      return {
        success: true,
        data: {
          challengeName,
          containers,
          networks: deploymentResult.networks,
          health: healthStatus,
          guacamole: guacamole || { error: 'Guacamole setup skipped - attacker IP not available' }
        }
      };

    } catch (error) {
      this.logger.error('Deployer', 'Deployment failed', error.stack);
      // Return user-friendly error without exposing stack traces or file paths
      return {
        success: false,
        error: 'Challenge deploy failed',
        details: process.env.NODE_ENV === 'development' ? error.stack : undefined
      };
    }
  }

  /**
   * Prepare deployment environment
   */
  async prepareEnvironment(challengeName) {
    this.logger.info('Deployer', 'Preparing environment', { challengeName });

    // Disconnect guacd from old networks
    await this.networkManager.disconnectGuacdFromOldNetworks(challengeName);

    // Re-validate and re-allocate IPs/subnet to ensure they're available
    // This is important because IPs might have been freed or conflicts might exist
    this.logger.info('Deployer', 'Re-validating IP allocation', { challengeName });
    await this.revalidateIPAllocation(challengeName);
  }

  /**
   * Re-validate and re-allocate IPs during deployment
   * ALWAYS re-allocates fresh IPs to ensure they're available and not conflicting
   * @param {boolean} forceNew - Force allocation of a completely new subnet (skip existing allocation check)
   */
  async revalidateIPAllocation(challengeName, forceNew = false) {
    try {
      const { subnetAllocator } = await import('../subnet-allocator.js');
      const fs = await import('fs/promises');
      const yamlModule = await import('js-yaml');
      const yaml = yamlModule.default || yamlModule;
      
      // Read docker-compose.yml to get current configuration
      const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
      const composeFile = path.join(challengePath, 'docker-compose.yml');
      
      try {
        const composeContent = await fs.readFile(composeFile, 'utf8');
        const composeConfig = yaml.load(composeContent);
        
        // Extract subnet and network info from compose file
        const networks = composeConfig.networks || {};
        const challengeNetwork = Object.keys(networks).find(n => 
          !n.includes('ctf-instances-network') && !n.includes('external')
        );
        
        if (!challengeNetwork) {
          this.logger.warn('Deployer', 'No challenge network found in docker-compose.yml');
          return;
        }

        // Count services to determine victim count
        const services = composeConfig.services || {};
        const victimServices = Object.keys(services).filter(name => 
          !name.includes('attacker') && !name.includes('database') && !name.includes('api')
        );
        const victimCount = victimServices.length;
        const hasDatabase = Object.keys(services).some(name => name.includes('database'));
        const hasAPI = Object.keys(services).some(name => name.includes('api'));

        // ALWAYS re-allocate subnet to get fresh IPs
        this.logger.info('Deployer', 'Re-allocating subnet and IPs for deployment', {
          challengeName,
          victimCount,
          hasDatabase,
          hasAPI
        });

        // If forcing new allocation, release existing one first
        if (forceNew) {
          try {
            const { subnetAllocator } = await import('../subnet-allocator.js');
            await subnetAllocator.releaseSubnet(challengeName, 'default');
            this.logger.info('Deployer', 'Released existing subnet allocation for re-allocation', { challengeName });
          } catch (releaseError) {
            this.logger.warn('Deployer', 'Failed to release existing subnet (may not exist)', { error: releaseError.message });
          }
        }

        const newSubnet = await subnetAllocator.allocateSubnet(challengeName, 'default', {
          victimCount,
          randomizeIPs: true,  // Force random IP allocation for victims
          needsDatabase: hasDatabase,
          needsAPI: hasAPI,
          forceNew: forceNew  // Pass flag to skip existing allocation check
        });

        // Update subnet in compose config
        if (networks[challengeNetwork].ipam?.config?.[0]) {
          networks[challengeNetwork].ipam.config[0].subnet = newSubnet.subnet;
          networks[challengeNetwork].ipam.config[0].gateway = newSubnet.gateway;
        } else {
          // Create IPAM config if it doesn't exist
          if (!networks[challengeNetwork].ipam) {
            networks[challengeNetwork].ipam = { config: [] };
          }
          networks[challengeNetwork].ipam.config = [{
            subnet: newSubnet.subnet,
            gateway: newSubnet.gateway
          }];
        }

        // Update IPs for all services
        const baseIP = newSubnet.subnet.split('/')[0].split('.').slice(0, 3).join('.');
        let victimIndex = 0;

        for (const [serviceName, service] of Object.entries(services)) {
          if (!service.networks) {
            service.networks = {};
          }
          if (!service.networks[challengeNetwork]) {
            service.networks[challengeNetwork] = {};
          }

          // Assign IP based on service type
          if (serviceName.includes('attacker')) {
            service.networks[challengeNetwork].ipv4_address = newSubnet.ips.attacker;
            this.logger.debug('Deployer', 'Updated attacker IP', {
              service: serviceName,
              ip: newSubnet.ips.attacker
            });
          } else if (serviceName.includes('database')) {
            if (newSubnet.ips.database) {
              service.networks[challengeNetwork].ipv4_address = newSubnet.ips.database;
              this.logger.debug('Deployer', 'Updated database IP', {
                service: serviceName,
                ip: newSubnet.ips.database
              });
            }
          } else if (serviceName.includes('api')) {
            if (newSubnet.ips.api) {
              service.networks[challengeNetwork].ipv4_address = newSubnet.ips.api;
              this.logger.debug('Deployer', 'Updated API IP', {
                service: serviceName,
                ip: newSubnet.ips.api
              });
            }
          } else {
            // Victim service - use allocated victim IPs
            const victimIPs = newSubnet.ips.victims || [];
            if (victimIndex < victimIPs.length) {
              service.networks[challengeNetwork].ipv4_address = victimIPs[victimIndex];
              this.logger.debug('Deployer', 'Updated victim IP', {
                service: serviceName,
                ip: victimIPs[victimIndex],
                index: victimIndex
              });
              victimIndex++;
            } else {
              // Fallback: use sequential IPs if not enough allocated
              const fallbackIP = `${baseIP}.${100 + victimIndex}`;
              service.networks[challengeNetwork].ipv4_address = fallbackIP;
              this.logger.warn('Deployer', 'Using fallback IP for victim', {
                service: serviceName,
                ip: fallbackIP
              });
              victimIndex++;
            }
          }
        }
        
        // Write updated compose file
        const updatedCompose = yaml.dump(composeConfig, { 
          lineWidth: -1,
          noRefs: true,
          quotingType: '"',
          indent: 2
        });
        await fs.writeFile(composeFile, updatedCompose, 'utf8');
        
        this.logger.success('Deployer', '✅ Re-allocated and updated IPs in docker-compose.yml', {
          subnet: newSubnet.subnet,
          gateway: newSubnet.gateway,
          attackerIP: newSubnet.ips.attacker,
          victimCount: victimIndex
        });

      } catch (readError) {
        this.logger.error('Deployer', 'Failed to re-allocate IPs', {
          error: readError.message,
          stack: readError.stack
        });
        throw new Error(`Failed to re-allocate IPs: ${readError.message}`);
      }
    } catch (error) {
      this.logger.error('Deployer', 'IP re-allocation failed', {
        error: error.message,
        stack: error.stack
      });
      throw error; // Throw error - IP allocation is critical
    }
  }

  /**
   * Deploy containers using docker compose
   */
  async deployContainers(challengePath, challengeName) {
    try {
      this.logger.info('Deployer', 'Deploying containers', { challengePath });

      // Normalize path for Windows (use forward slashes or properly escape)
      const composeFile = path.join(challengePath, 'docker-compose.yml');
      
      // Verify file exists
      const fs = await import('fs/promises');
      try {
        await fs.access(composeFile);
        this.logger.debug('Deployer', 'docker-compose.yml found', { path: composeFile });
      } catch (accessError) {
        // Try to pull latest changes in case files were just pushed
        this.logger.warn('Deployer', 'docker-compose.yml not found, pulling latest changes', { path: composeFile });
        try {
          const { gitManager } = await import('../git-manager.js');
          await gitManager.ensureRepository();
          // Check again after pull
          await fs.access(composeFile);
          this.logger.debug('Deployer', 'docker-compose.yml found after pull', { path: composeFile });
        } catch (pullError) {
          throw new Error(`docker-compose.yml not found at: ${composeFile}. Challenge may not be saved correctly. Error: ${accessError.message}`);
        }
      }

      // Use absolute path and quote it for Windows compatibility
      const absoluteComposeFile = path.resolve(composeFile);
      const quotedPath = process.platform === 'win32' 
        ? `"${absoluteComposeFile.replace(/\\/g, '/')}"` 
        : absoluteComposeFile;

      // Run docker compose up
      // Use the challenge directory as working directory
      const absoluteChallengePath = path.resolve(challengePath);
      
      this.logger.info('Deployer', 'Running docker compose', {
        composeFile: quotedPath,
        workingDir: absoluteChallengePath
      });

      let stdout, stderr;
      let retryCount = 0;
      const maxRetries = 3;
      let deploymentSuccess = false;
      
      while (retryCount < maxRetries && !deploymentSuccess) {
        try {
          const result = await execPromise(
            `docker compose -f ${quotedPath} up --build -d`,
            { cwd: absoluteChallengePath, maxBuffer: 10 * 1024 * 1024 } // 10MB buffer
          );
          stdout = result.stdout;
          stderr = result.stderr;
          
          // Check if error message indicates subnet overlap (even if exit code is 0)
          const isSubnetOverlap = stderr.includes('Pool overlaps') || 
                                  stderr.includes('overlaps with other') ||
                                  stdout.includes('Pool overlaps') ||
                                  stdout.includes('Error') && stdout.includes('overlaps');
          
          if (isSubnetOverlap && retryCount < maxRetries - 1) {
            this.logger.warn('Deployer', 'Subnet overlap detected in output, re-allocating subnet and retrying', {
              attempt: retryCount + 1,
              maxRetries,
              stderr: stderr.substring(0, 300)
            });
            
            // Re-allocate subnet with force flag to find a different one
            await this.revalidateIPAllocation(challengeName, true); // Force re-allocation
            
            retryCount++;
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2s before retry
            continue;
          }
          
          deploymentSuccess = true; // Success, exit retry loop
          break;
        } catch (execError) {
          stdout = execError.stdout || '';
          stderr = execError.stderr || execError.message || '';
          
          // Check if error is due to subnet overlap
          const isSubnetOverlap = stderr.includes('Pool overlaps') || 
                                  stderr.includes('overlaps with other') ||
                                  execError.message.includes('Pool overlaps') ||
                                  stdout.includes('Pool overlaps');
          
          // Use AI to analyze and fix the error (before manual fixes)
          if (retryCount < maxRetries - 1) {
            this.logger.info('Deployer', 'Using AI to analyze and fix deployment error', {
              attempt: retryCount + 1,
              maxRetries
            });

            // Create error object with all context
            const errorWithContext = {
              message: execError.message,
              stdout: stdout || '',
              stderr: stderr || '',
              originalError: execError
            };

            // Ask AI to analyze and fix
            const fixResult = await deploymentErrorFixer.analyzeAndFix(
              errorWithContext,
              challengeName,
              challengePath
            );

            if (fixResult.fixed) {
              this.logger.success('Deployer', 'AI successfully fixed deployment error', {
                fixes: fixResult.fixes?.map(f => f.action).join(', ') || 'unknown'
              });
              
              // Re-allocate subnet if it was a network issue
              if (isSubnetOverlap || fixResult.analysis?.errorType === 'network_overlap') {
                await this.revalidateIPAllocation(challengeName, true);
              }
              
              retryCount++;
              await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2s before retry
              continue;
            } else {
              this.logger.warn('Deployer', 'AI could not fix error automatically', {
                reason: fixResult.reason
              });
            }
          }
          
          // Fallback: Manual fix for subnet overlap (if AI didn't fix it)
          if (isSubnetOverlap && retryCount < maxRetries - 1) {
            this.logger.warn('Deployer', 'Subnet overlap detected, re-allocating subnet and retrying', {
              attempt: retryCount + 1,
              maxRetries,
              error: execError.message,
              stdout: stdout?.substring(0, 500),
              stderr: stderr?.substring(0, 500)
            });
            
            // Try to remove the failed network before retrying
            // Check for networks matching the challenge name pattern
            try {
              const { execSync } = await import('child_process');
              
              // Try multiple possible network name formats (Docker Compose prefixes with directory name)
              const possibleNetworkNames = [
                `${challengeName}_ctf-${challengeName}-net`, // Docker Compose format (most common)
                `ctf-${challengeName}-default-net`,
                `ctf-${challengeName}-net`,
                `${challengeName}-default-net`
              ];
              
              for (const networkName of possibleNetworkNames) {
                try {
                  execSync(`docker network rm ${networkName}`, { stdio: 'ignore' });
                  this.logger.info('Deployer', 'Removed failed network before retry', { networkName });
                } catch (rmError) {
                  // Network might not exist, that's okay - try next name
                  this.logger.debug('Deployer', 'Network removal attempted', { networkName });
                }
              }
              
              // Also try to find and remove any networks with the challenge name in them
              try {
                const networks = execSync('docker network ls --format "{{.Name}}"', { encoding: 'utf8' });
                const networkList = networks.trim().split('\n').filter(n => n && n.includes(challengeName));
                for (const network of networkList) {
                  try {
                    execSync(`docker network rm ${network}`, { stdio: 'ignore' });
                    this.logger.info('Deployer', 'Removed network matching challenge name', { network });
                  } catch (rmError) {
                    // Continue trying others
                  }
                }
              } catch (listError) {
                // Continue anyway
              }
            } catch (cleanupError) {
              this.logger.warn('Deployer', 'Network cleanup failed, continuing anyway', { error: cleanupError.message });
            }
            
            // Re-allocate subnet with force flag to find a different one
            await this.revalidateIPAllocation(challengeName, true); // Force re-allocation
            
            retryCount++;
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2s before retry
            continue;
          }
          
          // If not subnet overlap or last retry, check if containers were created anyway
          // Docker compose might return non-zero exit code but still succeed
          const containers = await this.containerManager.getContainerInfo(challengeName);
          if (containers.victims.length > 0 || containers.attacker) {
            this.logger.warn('Deployer', 'Docker compose returned error but containers were created', {
              error: execError.message,
              containersFound: true
            });
            deploymentSuccess = true;
            break;
          }
          
          // Last retry or non-recoverable error
          if (retryCount >= maxRetries - 1) {
            // Log full error details for debugging
            this.logger.error('Deployer', 'Docker compose failed after all retries', {
              error: execError.message,
              stdout: stdout || 'No stdout',
              stderr: stderr || 'No stderr',
              isSubnetOverlap,
              retryCount,
              maxRetries
            });
            
            // If it's a subnet overlap, provide more specific error
            if (isSubnetOverlap) {
              const userError = new Error('Challenge deploy failed: Network subnet conflict. Please try again or check for existing networks.');
              userError.originalError = execError;
              throw userError;
            }
            
            // Throw user-friendly error without stack trace
            const userError = new Error('Challenge deploy failed');
            userError.originalError = execError; // Keep for logging
            throw userError;
          }
          
          retryCount++;
          await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1s before retry
        }
      }

      this.logger.debug('Deployer', 'Docker compose output', { 
        stdout: stdout?.substring(0, 1000), // First 1000 chars
        stderr: stderr?.substring(0, 1000)
      });

      // Wait for containers to start and check their status
      // Give containers time to stabilize (they may restart a few times)
      this.logger.info('Deployer', 'Waiting for containers to start and stabilize...');
      await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10s for containers to stabilize
      
      // Check if error was due to subnet overlap
      const isSubnetOverlap = stderr.includes('Pool overlaps') || 
                              stderr.includes('overlaps with other') ||
                              stdout.includes('Pool overlaps');
      
      if (isSubnetOverlap) {
        this.logger.error('Deployer', 'Subnet overlap detected during Docker network creation', {
          stderr: stderr.substring(0, 500)
        });
        throw new Error(`Subnet overlap: The allocated subnet conflicts with an existing Docker network. This should have been detected earlier. Please try deploying again - the system will allocate a new subnet.`);
      }

      // Check if containers were actually created
      const containers = await this.containerManager.getContainerInfo(challengeName);
      if (containers.victims.length === 0 && !containers.attacker) {
        this.logger.error('Deployer', 'No containers found after docker compose up', {
          stdout: stdout?.substring(0, 500),
          stderr: stderr?.substring(0, 500)
        });
        // Return user-friendly error without stack trace
        throw new Error('Challenge deploy failed');
      }
      
      // Check container exit status and logs if containers exited or restarting
      // But allow containers to restart a few times (they might be stabilizing)
      for (const victim of containers.victims) {
        if (!victim.running || (victim.status && victim.status.includes('Exited'))) {
          try {
            const container = this.docker.getContainer(victim.id);
            const inspect = await container.inspect();
            const exitCode = inspect.State.ExitCode;
            const restartCount = inspect.RestartCount || 0;
            
            // Only log as error if container has exited and not restarting
            // Exit code 137 (SIGKILL) might be from OOM or manual kill, not necessarily a failure
            if (exitCode !== 0 && exitCode !== 137 && restartCount < 3) {
              // Container might still be restarting, give it more time
              this.logger.info('Deployer', 'Container restarting, waiting for stabilization', {
                name: victim.name,
                exitCode,
                restartCount
              });
            } else if (restartCount >= 3 || (exitCode !== 0 && exitCode !== 137)) {
              // Container has restarted too many times or has a real error
              const logs = await container.logs({ stdout: true, stderr: true, tail: 50 });
              const logOutput = logs.toString();
              
              this.logger.warn('Deployer', 'Container issue detected, checking logs', {
                name: victim.name,
                exitCode,
                status: victim.status,
                running: inspect.State.Running,
                restartCount,
                logs: logOutput.substring(0, 1000)
              });
              
              // Log full error to console for debugging
              console.error(`\n❌ Container ${victim.name} Error Details:`);
              console.error(`   Status: ${victim.status}`);
              console.error(`   Exit Code: ${exitCode}`);
              console.error(`   Restart Count: ${restartCount}`);
              console.error(`   Last 50 lines of logs:\n${logOutput}`);
            }
          } catch (logError) {
            this.logger.warn('Deployer', 'Could not read container logs', { name: victim.name, error: logError.message });
          }
        } else if (victim.status && victim.status.includes('Restarting')) {
          // Container is restarting - this is okay, it might stabilize
          this.logger.info('Deployer', 'Container is restarting, will check again', {
            name: victim.name,
            status: victim.status
          });
        }
      }
      if (containers.attacker && !containers.attacker.running && containers.attacker.status?.includes('Exited')) {
        try {
          const container = this.docker.getContainer(containers.attacker.id);
          const inspect = await container.inspect();
          const exitCode = inspect.State.ExitCode;
          const logs = await container.logs({ stdout: true, stderr: true, tail: 30 });
          this.logger.warn('Deployer', 'Attacker container exited, checking logs', {
            name: containers.attacker.name,
            exitCode,
            status: containers.attacker.status,
            logs: logs.toString().substring(0, 500)
          });
        } catch (logError) {
          this.logger.warn('Deployer', 'Could not read attacker container logs', { error: logError.message });
        }
      }
      
      this.logger.info('Deployer', 'Containers found after compose up', {
        attacker: containers.attacker ? { name: containers.attacker.name, running: containers.attacker.running, status: containers.attacker.status } : 'NOT FOUND',
        victims: containers.victims.map(v => ({ name: v.name, running: v.running, status: v.status })),
        total: containers.victims.length + (containers.attacker ? 1 : 0)
      });

      // Get network information
      const networks = await this.getNetworkInfo(challengeName);

      return {
        success: true,
        networks
      };

    } catch (error) {
      this.logger.error('Deployer', 'Container deployment failed', error.stack);
      
      // Try to auto-fix and retry
      const fixResult = await this.attemptFix(error, challengePath);
      if (fixResult.fixed) {
        return await this.deployContainers(challengePath, challengeName);
      }

      // Return user-friendly error without exposing stack traces or file paths
      return {
        success: false,
        error: 'Challenge deploy failed',
        details: process.env.NODE_ENV === 'development' ? error.stack : undefined
      };
    }
  }

  /**
   * Get network information
   */
  async getNetworkInfo(challengeName) {
    try {
      const networks = await this.docker.listNetworks();
      const challengeNetwork = networks.find(n => 
        n.Name.includes(challengeName) && !n.Name.includes('ctf-instances-network')
      );

      return {
        challengeNetwork: challengeNetwork?.Name || null
      };
    } catch (error) {
      return {
        challengeNetwork: null
      };
    }
  }

  /**
   * Attempt to fix deployment error
   */
  async attemptFix(error, challengePath) {
    const errorMessage = error.message.toLowerCase();

    // Network removal errors
    if (errorMessage.includes('network has active endpoints')) {
      this.logger.info('Deployer', 'Fixing network removal error');
      // Already handled in prepareEnvironment
      return { fixed: true };
    }

    return { fixed: false };
  }
}


