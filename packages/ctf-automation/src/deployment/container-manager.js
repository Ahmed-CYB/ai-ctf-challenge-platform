/**
 * Container Manager - Manages container lifecycle
 * 
 * Responsibilities:
 * - Get container information
 * - Start/stop containers
 * - Monitor container status
 * - Fix container issues
 */

import Docker from 'dockerode';
import { Logger } from '../core/logger.js';

export class ContainerManager {
  constructor() {
    this.docker = new Docker();
    this.logger = new Logger();
  }

  /**
   * Get container information for a challenge
   */
  async getContainerInfo(challengeName) {
    try {
      const containers = await this.docker.listContainers({ all: true });
      
      const challengeContainers = containers.filter(c => 
        c.Names.some(name => name.includes(challengeName))
      );

      const info = {
        attacker: null,
        victims: []
      };

      for (const container of challengeContainers) {
        const containerObj = this.docker.getContainer(container.Id);
        const inspect = await containerObj.inspect();

        const isAttacker = container.Names.some(name => 
          name.includes('attacker') || inspect.Config.Labels?.['com.ctf.machine.type'] === 'attacker'
        );

        const containerInfo = {
          id: container.Id,
          name: container.Names[0].replace('/', ''),
          status: container.Status,
          ip: this.extractIP(inspect),
          running: container.Status.startsWith('Up')
        };

        if (isAttacker) {
          info.attacker = containerInfo;
        } else {
          info.victims.push(containerInfo);
        }
      }

      return info;

    } catch (error) {
      this.logger.error('ContainerManager', 'Failed to get container info', error.stack);
      throw error;
    }
  }

  /**
   * Extract IP address from container inspect
   */
  extractIP(inspect) {
    const networks = inspect.NetworkSettings?.Networks || {};
    
    // Try to find challenge network (contains challenge name or ctf- prefix)
    // Priority: challenge-specific network > any non-bridge network
    const networkNames = Object.keys(networks);
    
    // First, try to find a network that contains the challenge name pattern
    let challengeNetwork = networkNames.find(n => 
      n.includes('ctf-') && 
      !n.includes('ctf-instances-network') && 
      !n.includes('bridge') &&
      !n.includes('host')
    );

    // If not found, try any non-default network
    if (!challengeNetwork) {
      challengeNetwork = networkNames.find(n => 
        !n.includes('bridge') &&
        !n.includes('host') &&
        n !== 'none'
      );
    }

    // Get IP from the network
    if (challengeNetwork && networks[challengeNetwork]?.IPAddress) {
      const ip = networks[challengeNetwork].IPAddress;
      this.logger.debug('ContainerManager', 'Extracted IP', { 
        network: challengeNetwork, 
        ip 
      });
      return ip;
    }

    // Log all available networks for debugging
    this.logger.debug('ContainerManager', 'No IP found, available networks', {
      networks: networkNames,
      networkDetails: Object.entries(networks).map(([name, config]) => ({
        name,
        ip: config?.IPAddress || 'none'
      }))
    });

    return null;
  }

  /**
   * Start a container
   */
  async startContainer(containerName) {
    try {
      const container = this.docker.getContainer(containerName);
      await container.start();
      this.logger.info('ContainerManager', 'Container started', { containerName });
      return { success: true };
    } catch (error) {
      this.logger.error('ContainerManager', 'Failed to start container', error.stack);
      return { success: false, error: error.message };
    }
  }

  /**
   * Restart a container
   */
  async restartContainer(containerName) {
    try {
      const container = this.docker.getContainer(containerName);
      await container.restart();
      this.logger.info('ContainerManager', 'Container restarted', { containerName });
      return { success: true };
    } catch (error) {
      this.logger.error('ContainerManager', 'Failed to restart container', error.stack);
      return { success: false, error: error.message };
    }
  }

  /**
   * Get all running challenge names (excluding the specified challenge)
   */
  async getRunningChallenges(excludeChallengeName = null) {
    try {
      const containers = await this.docker.listContainers({ all: false }); // Only running containers
      
      const challengeNames = new Set();
      
      for (const container of containers) {
        const name = container.Names[0]?.replace('/', '') || '';
        
        // Extract challenge name from container name pattern: ctf-{challengeName}-{machineType}
        const match = name.match(/^ctf-(.+?)-(attacker|victim|database|api)/);
        if (match) {
          const challengeName = match[1];
          if (!excludeChallengeName || challengeName !== excludeChallengeName) {
            challengeNames.add(challengeName);
          }
        }
      }
      
      return Array.from(challengeNames);
    } catch (error) {
      this.logger.error('ContainerManager', 'Failed to get running challenges', error.stack);
      return [];
    }
  }
}


