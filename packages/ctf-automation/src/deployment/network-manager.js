/**
 * Network Manager - Manages Docker networks
 * 
 * Responsibilities:
 * - Connect/disconnect containers from networks
 * - Setup Guacamole network connections
 * - Verify network connectivity
 */

import Docker from 'dockerode';
import { Logger } from '../core/logger.js';

export class NetworkManager {
  constructor() {
    this.docker = new Docker();
    this.logger = new Logger();
  }

  /**
   * Setup networks for deployment
   */
  async setupNetworks(challengeName, containers) {
    try {
      this.logger.info('NetworkManager', 'Setting up networks', { challengeName });

      // Find challenge network
      const networks = await this.docker.listNetworks();
      const challengeNetwork = networks.find(n => 
        n.Name.includes(challengeName) && !n.Name.includes('ctf-instances-network')
      );

      if (!challengeNetwork) {
        throw new Error(`Challenge network not found for ${challengeName}`);
      }

      // Connect guacd to challenge network
      await this.connectGuacdToNetwork(challengeNetwork.Name);

      this.logger.success('NetworkManager', 'Networks setup complete');

    } catch (error) {
      this.logger.error('NetworkManager', 'Network setup failed', error.stack);
      throw error;
    }
  }

  /**
   * Connect guacd to challenge network
   */
  async connectGuacdToNetwork(networkName) {
    try {
      const guacdContainer = 'ctf-guacd-new';
      const network = this.docker.getNetwork(networkName);

      // Check if already connected
      const networkInfo = await network.inspect();
      const isConnected = networkInfo.Containers && 
        Object.values(networkInfo.Containers).some(c => c.Name === guacdContainer);

      if (!isConnected) {
        await network.connect({ Container: guacdContainer });
        this.logger.info('NetworkManager', 'Connected guacd to network', { networkName });
      }

    } catch (error) {
      this.logger.warn('NetworkManager', 'Failed to connect guacd', error.message);
      // Don't throw - this is not critical
    }
  }

  /**
   * Disconnect guacd from old networks
   */
  async disconnectGuacdFromOldNetworks(currentChallengeName) {
    try {
      const guacdContainer = 'ctf-guacd-new';
      const networks = await this.docker.listNetworks();

      for (const network of networks) {
        // Skip non-challenge networks
        if (!network.Name.includes('ctf-') || 
            network.Name.includes('ctf-instances-network') ||
            network.Name.includes('ctf-network') ||
            network.Name.includes(currentChallengeName)) {
          continue;
        }

        try {
          const networkObj = this.docker.getNetwork(network.Id);
          await networkObj.disconnect({ Container: guacdContainer, Force: true });
          this.logger.info('NetworkManager', 'Disconnected guacd from old network', { 
            network: network.Name 
          });
        } catch (error) {
          // Ignore errors - network might not be connected
        }
      }

    } catch (error) {
      this.logger.warn('NetworkManager', 'Failed to disconnect guacd from old networks', error.message);
    }
  }
}


