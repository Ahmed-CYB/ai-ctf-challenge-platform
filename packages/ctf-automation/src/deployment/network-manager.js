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
   * CRITICAL: Connects guacd to challenge network so Guacamole can access attacker
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
        this.logger.error('NetworkManager', 'Challenge network not found', { challengeName, availableNetworks: networks.map(n => n.Name) });
        throw new Error(`Challenge network not found for ${challengeName}`);
      }

      this.logger.info('NetworkManager', 'Found challenge network', { 
        networkName: challengeNetwork.Name,
        networkId: challengeNetwork.Id 
      });

      // CRITICAL: Connect guacd to challenge network (enables Guacamole access)
      const connected = await this.connectGuacdToNetwork(challengeNetwork.Name);
      
      if (connected) {
        this.logger.success('NetworkManager', 'Networks setup complete - Guacamole can now access attacker');
        return true;
      } else {
        this.logger.warn('NetworkManager', 'Network setup completed but guacd connection had issues');
        return false;
      }

    } catch (error) {
      this.logger.error('NetworkManager', 'Network setup failed', error.stack);
      // Don't throw - allow deployment to continue even if guacd connection fails
      // The connection can be retried later
      return false;
    }
  }

  /**
   * Connect guacd to challenge network
   * CRITICAL: This enables Guacamole to access the attacker container
   */
  async connectGuacdToNetwork(networkName) {
    const guacdContainer = 'ctf-guacd-new';
    const maxRetries = 3;
    let lastError = null;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const network = this.docker.getNetwork(networkName);

        // Check if already connected
        const networkInfo = await network.inspect();
        const isConnected = networkInfo.Containers && 
          Object.values(networkInfo.Containers).some(c => c.Name === guacdContainer);

        if (isConnected) {
          this.logger.info('NetworkManager', 'Guacd already connected to network', { networkName });
          return true;
        }

        // Connect guacd to network
        await network.connect({ Container: guacdContainer });
        
        // Verify connection
        await new Promise(resolve => setTimeout(resolve, 1000));
        const verifyInfo = await network.inspect();
        const verified = verifyInfo.Containers && 
          Object.values(verifyInfo.Containers).some(c => c.Name === guacdContainer);

        if (verified) {
          this.logger.success('NetworkManager', 'Connected guacd to network', { networkName });
          return true;
        } else {
          throw new Error('Connection verification failed');
        }

      } catch (error) {
        lastError = error;
        this.logger.warn('NetworkManager', `Failed to connect guacd (attempt ${attempt}/${maxRetries})`, { 
          networkName, 
          error: error.message 
        });
        
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
        }
      }
    }

    // If all retries failed, log error but don't throw (deployment can continue)
    this.logger.error('NetworkManager', 'Failed to connect guacd after all retries', lastError?.stack);
    return false;
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


