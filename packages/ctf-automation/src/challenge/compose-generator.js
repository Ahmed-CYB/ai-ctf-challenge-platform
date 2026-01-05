/**
 * Compose Generator - Generates perfect docker-compose.yml
 * 
 * Responsibilities:
 * - Generate docker-compose.yml with correct syntax
 * - Configure networks correctly
 * - Set up IP addresses
 * - Include all required services
 */

import yaml from 'js-yaml';
import { Logger } from '../core/logger.js';
import { linuxOnlyValidator } from '../core/linux-only-validator.js';

export class ComposeGenerator {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Generate docker-compose.yml
   */
  async generate(structure, dockerfiles) {
    try {
      this.logger.info('ComposeGenerator', 'Generating docker-compose.yml');

      const compose = {
        services: {},
        networks: {}
      };

      // Add each machine as a service
      for (const machine of structure.machines) {
        const dockerfile = dockerfiles.find(df => df.machineName === machine.name);
        compose.services[machine.name] = this.buildService(machine, dockerfile, structure);
      }

      // Add network configuration
      compose.networks = this.buildNetworks(structure);

      // Convert to YAML
      const yamlContent = yaml.dump(compose, {
        indent: 2,
        lineWidth: -1,
        noRefs: true
      });

      // Validate YAML syntax
      try {
        yaml.load(yamlContent);
      } catch (yamlError) {
        throw new Error(`Generated invalid YAML: ${yamlError.message}`);
      }

      // 🔒 CRITICAL: Validate docker-compose for Windows images
      const composeValidation = await linuxOnlyValidator.validateDockerCompose(compose);
      if (!composeValidation.valid) {
        this.logger.error('ComposeGenerator', 'Windows images detected in docker-compose', {
          errors: composeValidation.errors
        });
        throw new Error(
          `docker-compose.yml contains Windows-specific content: ` +
          composeValidation.errors.join('; ')
        );
      }

      if (composeValidation.warnings.length > 0) {
        this.logger.warn('ComposeGenerator', 'Docker-compose validation warnings', composeValidation.warnings);
      }

      this.logger.success('ComposeGenerator', 'docker-compose.yml generated');

      return {
        success: true,
        data: {
          content: yamlContent,
          path: 'docker-compose.yml'
        }
      };

    } catch (error) {
      this.logger.error('ComposeGenerator', 'Generation failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Build service configuration
   */
  buildService(machine, dockerfile, structure) {
    const service = {
      build: {
        context: `./${machine.name}`,
        dockerfile: machine.role === 'attacker' ? 'Dockerfile' : 'Dockerfile'
      },
      container_name: `ctf-${structure.name}-${machine.name}`,
      networks: {}
    };

    // Add network configuration
    const networkName = `ctf-${structure.name}-net`;
    service.networks[networkName] = {
      ipv4_address: machine.ip
    };

    // Attacker needs capabilities for network tools
    if (machine.role === 'attacker') {
      // SECURITY: Attacker is NOT connected to ctf-instances-network
      // Guacamole connects to challenge network instead (via guacd)
      service.cap_add = ['NET_RAW', 'NET_ADMIN'];
      // Attacker needs stdin_open and tty for interactive shell
      service.stdin_open = true;
      service.tty = true;
    }

    // Add restart policy
    service.restart = 'unless-stopped';

    return service;
  }

  /**
   * Build network configuration
   */
  buildNetworks(structure) {
    const networks = {
      [`ctf-${structure.name}-net`]: {
        name: `ctf-${structure.name}-net`, // Explicit name to prevent Docker Compose prefixing
        driver: 'bridge',
        // SECURITY: Make network internal to prevent access to external networks
        // Guacamole (guacd) will connect to this network to access attacker
        internal: false, // Keep false so guacd can connect, but we'll use iptables to block gateway
        ipam: {
          config: [{
            subnet: structure.subnet,
            gateway: this.getGateway(structure.subnet)
          }]
        }
      }
    };

    return networks;
  }

  /**
   * Get gateway IP from subnet
   */
  getGateway(subnet) {
    // Extract network address and set .1 as gateway
    const parts = subnet.split('/');
    const network = parts[0];
    const ipParts = network.split('.');
    ipParts[3] = '1';
    return ipParts.join('.');
  }
}


