/**
 * Comprehensive Validation Agent
 * 
 * Performs thorough validation checks similar to manual validation:
 * - Subnet allocation and conflict detection
 * - Network overlap checking
 * - IP address validation
 * - Docker configuration validation
 * - Service configuration validation
 * 
 * Runs automatically during challenge creation and deployment
 */

import { execSync } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import yaml from 'js-yaml';
import { Logger } from '../core/logger.js';
import { subnetAllocator } from '../subnet-allocator.js';

export class ComprehensiveValidationAgent {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Comprehensive validation for challenge creation
   * Validates structure, subnet, IPs, and configurations
   */
  async validateChallengeCreation(structure, challengeName) {
    const results = {
      success: true,
      warnings: [],
      errors: [],
      fixes: []
    };

    this.logger.info('ComprehensiveValidationAgent', 'Starting comprehensive validation for challenge creation', { challengeName });

    // 1. Validate subnet allocation
    const subnetValidation = await this.validateSubnetAllocation(structure, challengeName);
    if (!subnetValidation.valid) {
      results.errors.push(...subnetValidation.errors);
      results.fixes.push(...subnetValidation.fixes);
      results.success = false;
    }
    if (subnetValidation.warnings) {
      results.warnings.push(...subnetValidation.warnings);
    }

    // 2. Validate network configuration
    const networkValidation = await this.validateNetworkConfiguration(structure);
    if (!networkValidation.valid) {
      results.errors.push(...networkValidation.errors);
      results.fixes.push(...networkValidation.fixes);
      results.success = false;
    }

    // 3. Validate IP addresses
    const ipValidation = await this.validateIPAddresses(structure);
    if (!ipValidation.valid) {
      results.errors.push(...ipValidation.errors);
      results.fixes.push(...ipValidation.fixes);
      results.success = false;
    }

    // 4. Check for Docker network conflicts
    const dockerValidation = await this.validateDockerNetworks(structure);
    if (!dockerValidation.valid) {
      results.errors.push(...dockerValidation.errors);
      results.fixes.push(...dockerValidation.fixes);
      results.success = false;
    }
    if (dockerValidation.warnings) {
      results.warnings.push(...dockerValidation.warnings);
    }

    // 5. Validate structure completeness
    const structureValidation = this.validateStructureCompleteness(structure);
    if (!structureValidation.valid) {
      results.errors.push(...structureValidation.errors);
      results.success = false;
    }

    if (results.success) {
      this.logger.success('ComprehensiveValidationAgent', 'Comprehensive validation passed', { challengeName });
    } else {
      this.logger.warn('ComprehensiveValidationAgent', 'Comprehensive validation found issues', {
        challengeName,
        errorCount: results.errors.length,
        warningCount: results.warnings.length
      });
    }

    return results;
  }

  /**
   * Comprehensive validation for challenge deployment
   * Validates existing challenge files and deployment readiness
   */
  async validateChallengeDeployment(challengeName) {
    const results = {
      success: true,
      warnings: [],
      errors: [],
      fixes: []
    };

    this.logger.info('ComprehensiveValidationAgent', 'Starting comprehensive validation for challenge deployment', { challengeName });

    const challengePath = path.join(process.env.CLONE_PATH || path.resolve(process.cwd(), 'challenges-repo'), 'challenges', challengeName);

    // 1. Check if challenge exists
    try {
      await fs.access(challengePath);
    } catch {
      results.errors.push(`Challenge directory not found: ${challengePath}`);
      results.success = false;
      return results;
    }

    // 2. Validate docker-compose.yml
    const composeValidation = await this.validateDockerComposeFile(challengePath, challengeName);
    if (!composeValidation.valid) {
      results.errors.push(...composeValidation.errors);
      results.fixes.push(...composeValidation.fixes);
      results.success = false;
    }

    // 3. Validate subnet in docker-compose.yml
    const subnetValidation = await this.validateDeploymentSubnet(challengePath, challengeName);
    if (!subnetValidation.valid) {
      results.errors.push(...subnetValidation.errors);
      results.fixes.push(...subnetValidation.fixes);
      results.success = false;
    }
    if (subnetValidation.warnings) {
      results.warnings.push(...subnetValidation.warnings);
    }

    // 4. Check for existing Docker networks
    const networkConflict = await this.checkNetworkConflicts(challengeName);
    if (networkConflict.hasConflict) {
      results.warnings.push(...networkConflict.warnings);
      results.fixes.push(...networkConflict.fixes);
    }

    // 5. Validate Dockerfiles exist
    const dockerfileValidation = await this.validateDockerfilesExist(challengePath);
    if (!dockerfileValidation.valid) {
      results.errors.push(...dockerfileValidation.errors);
      results.success = false;
    }

    if (results.success) {
      this.logger.success('ComprehensiveValidationAgent', 'Comprehensive deployment validation passed', { challengeName });
    } else {
      this.logger.warn('ComprehensiveValidationAgent', 'Comprehensive deployment validation found issues', {
        challengeName,
        errorCount: results.errors.length,
        warningCount: results.warnings.length
      });
    }

    return results;
  }

  /**
   * Validate subnet allocation
   */
  async validateSubnetAllocation(structure, challengeName) {
    const result = { valid: true, errors: [], warnings: [], fixes: [] };

    if (!structure.subnet) {
      result.valid = false;
      result.errors.push('Subnet not allocated in structure');
      return result;
    }

    const subnet = structure.subnet;
    const [ip, mask] = subnet.split('/');
    const ipParts = ip.split('.').map(Number);

    // Check if subnet is in reserved range (172.24.x.x overlaps with ctf-network)
    if (ipParts[0] === 172 && ipParts[1] === 24) {
      result.valid = false;
      result.errors.push(`Subnet ${subnet} is in reserved range 172.24.x.x (overlaps with ctf-network infrastructure)`);
      result.fixes.push({
        type: 'subnet_reallocation',
        description: 'Re-allocate subnet outside 172.24.x.x range',
        action: 'allocate_new_subnet'
      });
      return result;
    }

    // Check if third octet starts from 1 (not 0)
    if (ipParts[2] === 0) {
      result.warnings.push(`Subnet ${subnet} uses third octet 0 (should start from 1)`);
      result.fixes.push({
        type: 'subnet_octet',
        description: 'Third octet should start from 1, not 0',
        action: 'adjust_third_octet'
      });
    }

    // Check if subnet is in use
    const isInUse = subnetAllocator.isSubnetInUse(subnet);
    if (isInUse) {
      result.valid = false;
      result.errors.push(`Subnet ${subnet} is already in use by another network`);
      result.fixes.push({
        type: 'subnet_conflict',
        description: 'Subnet conflict detected, need to allocate different subnet',
        action: 'allocate_alternative_subnet'
      });
    }

    return result;
  }

  /**
   * Validate network configuration
   */
  async validateNetworkConfiguration(structure) {
    const result = { valid: true, errors: [], warnings: [], fixes: [] };

    // Network name is generated during compose generation, not structure building
    // So we generate it here for validation purposes, or check if it exists
    const networkName = structure.networkName || (structure.name ? `ctf-${structure.name}-net` : null);

    if (!networkName) {
      // If we can't generate a network name, it's a warning, not an error
      result.warnings.push('Network name not defined in structure (will be generated during compose generation)');
      return result;
    }

    // Check network name format
    if (!networkName.startsWith('ctf-')) {
      result.warnings.push(`Network name "${networkName}" should start with "ctf-"`);
    }

    // Validate subnet format
    if (structure.subnet && !/^172\.\d{1,3}\.\d{1,3}\.0\/24$/.test(structure.subnet)) {
      result.valid = false;
      result.errors.push(`Invalid subnet format: ${structure.subnet}. Expected format: 172.x.x.0/24`);
    }

    return result;
  }

  /**
   * Validate IP addresses
   */
  async validateIPAddresses(structure) {
    const result = { valid: true, errors: [], warnings: [], fixes: [] };

    if (!structure.machines || structure.machines.length === 0) {
      result.valid = false;
      result.errors.push('No machines defined in structure');
      return result;
    }

    const usedIPs = new Set();
    const subnet = structure.subnet;
    const [baseIP] = subnet.split('/');
    const baseParts = baseIP.split('.').slice(0, 3).join('.');

    // Check each machine's IP
    for (const machine of structure.machines) {
      if (!machine.ip) {
        result.valid = false;
        result.errors.push(`Machine "${machine.name}" missing IP address`);
        continue;
      }

      // Check IP format
      if (!/^172\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(machine.ip)) {
        result.valid = false;
        result.errors.push(`Invalid IP format for machine "${machine.name}": ${machine.ip}`);
        continue;
      }

      // Check if IP is in the same subnet
      if (!machine.ip.startsWith(baseParts)) {
        result.valid = false;
        result.errors.push(`Machine "${machine.name}" IP ${machine.ip} is not in subnet ${subnet}`);
      }

      // Check for duplicate IPs
      if (usedIPs.has(machine.ip)) {
        result.valid = false;
        result.errors.push(`Duplicate IP address ${machine.ip} assigned to multiple machines`);
      }
      usedIPs.add(machine.ip);

      // Check reserved IPs
      const lastOctet = parseInt(machine.ip.split('.')[3]);
      if (lastOctet === 0 || lastOctet === 1 || lastOctet === 255) {
        result.warnings.push(`Machine "${machine.name}" uses reserved IP ${machine.ip} (last octet: ${lastOctet})`);
      }
    }

    return result;
  }

  /**
   * Validate Docker networks for conflicts
   */
  async validateDockerNetworks(structure) {
    const result = { valid: true, errors: [], warnings: [], fixes: [] };

    if (!structure.subnet) {
      return result;
    }

    try {
      // Check if subnet overlaps with existing Docker networks
      const isInUse = subnetAllocator.isSubnetInUse(structure.subnet);
      if (isInUse) {
        result.valid = false;
        result.errors.push(`Subnet ${structure.subnet} conflicts with existing Docker network`);
        result.fixes.push({
          type: 'network_conflict',
          description: 'Subnet overlaps with existing network',
          action: 'reallocate_subnet'
        });
      }

      // Check for network name conflicts
      if (structure.networkName) {
        const networks = execSync('docker network ls --format "{{.Name}}"', { encoding: 'utf8' });
        const networkList = networks.trim().split('\n').filter(n => n);
        
        if (networkList.includes(structure.networkName)) {
          result.warnings.push(`Network name "${structure.networkName}" already exists`);
          result.fixes.push({
            type: 'network_name_conflict',
            description: 'Network name already exists, may need cleanup',
            action: 'check_existing_network'
          });
        }
      }
    } catch (error) {
      this.logger.warn('ComprehensiveValidationAgent', 'Could not check Docker networks', { error: error.message });
      result.warnings.push('Could not verify Docker network conflicts (Docker may not be accessible)');
    }

    return result;
  }

  /**
   * Validate structure completeness
   */
  validateStructureCompleteness(structure) {
    const result = { valid: true, errors: [], warnings: [] };

    // Required fields
    if (!structure.name) {
      result.valid = false;
      result.errors.push('Missing challenge name');
    }

    if (!structure.subnet) {
      result.valid = false;
      result.errors.push('Missing subnet allocation');
    }

    if (!structure.machines || structure.machines.length === 0) {
      result.valid = false;
      result.errors.push('No machines defined');
      return result;
    }

    // Validate each machine
    for (const machine of structure.machines) {
      if (!machine.name) {
        result.valid = false;
        result.errors.push('Machine missing name');
      }

      if (!machine.ip) {
        result.valid = false;
        result.errors.push(`Machine "${machine.name || 'unnamed'}" missing IP address`);
      }

      if (!machine.os) {
        result.valid = false;
        result.errors.push(`Machine "${machine.name || 'unnamed'}" missing OS specification`);
      }

      if (machine.type === 'victim' && (!machine.services || machine.services.length === 0)) {
        result.warnings.push(`Victim machine "${machine.name}" has no services defined`);
      }
    }

    return result;
  }

  /**
   * Validate docker-compose.yml file
   */
  async validateDockerComposeFile(challengePath, challengeName) {
    const result = { valid: true, errors: [], warnings: [], fixes: [] };

    const composeFile = path.join(challengePath, 'docker-compose.yml');

    try {
      const content = await fs.readFile(composeFile, 'utf8');
      const compose = yaml.load(content);

      // Validate YAML structure
      if (!compose) {
        result.valid = false;
        result.errors.push('docker-compose.yml is empty or invalid');
        return result;
      }

      // Check for services
      if (!compose.services || Object.keys(compose.services).length === 0) {
        result.valid = false;
        result.errors.push('No services defined in docker-compose.yml');
      }

      // Check for networks
      if (!compose.networks || Object.keys(compose.networks).length === 0) {
        result.valid = false;
        result.errors.push('No networks defined in docker-compose.yml');
      }

      // Check for obsolete version attribute
      if (compose.version) {
        result.warnings = result.warnings || [];
        result.warnings.push('docker-compose.yml contains obsolete "version" attribute (not needed in Compose v2)');
        result.fixes.push({
          type: 'remove_version',
          description: 'Remove obsolete version attribute',
          action: 'remove_version_attribute'
        });
      }

    } catch (error) {
      if (error.name === 'YAMLException') {
        result.valid = false;
        result.errors.push(`YAML syntax error in docker-compose.yml: ${error.message}`);
      } else {
        result.valid = false;
        result.errors.push(`Error reading docker-compose.yml: ${error.message}`);
      }
    }

    return result;
  }

  /**
   * Validate subnet in docker-compose.yml for deployment
   */
  async validateDeploymentSubnet(challengePath, challengeName) {
    const result = { valid: true, errors: [], warnings: [], fixes: [] };

    const composeFile = path.join(challengePath, 'docker-compose.yml');

    try {
      const content = await fs.readFile(composeFile, 'utf8');
      const compose = yaml.load(content);

      if (!compose.networks) {
        return result;
      }

      // Find challenge network (not external)
      const challengeNetwork = Object.keys(compose.networks).find(n => 
        !compose.networks[n].external && !n.includes('ctf-instances-network')
      );

      if (!challengeNetwork) {
        return result;
      }

      const networkConfig = compose.networks[challengeNetwork];
      if (networkConfig.ipam && networkConfig.ipam.config) {
        for (const config of networkConfig.ipam.config) {
          if (config.subnet) {
            const subnet = config.subnet;
            const [ip] = subnet.split('/');
            const ipParts = ip.split('.').map(Number);

            // Check for reserved range (172.24.x.x)
            if (ipParts[0] === 172 && ipParts[1] === 24) {
              result.valid = false;
              result.errors.push(`Subnet ${subnet} in docker-compose.yml is in reserved range 172.24.x.x`);
              result.fixes.push({
                type: 'subnet_reallocation',
                description: 'Re-allocate subnet outside 172.24.x.x range',
                action: 'reallocate_subnet'
              });
            }

            // Check if third octet is 0
            if (ipParts[2] === 0) {
              result.warnings.push(`Subnet ${subnet} uses third octet 0 (should start from 1)`);
            }

            // Check if subnet is in use
            const isInUse = subnetAllocator.isSubnetInUse(subnet);
            if (isInUse) {
              result.valid = false;
              result.errors.push(`Subnet ${subnet} conflicts with existing Docker network`);
              result.fixes.push({
                type: 'subnet_conflict',
                description: 'Subnet conflict detected',
                action: 'reallocate_subnet'
              });
            }
          }
        }
      }
    } catch (error) {
      this.logger.warn('ComprehensiveValidationAgent', 'Error validating deployment subnet', { error: error.message });
    }

    return result;
  }

  /**
   * Check for network conflicts with existing Docker networks
   */
  async checkNetworkConflicts(challengeName) {
    const result = { hasConflict: false, warnings: [], fixes: [] };

    try {
      const networkName = `ctf-${challengeName}-default-net`;
      const networks = execSync('docker network ls --format "{{.Name}}"', { encoding: 'utf8' });
      const networkList = networks.trim().split('\n').filter(n => n);

      if (networkList.includes(networkName)) {
        result.hasConflict = true;
        result.warnings.push(`Network "${networkName}" already exists`);
        result.fixes.push({
          type: 'network_cleanup',
          description: 'Existing network found, may need cleanup',
          action: 'remove_existing_network'
        });
      }
    } catch (error) {
      this.logger.warn('ComprehensiveValidationAgent', 'Could not check network conflicts', { error: error.message });
    }

    return result;
  }

  /**
   * Validate Dockerfiles exist
   */
  async validateDockerfilesExist(challengePath) {
    const result = { valid: true, errors: [], warnings: [] };

    try {
      const composeFile = path.join(challengePath, 'docker-compose.yml');
      const content = await fs.readFile(composeFile, 'utf8');
      const compose = yaml.load(content);

      if (!compose.services) {
        return result;
      }

      for (const [serviceName, serviceConfig] of Object.entries(compose.services)) {
        if (serviceConfig.build) {
          const buildContext = serviceConfig.build.context || '.';
          const dockerfile = serviceConfig.build.dockerfile || 'Dockerfile';
          const dockerfilePath = path.join(challengePath, buildContext, dockerfile);

          try {
            await fs.access(dockerfilePath);
          } catch {
            result.valid = false;
            result.errors.push(`Dockerfile not found for service "${serviceName}": ${dockerfilePath}`);
          }
        }
      }
    } catch (error) {
      result.valid = false;
      result.errors.push(`Error validating Dockerfiles: ${error.message}`);
    }

    return result;
  }

  /**
   * Apply automatic fixes based on validation results
   */
  async applyFixes(challengePath, fixes, challengeName) {
    const appliedFixes = [];

    for (const fix of fixes) {
      try {
        switch (fix.type) {
          case 'subnet_reallocation':
          case 'subnet_conflict':
            // Actually trigger subnet reallocation by updating docker-compose.yml
            this.logger.info('ComprehensiveValidationAgent', 'Reallocating subnet to fix conflict', { challengeName });
            await this.reallocateSubnet(challengePath, challengeName);
            appliedFixes.push(fix);
            break;

          case 'remove_version':
            await this.removeVersionAttribute(challengePath);
            appliedFixes.push(fix);
            break;

          case 'network_cleanup':
            this.logger.info('ComprehensiveValidationAgent', 'Network cleanup may be needed', { challengeName });
            appliedFixes.push(fix);
            break;

          default:
            this.logger.debug('ComprehensiveValidationAgent', 'No automatic fix available', { fixType: fix.type });
        }
      } catch (error) {
        this.logger.warn('ComprehensiveValidationAgent', 'Failed to apply fix', { fixType: fix.type, error: error.message });
      }
    }

    return appliedFixes;
  }

  /**
   * Remove version attribute from docker-compose.yml
   */
  async removeVersionAttribute(challengePath) {
    const composeFile = path.join(challengePath, 'docker-compose.yml');
    const content = await fs.readFile(composeFile, 'utf8');
    const compose = yaml.load(content);

    if (compose.version) {
      delete compose.version;
      const newContent = yaml.dump(compose, { lineWidth: -1 });
      await fs.writeFile(composeFile, newContent, 'utf8');
      this.logger.info('ComprehensiveValidationAgent', 'Removed version attribute from docker-compose.yml');
    }
  }

  /**
   * Reallocate subnet for a challenge by updating docker-compose.yml
   */
  async reallocateSubnet(challengePath, challengeName) {
    try {
      const { subnetAllocator } = await import('../subnet-allocator.js');
      const composeFile = path.join(challengePath, 'docker-compose.yml');
      const content = await fs.readFile(composeFile, 'utf8');
      const compose = yaml.load(content);

      // Find challenge network
      const networks = compose.networks || {};
      const challengeNetwork = Object.keys(networks).find(n => 
        !n.includes('ctf-instances-network') && !n.includes('external')
      );

      if (!challengeNetwork) {
        this.logger.warn('ComprehensiveValidationAgent', 'No challenge network found for reallocation');
        return;
      }

      // Count services to determine victim count
      const services = compose.services || {};
      const victimServices = Object.keys(services).filter(name => 
        !name.includes('attacker') && !name.includes('database') && !name.includes('api')
      );
      const victimCount = victimServices.length;
      const hasDatabase = Object.keys(services).some(name => name.includes('database'));
      const hasAPI = Object.keys(services).some(name => name.includes('api'));

      // Force new subnet allocation
      this.logger.info('ComprehensiveValidationAgent', 'Allocating new subnet', {
        challengeName,
        victimCount,
        forceNew: true
      });

      // Release existing allocation first
      try {
        await subnetAllocator.releaseSubnet(challengeName, 'default');
        this.logger.info('ComprehensiveValidationAgent', 'Released existing subnet allocation', { challengeName });
      } catch (releaseError) {
        this.logger.debug('ComprehensiveValidationAgent', 'No existing allocation to release', { error: releaseError.message });
      }

      const newAllocation = await subnetAllocator.allocateSubnet(challengeName, 'default', {
        victimCount,
        randomizeIPs: true,
        forceNew: true, // Force new allocation to avoid conflicts
        needsDatabase: hasDatabase,
        needsAPI: hasAPI
      });

      // Update docker-compose.yml with new subnet
      const networkConfig = networks[challengeNetwork];
      if (networkConfig.ipam && networkConfig.ipam.config) {
        networkConfig.ipam.config[0].subnet = newAllocation.subnet;
        networkConfig.ipam.config[0].gateway = newAllocation.gateway;
      } else {
        networks[challengeNetwork] = {
          driver: 'bridge',
          ipam: {
            config: [{
              subnet: newAllocation.subnet,
              gateway: newAllocation.gateway
            }]
          }
        };
      }

      // Update service IPs
      let victimIndex = 0;
      for (const [serviceName, serviceConfig] of Object.entries(services)) {
        if (serviceConfig.networks && serviceConfig.networks[challengeNetwork]) {
          const networkConfig = serviceConfig.networks[challengeNetwork];
          
          if (serviceName.includes('attacker')) {
            networkConfig.ipv4_address = newAllocation.ips.attacker;
          } else if (serviceName.includes('database')) {
            networkConfig.ipv4_address = newAllocation.ips.database;
          } else if (serviceName.includes('api')) {
            networkConfig.ipv4_address = newAllocation.ips.api;
          } else {
            // Victim machine
            const victimIPs = newAllocation.ips.victims || [];
            if (victimIndex < victimIPs.length) {
              networkConfig.ipv4_address = victimIPs[victimIndex];
            } else {
              // Fallback to sequential IPs
              const baseIP = newAllocation.subnet.split('/')[0].split('.').slice(0, 3).join('.');
              networkConfig.ipv4_address = `${baseIP}.${10 + victimIndex}`;
            }
            victimIndex++;
          }
        }
      }

      // Write updated compose file
      const newContent = yaml.dump(compose, { lineWidth: -1 });
      await fs.writeFile(composeFile, newContent, 'utf8');

      this.logger.success('ComprehensiveValidationAgent', 'Subnet reallocated successfully', {
        challengeName,
        newSubnet: newAllocation.subnet
      });

    } catch (error) {
      this.logger.error('ComprehensiveValidationAgent', 'Failed to reallocate subnet', error.stack);
      throw error;
    }
  }
}

export const comprehensiveValidationAgent = new ComprehensiveValidationAgent();

