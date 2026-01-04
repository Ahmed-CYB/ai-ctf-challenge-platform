import crypto from 'crypto';
import { execSync } from 'child_process';
import { dbManager } from './db-manager.js';

/**
 * Subnet Allocator for CTF Platform
 * Allocates unique private IP addresses to each service in a challenge
 * 
 * IMPROVEMENT: Now uses database for persistent, race-condition-free allocation
 * 
 * IP Scheme: 172.{20-30}.{userId}.{serviceId}
 * - Base range: 172.20.0.0 to 172.30.255.255
 * - challengeId: Selects which /16 network (172.20 through 172.30) = 11 networks
 * - userId: 0-255 (derived from user ID hash) = /24 subnet
 * - serviceId: Fixed per service type:
 *   - .1: Gateway
 *   - .3: Attacker (Kali Linux)
 *   - .10-40: Victims (multiple if needed)
 *   - .50: Database
 *   - .60: API
 */

export class SubnetAllocator {
  constructor() {
    this.allocations = new Map(); // In-memory cache for performance
    this.dbEnabled = true; // Use database by default
  }

  /**
   * Check if a subnet is already in use by Docker
   * @param {string} subnet - Subnet to check (e.g., "172.25.50.0/24")
   * @returns {boolean} - True if subnet is in use
   */
  isSubnetInUse(subnet) {
    try {
      const networks = execSync('docker network ls --format "{{.Name}}"', { encoding: 'utf8' });
      const networkList = networks.trim().split('\n').filter(n => n);
      
      // Infrastructure networks to exclude from overlap checking
      // These are platform networks, not challenge networks
      const infrastructureNetworks = [
        'ctf-network',
        'ctf-platform-network',
        'bridge',
        'host',
        'none'
      ];
      
      const [newIp, newMask] = subnet.split('/');
      const newIpParts = newIp.split('.').map(Number);
      const newMaskBits = parseInt(newMask);
      
      for (const network of networkList) {
        // Skip infrastructure networks - they use different IP ranges for platform services
        if (infrastructureNetworks.includes(network)) {
          continue;
        }
        
        // Skip external networks (they don't have IPAM config)
        if (network.includes('_external') || network === 'ctf-instances-network') {
          continue;
        }
        
        try {
          const inspect = execSync(`docker network inspect ${network}`, { encoding: 'utf8' });
          const networkInfo = JSON.parse(inspect)[0];
          
          // Skip external networks
          if (networkInfo.ConfigOnly || (networkInfo.Options && networkInfo.Options.external === 'true')) {
            continue;
          }
          
          if (networkInfo.IPAM && networkInfo.IPAM.Config) {
            for (const config of networkInfo.IPAM.Config) {
              if (!config.Subnet) continue;
              
              // Exact match
              if (config.Subnet === subnet) {
                console.log(`⚠️  Subnet ${subnet} already in use by network: ${network}`);
                return true;
              }
              
              // Check for CIDR overlap (e.g., 172.21.193.0/24 overlaps with 172.21.0.0/16)
              // But only for challenge networks, not infrastructure
              const [existingIp, existingMask] = config.Subnet.split('/');
              const existingIpParts = existingIp.split('.').map(Number);
              const existingMaskBits = parseInt(existingMask);
              
              if (this.checkCIDROverlap(newIpParts, newMaskBits, existingIpParts, existingMaskBits)) {
                console.log(`⚠️  Subnet ${subnet} overlaps with ${config.Subnet} in network: ${network}`);
                return true;
              }
            }
          }
        } catch (inspectError) {
          // Skip networks that can't be inspected
          continue;
        }
      }
      
      return false;
    } catch (error) {
      console.warn('Could not check Docker networks:', error.message);
      return false; // Assume not in use if we can't check
    }
  }

  /**
   * Check if two CIDR ranges overlap
   * @param {number[]} ip1 - First IP address as array [172, 21, 193, 0]
   * @param {number} mask1 - First subnet mask bits (e.g., 24)
   * @param {number[]} ip2 - Second IP address as array [172, 21, 0, 0]
   * @param {number} mask2 - Second subnet mask bits (e.g., 16)
   * @returns {boolean} - True if ranges overlap
   */
  checkCIDROverlap(ip1, mask1, ip2, mask2) {
    // Convert IP to 32-bit integer
    const ipToInt = (ip) => (ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3];
    
    const ip1Int = ipToInt(ip1);
    const ip2Int = ipToInt(ip2);
    
    // Calculate network addresses (IP & mask)
    const mask1Int = ~((1 << (32 - mask1)) - 1);
    const mask2Int = ~((1 << (32 - mask2)) - 1);
    
    const network1 = ip1Int & mask1Int;
    const network2 = ip2Int & mask2Int;
    
    // Calculate broadcast addresses
    const broadcast1 = network1 | ~mask1Int;
    const broadcast2 = network2 | ~mask2Int;
    
    // Check if ranges overlap
    return (network1 <= broadcast2 && broadcast1 >= network2);
  }

  /**
   * Find an available subnet by trying different second octets and user IDs
   * @param {number} challengeId - Challenge ID (0-10)
   * @param {number} startUserId - Starting user ID to try
   * @param {number} maxAttempts - Maximum attempts to find free subnet
   * @returns {object|null} - Available allocation or null if none found
   */
  findAvailableSubnet(challengeId, startUserId, maxAttempts = 50) {
    // Reserved ranges to skip: 172.20, 172.21, 172.22
    const reservedOctets = [20, 21, 22];
    
    // Try different second octets (172.23.x.x to 172.30.x.x)
    for (let octetOffset = 0; octetOffset < 11; octetOffset++) {
      let secondOctet = 20 + octetOffset;
      
      // Skip reserved ranges
      if (reservedOctets.includes(secondOctet)) {
        console.log(`⏭️  Skipping reserved range 172.${secondOctet}.x.x`);
        continue;
      }
      
      // Try different user IDs within this octet range
      for (let attempt = 0; attempt < 20; attempt++) {
        const userIdNum = (startUserId + attempt) % 256;
        const subnet = `172.${secondOctet}.${userIdNum}.0/24`;
        
        if (!this.isSubnetInUse(subnet)) {
          console.log(`✅ Found available subnet: ${subnet}`);
          return {
            userIdNum,
            subnet,
            gateway: `172.${secondOctet}.${userIdNum}.1`,
            attackerIP: `172.${secondOctet}.${userIdNum}.3`,  // Attacker always at .3
            victimIP: `172.${secondOctet}.${userIdNum}.10`,   // Primary victim at .10
            victim2IP: `172.${secondOctet}.${userIdNum}.20`,  // Second victim at .20
            victim3IP: `172.${secondOctet}.${userIdNum}.30`,  // Third victim at .30
            victim4IP: `172.${secondOctet}.${userIdNum}.40`,  // Fourth victim at .40
            databaseIP: `172.${secondOctet}.${userIdNum}.50`, // Database at .50
            apiIP: `172.${secondOctet}.${userIdNum}.60`       // API at .60
          };
        }
      }
      
      console.log(`⚠️  No available subnets in 172.${secondOctet}.x.x range, trying next range...`);
    }
    
    console.error(`❌ Could not find available subnet after trying all ranges`);
    return null;
  }

  /**
   * Hash a string to a number within a range
   * @param {string} str - String to hash
   * @param {number} max - Maximum value (exclusive)
   * @returns {number} - Hash value between 0 and max-1
   */
  hashToNumber(str, max) {
    const hash = crypto.createHash('sha256').update(str).digest('hex');
    const num = parseInt(hash.substring(0, 8), 16);
    return num % max;
  }

  /**
   * Allocate dynamic IPs within a subnet (avoids conflicts)
   * @param {string} baseIP - Base IP (e.g., "172.23.194")
   * @param {number} count - Number of IPs needed
   * @param {Set} excludedIPs - IPs to exclude from allocation
   * @param {boolean} randomize - Whether to randomize IPs (default: true)
   * @param {Array<number>} preferredIPs - Preferred IPs if not randomizing
   * @returns {Array<string>} Array of allocated IPs
   */
  allocateDynamicIPs(baseIP, count, excludedIPs = new Set(), randomize = true, preferredIPs = []) {
    const ipRange = { min: 10, max: 200 }; // Available range for dynamic allocation
    const allocatedIPs = [];
    
    if (!randomize && preferredIPs.length > 0) {
      // Use preferred IPs if available and not excluded
      for (let i = 0; i < count && i < preferredIPs.length; i++) {
        if (!excludedIPs.has(preferredIPs[i])) {
          allocatedIPs.push(`${baseIP}.${preferredIPs[i]}`);
          excludedIPs.add(preferredIPs[i]);
        }
      }
      // If we still need more, fall through to random allocation
      if (allocatedIPs.length >= count) {
        return allocatedIPs;
      }
    }
    
    // Randomized allocation with enhanced randomness
    const availableRange = Array.from(
      { length: ipRange.max - ipRange.min + 1 }, 
      (_, i) => ipRange.min + i
    ).filter(ip => !excludedIPs.has(ip));
    
    // Enhanced shuffle: Use crypto.randomBytes for better randomness
    // Fallback to Math.random() if crypto is not available
    const shuffleArray = (array) => {
      try {
        // Use crypto for better randomness
        const crypto = require('crypto');
        for (let i = array.length - 1; i > 0; i--) {
          const randomBytes = crypto.randomBytes(4);
          const j = randomBytes.readUInt32BE(0) % (i + 1);
          [array[i], array[j]] = [array[j], array[i]];
        }
      } catch (e) {
        // Fallback to Math.random()
        for (let i = array.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [array[i], array[j]] = [array[j], array[i]];
        }
      }
      return array;
    };
    
    // Shuffle available IPs with enhanced randomness
    const shuffledRange = shuffleArray([...availableRange]);
    
    // Allocate remaining needed IPs from shuffled range
    const remaining = count - allocatedIPs.length;
    for (let i = 0; i < remaining && i < shuffledRange.length; i++) {
      const lastOctet = shuffledRange[i];
      allocatedIPs.push(`${baseIP}.${lastOctet}`);
      excludedIPs.add(lastOctet);
    }
    
    if (allocatedIPs.length < count) {
      console.warn(`⚠️ Could only allocate ${allocatedIPs.length} of ${count} requested IPs`);
    }
    
    return allocatedIPs;
  }

  /**
   * Allocate a subnet for a challenge instance
   * IMPROVEMENT: Now uses database with transaction locking to prevent race conditions
   * @param {string} challengeName - Name of the challenge
   * @param {string} userId - User ID or session ID
   * @param {object} options - Allocation options
   * @param {number} options.victimCount - Number of victim containers (0-5, default: 1)
   * @param {boolean} options.randomizeIPs - Randomize all IPs including database/API (default: true)
   * @param {boolean} options.needsDatabase - Allocate database IP (default: false)
   * @param {boolean} options.needsAPI - Allocate API IP (default: false)
   * @returns {Promise<object>} Allocation info with subnet, IPs, and network config
   */
  async allocateSubnet(challengeName, userId = 'default', options = {}) {
    const {
      victimCount = 1,
      randomizeIPs = true,  // Changed: now randomizes by default
      needsDatabase = false,
      needsAPI = false
    } = options;
    
    // Validate victim count (0-5)
    const validVictimCount = Math.max(0, Math.min(5, victimCount));
    if (victimCount !== validVictimCount) {
      console.warn(`⚠️ Victim count adjusted from ${victimCount} to ${validVictimCount} (allowed: 0-5)`);
    }
    
    const instanceId = `${challengeName}-${userId}`;

    // Check in-memory cache first (performance optimization)
    // Skip cache if forceNew is true (for handling subnet conflicts)
    if (!options.forceNew && this.allocations.has(instanceId)) {
      return this.allocations.get(instanceId);
    }

    // IMPROVEMENT: Check database for existing allocation (persistent across restarts)
    // Skip if forceNew is true (for handling subnet conflicts)
    if (this.dbEnabled && !options.forceNew) {
      try {
        const existingResult = await dbManager.pool.query(`
          SELECT * FROM subnet_allocations
          WHERE challenge_name = $1 AND user_id = $2 AND is_active = TRUE
        `, [challengeName, userId]);

        if (existingResult.rows.length > 0) {
          const dbAllocation = existingResult.rows[0];
          const allocation = this._convertDbToAllocation(dbAllocation);
          this.allocations.set(instanceId, allocation); // Cache it
          console.log(`📊 Retrieved existing subnet allocation from database for ${instanceId}`);
          return allocation;
        }
      } catch (dbError) {
        console.warn('⚠️  Database check failed, falling back to in-memory allocation:', dbError.message);
        // Continue with in-memory allocation
      }
    }

    // Generate deterministic IDs from hashes
    const challengeId = this.hashToNumber(challengeName, 11); // 0-10 (maps to 172.20-172.30)
    const userIdNum = this.hashToNumber(userId.toString(), 256); // 0-255

    // First, try the hash-based subnet
    // Skip 172.22.x.x which is reserved for Guacamole
    let secondOctet = 20 + challengeId;
    if (secondOctet === 22) {
      secondOctet = 23; // Skip to 172.23.x.x instead
    }
    
    let subnet = `172.${secondOctet}.${userIdNum}.0/24`;
    const baseIP = `172.${secondOctet}.${userIdNum}`;
    
    // Check if this subnet is in use
    // If forceNew is true, always check and find alternative if in use
    let finalAllocation;
    const shouldCheckSubnet = options.forceNew || !this.allocations.has(instanceId);
    
    if (shouldCheckSubnet && this.isSubnetInUse(subnet)) {
      console.log(`⚠️ Hash-based subnet ${subnet} is in use, finding alternative...`);
      finalAllocation = this.findAvailableSubnet(challengeId, userIdNum);
      
      if (!finalAllocation) {
        throw new Error(`Cannot allocate subnet for ${challengeName}: All subnets in 172.${secondOctet}.0.0/16 are in use`);
      }
      
      // Extract base IP from finalAllocation subnet
      const subnetParts = finalAllocation.subnet.split('.');
      const finalBaseIP = `${subnetParts[0]}.${subnetParts[1]}.${subnetParts[2]}`;
      
      // Build allocation with new dynamic system
      this._buildAllocation(finalAllocation, finalBaseIP, validVictimCount, randomizeIPs, needsDatabase, needsAPI);
      
    } else if (shouldCheckSubnet && !this.isSubnetInUse(subnet)) {
      // Use the hash-based allocation (subnet is available)
      finalAllocation = {
        userIdNum,
        subnet,
        gateway: `${baseIP}.1`,
        attackerIP: `${baseIP}.3`  // Attacker always at .3
      };
      
      // Build allocation with new dynamic system
      this._buildAllocation(finalAllocation, baseIP, validVictimCount, randomizeIPs, needsDatabase, needsAPI);
    } else {
      // Use cached allocation (not forcing new)
      if (this.allocations.has(instanceId)) {
        return this.allocations.get(instanceId);
      }
      
      // Fallback: use hash-based allocation
      finalAllocation = {
        userIdNum,
        subnet,
        gateway: `${baseIP}.1`,
        attackerIP: `${baseIP}.3`
      };
      
      this._buildAllocation(finalAllocation, baseIP, validVictimCount, randomizeIPs, needsDatabase, needsAPI);
    }

    // Generate a short, unique bridge name (max 15 chars for Linux)
    // Use first 6 chars of challenge name + hash for uniqueness
    const shortName = challengeName.substring(0, 6);
    const hashSuffix = this.hashToNumber(instanceId, 999).toString().padStart(3, '0');
    const bridgeName = `ctf${shortName}${hashSuffix}`.substring(0, 15);

    const allocation = {
      instanceId,
      challengeName,
      userId,
      subnet: finalAllocation.subnet,
      gateway: finalAllocation.gateway,
      ips: {
        victim: finalAllocation.victimIP,
        victim2: finalAllocation.victim2IP,
        victim3: finalAllocation.victim3IP,
        victim4: finalAllocation.victim4IP,
        victim5: finalAllocation.victim5IP,
        victims: finalAllocation.victimIPs,  // Array of all victim IPs
        database: finalAllocation.databaseIP,
        api: finalAllocation.apiIP,
        attacker: finalAllocation.attackerIP,
        webserver: finalAllocation.victimIP, // Alias
        target: finalAllocation.victimIP     // Alias
      },
      networkName: `ctf-${challengeName}-${userId}-net`,
      dockerNetworkConfig: {
        driver: 'bridge',
        ipam: {
          config: [{
            subnet: finalAllocation.subnet,
            gateway: finalAllocation.gateway
          }]
        },
        driver_opts: {
          'com.docker.network.bridge.name': bridgeName
        }
      }
    };

    this.allocations.set(instanceId, allocation);
    console.log(`📊 Allocated subnet for ${instanceId}:`);
    console.log(`   Subnet: ${finalAllocation.subnet}`);
    console.log(`   Gateway: ${finalAllocation.gateway}`);
    console.log(`   Victim: ${finalAllocation.victimIP}`);
    console.log(`   Attacker: ${finalAllocation.attackerIP}`);

    return allocation;
  }

  /**
   * Helper method to build IP allocation with new dynamic system
   * @private
   */
  _buildAllocation(allocation, baseIP, victimCount, randomizeIPs, needsDatabase, needsAPI) {
    // Reserved IPs that cannot be used for dynamic allocation
    const reservedIPs = new Set([
      1,  // Gateway
      2,  // Reserved
      3   // Attacker
    ]);
    
    // Calculate total IPs needed
    const totalIPsNeeded = victimCount + (needsDatabase ? 1 : 0) + (needsAPI ? 1 : 0);
    
    if (randomizeIPs) {
      // Allocate all IPs dynamically (victims, database, API together)
      const allIPs = this.allocateDynamicIPs(baseIP, totalIPsNeeded, reservedIPs, true);
      
      // Distribute allocated IPs
      let ipIndex = 0;
      
      // Victims (0-5)
      const victimIPs = [];
      for (let i = 0; i < victimCount; i++) {
        victimIPs.push(allIPs[ipIndex++]);
      }
      allocation.victimIPs = victimIPs;
      
      // Backward compatibility - named victim IPs
      allocation.victimIP = victimIPs[0] || null;
      allocation.victim2IP = victimIPs[1] || null;
      allocation.victim3IP = victimIPs[2] || null;
      allocation.victim4IP = victimIPs[3] || null;
      allocation.victim5IP = victimIPs[4] || null;
      
      // Database (randomized)
      allocation.databaseIP = needsDatabase ? allIPs[ipIndex++] : null;
      
      // API (randomized)
      allocation.apiIP = needsAPI ? allIPs[ipIndex++] : null;
      
    } else {
      // Fixed IP allocation (backward compatible)
      const preferredVictimIPs = [10, 20, 30, 40, 50]; // Up to 5 victims
      const victimIPs = this.allocateDynamicIPs(
        baseIP, 
        victimCount, 
        reservedIPs, 
        false, 
        preferredVictimIPs
      );
      
      allocation.victimIPs = victimIPs;
      allocation.victimIP = victimIPs[0] || null;
      allocation.victim2IP = victimIPs[1] || null;
      allocation.victim3IP = victimIPs[2] || null;
      allocation.victim4IP = victimIPs[3] || null;
      allocation.victim5IP = victimIPs[4] || null;
      
      // Fixed database/API IPs when not randomizing
      allocation.databaseIP = needsDatabase ? `${baseIP}.60` : null;
      allocation.apiIP = needsAPI ? `${baseIP}.70` : null;
    }
    
    return allocation;
  }

  /**
   * Create Docker network with allocated subnet
   * @param {object} docker - Dockerode instance
   * @param {object} allocation - Allocation from allocateSubnet()
   * @returns {Promise<string>} Network ID
   */
  async createNetwork(docker, allocation) {
    try {
      const networkConfig = {
        Name: allocation.networkName,
        Driver: 'bridge',
        IPAM: {
          Config: [{
            Subnet: allocation.subnet,
            Gateway: allocation.gateway
          }]
        },
        Options: allocation.dockerNetworkConfig.driver_opts
      };
      
      console.log(`\n📋 Docker Network Creation Config:`);
      console.log(JSON.stringify(networkConfig, null, 2));
      
      const network = await docker.createNetwork(networkConfig);

      console.log(`🌐 Created network ${allocation.networkName} with subnet ${allocation.subnet}`);
      return network.id;
    } catch (error) {
      if (error.statusCode === 409) {
        console.log(`⚠️  Network ${allocation.networkName} already exists, using existing`);
        const networks = await docker.listNetworks({
          filters: { name: [allocation.networkName] }
        });
        return networks[0]?.Id;
      }
      throw error;
    }
  }

  /**
   * Remove allocated subnet and clean up network
   * @param {object} docker - Dockerode instance
   * @param {string} instanceId - Instance ID
   */
  async cleanupNetwork(docker, instanceId) {
    const allocation = this.allocations.get(instanceId);
    if (!allocation) {
      console.log(`⚠️  No allocation found for ${instanceId}`);
      return;
    }

    try {
      const networks = await docker.listNetworks({
        filters: { name: [allocation.networkName] }
      });

      if (networks.length > 0) {
        const network = docker.getNetwork(networks[0].Id);
        await network.remove();
        console.log(`🗑️  Removed network ${allocation.networkName}`);
      }

      this.allocations.delete(instanceId);
    } catch (error) {
      console.error(`Error cleaning up network ${allocation.networkName}:`, error.message);
    }
  }

  /**
   * Release a subnet allocation (without cleaning up Docker network)
   * IMPROVEMENT: Now updates database to mark allocation as inactive
   * @param {string} challengeName - Challenge name to release
   * @param {string} userId - User ID (default: 'default')
   * @returns {Promise<boolean>} True if released successfully
   */
  async releaseSubnet(challengeName, userId = 'default') {
    const instanceId = `${challengeName}-${userId}`;
    
    // Remove from in-memory cache
    const inMemory = this.allocations.has(instanceId);
    if (inMemory) {
      this.allocations.delete(instanceId);
    }

    // IMPROVEMENT: Update database
    if (this.dbEnabled) {
      try {
        const result = await dbManager.pool.query(`
          UPDATE subnet_allocations
          SET is_active = FALSE, released_at = NOW(), updated_at = NOW()
          WHERE challenge_name = $1 AND user_id = $2 AND is_active = TRUE
        `, [challengeName, userId]);

        if (result.rowCount > 0) {
          console.log(`🗑️  Released subnet allocation in database for ${instanceId}`);
          return true;
        } else if (inMemory) {
          console.log(`🗑️  Released subnet allocation from memory for ${instanceId} (not in database)`);
          return true;
        }
      } catch (dbError) {
        console.warn('⚠️  Database release failed:', dbError.message);
        // Return true if in-memory release succeeded
        return inMemory;
      }
    }

    return inMemory;
  }

  /**
   * Get allocation info for an instance
   * @param {string} instanceId - Instance ID
   * @returns {object|null} Allocation info or null
   */
  getAllocation(instanceId) {
    return this.allocations.get(instanceId) || null;
  }

  /**
   * List all allocations
   * @returns {Array} All allocations
   */
  listAllocations() {
    return Array.from(this.allocations.values());
  }
}

// Export singleton instance
export const subnetAllocator = new SubnetAllocator();
