/**
 * Package Mapping Database Manager
 * Loads service-to-package mappings, tool classifications, and OS-specific configurations from database
 * BEST PRACTICE: Dynamic configuration allows automation to update mappings without code changes
 */

import { dbManager } from './db-manager.js';

// Add query method to dbManager if it doesn't exist
if (!dbManager.query) {
  dbManager.query = async function(sql, params = []) {
    return await this.pool.query(sql, params);
  };
}

// Cache for performance (5-minute TTL)
let cachedMappings = {
  serviceMappings: null,
  packageAliases: null,
  attackTools: null,
  invalidServices: null,
  baseTools: null,
  toolCategories: null,
  toolPackageMappings: null,
  timestamp: null
};
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Clear cache (useful after database updates)
 */
export function clearPackageMappingCache() {
  cachedMappings = {
    serviceMappings: null,
    packageAliases: null,
    attackTools: null,
    invalidServices: null,
    baseTools: null,
    toolCategories: null,
    toolPackageMappings: null,
    timestamp: null
  };
}

/**
 * Get service to package mappings
 */
export async function getServicePackageMappings() {
  const now = Date.now();
  
  if (cachedMappings.serviceMappings && cachedMappings.timestamp && (now - cachedMappings.timestamp) < CACHE_TTL) {
    return cachedMappings.serviceMappings;
  }
  
  try {
    const result = await dbManager.query(`
      SELECT 
        service_name,
        package_name,
        alpine_package,
        rhel_package,
        is_valid,
        service_type
      FROM service_package_mappings
      WHERE is_valid = true
      ORDER BY service_name
    `);
    
    const mappings = {};
    for (const row of result.rows) {
      mappings[row.service_name] = {
        default: row.package_name,
        alpine: row.alpine_package,
        rhel: row.rhel_package,
        isValid: row.is_valid,
        type: row.service_type
      };
    }
    
    cachedMappings.serviceMappings = mappings;
    cachedMappings.timestamp = now;
    
    return mappings;
  } catch (error) {
    console.error('❌ Error loading service package mappings:', error.message);
    return getDefaultServiceMappings();
  }
}

/**
 * Get package aliases
 */
export async function getPackageAliases(osType = 'all') {
  const now = Date.now();
  const cacheKey = `aliases_${osType}`;
  
  if (cachedMappings.packageAliases && cachedMappings.packageAliases[cacheKey] && cachedMappings.timestamp && (now - cachedMappings.timestamp) < CACHE_TTL) {
    return cachedMappings.packageAliases[cacheKey];
  }
  
  try {
    const result = await dbManager.query(`
      SELECT alias, actual_package
      FROM package_aliases
      WHERE os_type = $1 OR os_type = 'all'
      ORDER BY alias
    `, [osType]);
    
    const aliases = {};
    for (const row of result.rows) {
      aliases[row.alias] = row.actual_package;
    }
    
    if (!cachedMappings.packageAliases) {
      cachedMappings.packageAliases = {};
    }
    cachedMappings.packageAliases[cacheKey] = aliases;
    cachedMappings.timestamp = now;
    
    return aliases;
  } catch (error) {
    console.error('❌ Error loading package aliases:', error.message);
    return getDefaultPackageAliases(osType);
  }
}

/**
 * Get attack tools list (tools that should only be on attackers)
 */
export async function getAttackTools() {
  const now = Date.now();
  
  if (cachedMappings.attackTools && cachedMappings.timestamp && (now - cachedMappings.timestamp) < CACHE_TTL) {
    return cachedMappings.attackTools;
  }
  
  try {
    const result = await dbManager.query(`
      SELECT tool_name
      FROM attack_tools
      WHERE is_active = true
      ORDER BY tool_name
    `);
    
    const tools = result.rows.map(row => row.tool_name.toLowerCase());
    cachedMappings.attackTools = tools;
    cachedMappings.timestamp = now;
    
    return tools;
  } catch (error) {
    console.error('❌ Error loading attack tools:', error.message);
    return getDefaultAttackTools();
  }
}

/**
 * Get invalid service names (protocols that aren't packages)
 */
export async function getInvalidServiceNames() {
  const now = Date.now();
  
  if (cachedMappings.invalidServices && cachedMappings.timestamp && (now - cachedMappings.timestamp) < CACHE_TTL) {
    return cachedMappings.invalidServices;
  }
  
  try {
    const result = await dbManager.query(`
      SELECT service_name
      FROM invalid_service_names
      ORDER BY service_name
    `);
    
    const services = result.rows.map(row => row.service_name.toLowerCase());
    cachedMappings.invalidServices = services;
    cachedMappings.timestamp = now;
    
    return services;
  } catch (error) {
    console.error('❌ Error loading invalid service names:', error.message);
    return getDefaultInvalidServiceNames();
  }
}

/**
 * Get base tools for an OS type
 */
export async function getBaseTools(osType) {
  const now = Date.now();
  const cacheKey = `baseTools_${osType}`;
  
  if (cachedMappings.baseTools && cachedMappings.baseTools[cacheKey] && cachedMappings.timestamp && (now - cachedMappings.timestamp) < CACHE_TTL) {
    return cachedMappings.baseTools[cacheKey];
  }
  
  try {
    const result = await dbManager.query(`
      SELECT tools
      FROM base_tools_by_os
      WHERE os_type = $1 AND is_active = true
    `, [osType]);
    
    if (result.rows.length > 0) {
      const tools = result.rows[0].tools;
      
      if (!cachedMappings.baseTools) {
        cachedMappings.baseTools = {};
      }
      cachedMappings.baseTools[cacheKey] = tools;
      cachedMappings.timestamp = now;
      
      return tools;
    }
    
    return getDefaultBaseTools(osType);
  } catch (error) {
    console.error(`❌ Error loading base tools for ${osType}:`, error.message);
    return getDefaultBaseTools(osType);
  }
}

/**
 * Get tools by category
 */
export async function getToolsByCategory(category) {
  try {
    const result = await dbManager.query(`
      SELECT tool_name, priority
      FROM tool_categories
      WHERE category = $1 AND is_active = true
      ORDER BY priority DESC, tool_name
    `, [category]);
    
    return result.rows.map(row => row.tool_name);
  } catch (error) {
    console.error(`❌ Error loading tools for category ${category}:`, error.message);
    return getDefaultToolsByCategory(category);
  }
}

/**
 * Get tool to package mapping (for attacker machines)
 */
export async function getToolPackageMapping(toolName, osType = 'kali') {
  try {
    const result = await dbManager.query(`
      SELECT package_name
      FROM tool_package_mappings
      WHERE tool_name = $1 AND os_type = $2 AND is_active = true
      LIMIT 1
    `, [toolName, osType]);
    
    if (result.rows.length > 0) {
      return result.rows[0].package_name;
    }
    
    return null;
  } catch (error) {
    console.error(`❌ Error loading tool package mapping for ${toolName}:`, error.message);
    return null;
  }
}

/**
 * Get service package name for a specific OS
 */
export async function getServicePackageName(serviceName, packageManager) {
  const mappings = await getServicePackageMappings();
  const normalized = serviceName.toLowerCase().trim();
  
  if (!mappings[normalized]) {
    return null;
  }
  
  const mapping = mappings[normalized];
  
  if (!mapping.isValid || !mapping.default) {
    return null;
  }
  
  // Return OS-specific package if available
  if (packageManager === 'apk' && mapping.alpine) {
    return mapping.alpine;
  } else if ((packageManager === 'dnf' || packageManager === 'yum') && mapping.rhel) {
    return mapping.rhel;
  }
  
  return mapping.default;
}

/**
 * Get package mapping - resolves package name based on package manager and OS
 * This is a convenience function that combines service package resolution and aliases
 */
export async function getPackageMapping(packageName, packageManager, os) {
  // Determine OS type from package manager
  let osType = 'debian'; // default
  if (packageManager === 'apk') {
    osType = 'alpine';
  } else if (packageManager === 'dnf' || packageManager === 'yum') {
    osType = 'rhel';
  } else if (packageManager === 'pacman') {
    osType = 'arch';
  }
  
  // First, try to resolve as a service
  const servicePackage = await getServicePackageName(packageName, packageManager);
  if (servicePackage) {
    // Apply aliases to the resolved service package
    const aliases = await getPackageAliases(osType);
    return aliases[servicePackage.toLowerCase()] || servicePackage;
  }
  
  // If not a service, try to resolve as a tool
  const toolPackage = await getToolPackageMapping(packageName, osType);
  if (toolPackage) {
    // Apply aliases to the resolved tool package
    const aliases = await getPackageAliases(osType);
    return aliases[toolPackage.toLowerCase()] || toolPackage;
  }
  
  // Finally, check if the package name itself has an alias
  const aliases = await getPackageAliases(osType);
  const normalized = packageName.toLowerCase().trim();
  return aliases[normalized] || packageName;
}

// ============================================
// DEFAULT FALLBACKS (if database unavailable)
// ============================================

function getDefaultServiceMappings() {
  return {
    'ftp': { default: 'vsftpd', alpine: 'vsftpd', rhel: 'vsftpd', isValid: true, type: 'service' },
    'ssh': { default: 'openssh-server', alpine: 'openssh', rhel: 'openssh-server', isValid: true, type: 'service' },
    'web': { default: 'apache2', alpine: 'apache2', rhel: 'httpd', isValid: true, type: 'service' },
    'http': { default: 'apache2', alpine: 'apache2', rhel: 'httpd', isValid: true, type: 'service' },
    'smb': { default: 'samba', alpine: 'samba', rhel: 'samba', isValid: true, type: 'service' },
    'samba': { default: 'samba', alpine: 'samba', rhel: 'samba', isValid: true, type: 'service' }
  };
}

function getDefaultPackageAliases(osType) {
  const aliases = {
    'mysql-server': 'mariadb-server',
    'mysql': 'mariadb-server',
    'database': 'mariadb-server',
    'web-server': 'apache2',
    'http-server': 'apache2'
  };
  
  if (osType === 'alpine') {
    aliases['netcat'] = 'netcat-openbsd';
    aliases['openssh-server'] = 'openssh';
    aliases['mariadb-server'] = 'mariadb';
    // ✅ FIX: Alpine Linux doesn't have 'telnet' package - use busybox-extras instead
    aliases['telnet'] = 'busybox-extras';
    aliases['telnetd'] = 'busybox-extras';
  } else if (osType === 'rhel' || osType === 'dnf' || osType === 'yum') {
    aliases['netcat'] = 'nc';
    aliases['apache2'] = 'httpd';
    // ✅ FIX: Rocky Linux/RHEL use 'iputils' package, not 'iputils-ping' (Debian/Ubuntu naming)
    aliases['iputils-ping'] = 'iputils';
  }
  
  return aliases;
}

function getDefaultAttackTools() {
  return ['nmap', 'netcat', 'nc', 'ping', 'traceroute', 'tcpdump', 'wireshark', 'masscan', 'hping3', 'arp-scan', 'netdiscover'];
}

function getDefaultInvalidServiceNames() {
  return ['netbios', 'netbios-ns', 'netbios-ssn', 'netbios-dgm', 'cifs', 'smb2', 'smb3', 'echo', 'discard', 'chargen'];
}

function getDefaultBaseTools(osType) {
  if (osType === 'apk') {
    return ['openssh', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils-ping'];
  } else if (osType === 'yum') {
    // Legacy RHEL (yum-based systems)
    return ['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils'];
  } else if (osType === 'dnf') {
    // Rocky Linux, Fedora, RHEL
    return ['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils'];
  } else if (osType === 'pacman') {
    // Arch Linux
    return ['openssh', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils'];
  } else {
    // Ubuntu/Debian (apt-get) - default
    return ['openssh-server', 'sudo', 'vim', 'nano', 'curl', 'wget', 'git', 'net-tools', 'iputils-ping', 'ca-certificates', 'unzip', 'python3', 'python3-pip'];
  }
}

function getDefaultToolsByCategory(category) {
  const toolMap = {
    network: ['nmap', 'masscan', 'wireshark', 'tcpdump', 'netcat-traditional', 'hping3'],
    web: ['burpsuite', 'sqlmap', 'nikto', 'gobuster', 'dirb', 'wfuzz'],
    crypto: ['hashcat', 'john', 'openssl', 'gpg'],
    pwn: ['gdb', 'ghidra', 'radare2', 'objdump']
  };
  
  return toolMap[category] || [];
}

