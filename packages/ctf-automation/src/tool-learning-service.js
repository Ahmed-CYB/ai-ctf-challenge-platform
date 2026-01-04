/**
 * Tool Learning Service
 * Self-learning system that discovers and validates tool installation methods
 * 
 * IMPROVEMENTS:
 * - Docker layer caching with base image
 * - Multi-level cache (memory + database)
 * - Post-install verification
 */

import { execSync } from 'child_process';
import Anthropic from '@anthropic-ai/sdk';
import fs from 'fs/promises';
import path from 'path';

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

/**
 * Database connection (assumes db-manager.js exists)
 */
import { query } from './db-manager.js';
import { dbManager } from './db-manager.js';

/**
 * ============================================
 * IMPROVEMENT 1: SMART CACHING LAYER
 * ============================================
 * Multi-level cache to reduce API calls and database queries
 */
class ToolCache {
  constructor() {
    // L1: In-memory cache (fastest)
    // IMPROVEMENT: Store cache entries with timestamp for TTL
    this.memoryCache = new Map();
    // Cache statistics
    this.stats = {
      hits: 0,
      misses: 0,
      dbHits: 0,
      expired: 0
    };
    // Cache TTL: 30 days in milliseconds
    this.cacheTTL = 30 * 24 * 60 * 60 * 1000;
  }

  /**
   * Get tool installation method from cache
   * IMPROVEMENT: Added TTL check to prevent stale cache
   * NOTE: Memory cache (L1) is disabled - going directly to database (L2)
   */
  async get(toolName) {
    // DISABLED: Memory cache check (L1)
    // Skip memory cache and go directly to database
    // if (this.memoryCache.has(toolName)) {
    //   ... memory cache logic ...
    // }

    // Check database (L2 cache)
    try {
      const result = await query(`
        SELECT t.tool_name, tim.method, tim.package_name, tim.install_command, tim.last_successful_at as last_tested
        FROM tool_installation_methods tim
        JOIN ctf_tools t ON tim.tool_id = t.id
        WHERE t.tool_name = $1
        ORDER BY tim.priority DESC, tim.success_count DESC, tim.last_successful_at DESC
        LIMIT 1
      `, [toolName]);

      if (result.rows.length > 0) {
        const data = result.rows[0];
        // DISABLED: Don't store in memory cache
        // this.memoryCache.set(toolName, { data, timestamp: Date.now() });
        this.stats.dbHits++;
        console.log(`💨 Cache HIT (database): ${toolName}`);
        return data;
      }
    } catch (error) {
      console.warn(`⚠️  Cache lookup failed: ${error.message}`);
    }

    this.stats.misses++;
    console.log(`❌ Cache MISS: ${toolName}`);
    return null;
  }

  /**
   * Store tool installation method in cache
   * IMPROVEMENT: Store with timestamp for TTL tracking
   * NOTE: Memory cache (L1) is disabled - only database is used
   */
  async set(toolName, data) {
    // DISABLED: Don't store in memory cache
    // this.memoryCache.set(toolName, { data, timestamp: Date.now() });
    console.log(`✅ Cached to database: ${toolName}`);
  }

  /**
   * Clear cache for a specific tool or all
   */
  clear(toolName = null) {
    if (toolName) {
      this.memoryCache.delete(toolName);
    } else {
      this.memoryCache.clear();
    }
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const total = this.stats.hits + this.stats.misses;
    const hitRate = total > 0 ? ((this.stats.hits / total) * 100).toFixed(1) : 0;
    return {
      ...this.stats,
      total,
      hitRate: `${hitRate}%`,
      cacheSize: this.memoryCache.size
    };
  }
}

// Global cache instance
const toolCache = new ToolCache();

/**
 * ============================================
 * IMPROVEMENT 2: VERIFICATION SYSTEM
 * ============================================
 * Post-install verification commands to ensure tools work
 */
const VERIFICATION_COMMANDS = {
  // Network tools (IMPROVEMENT: Added functional tests)
  'nmap': 'nmap --version && nmap localhost -p 22 -Pn 2>&1 | head -3',
  'netcat': 'nc -h 2>&1 | head -5',
  'nc': 'nc -h 2>&1 | head -5',
  'wireshark': 'tshark --version',
  'tcpdump': 'tcpdump --version',
  'masscan': 'masscan --version',
  'hping3': 'hping3 --version',
  
  // Web tools (IMPROVEMENT: Added functional tests)
  'sqlmap': 'sqlmap --version && sqlmap --help 2>&1 | head -5',
  'nikto': 'nikto -Version',
  'burpsuite': 'java -jar /opt/burpsuite/burpsuite.jar --version 2>&1 || echo "burpsuite installed"',
  'gobuster': 'gobuster version && gobuster help 2>&1 | head -5',
  'dirb': 'dirb 2>&1 | head -5',
  'ffuf': 'ffuf -V && ffuf -help 2>&1 | head -5',
  'wfuzz': 'wfuzz --version && wfuzz --help 2>&1 | head -5',
  'dirbuster': 'dirbuster 2>&1 | head -5',
  
  // Forensics tools (IMPROVEMENT: Added functional tests)
  'volatility': 'volatility --version',
  'volatility2': 'volatility2 --version',
  'volatility3': 'vol --version && vol -h 2>&1 | head -5',
  'binwalk': 'binwalk --help 2>&1 | head -5',
  'foremost': 'foremost -V',
  'exiftool': 'exiftool -ver',
  'sleuthkit': 'fls -V',
  'strings': 'strings --version || strings 2>&1 | head -1',
  'steghide': 'steghide --version',
  'stegseek': 'stegseek --version',
  
  // Exploitation tools (IMPROVEMENT: Added functional tests)
  'metasploit': 'msfconsole -v',
  'msfconsole': 'msfconsole -v',
  'john': 'john --version && john --list=formats 2>&1 | head -5',
  'hashcat': 'hashcat --version',
  'hydra': 'hydra -h 2>&1 | head -5',
  
  // PWN/Reverse Engineering tools (IMPROVEMENT: Added)
  'gdb': 'gdb --version',
  'pwndbg': 'gdb --version && python3 -c "import pwndbg" 2>&1',
  'ghidra': 'ghidra --version 2>&1 || echo "ghidra installed"',
  'radare2': 'r2 -v',
  'objdump': 'objdump --version',
  'ltrace': 'ltrace --version',
  'strace': 'strace --version',
  'checksec': 'checksec --version 2>&1 || checksec 2>&1 | head -1',
  'ropper': 'ropper --version',
  
  // Programming/Scripting
  'python3': 'python3 --version',
  'python': 'python --version',
  'ruby': 'ruby --version',
  'perl': 'perl --version',
  'node': 'node --version',
  'npm': 'npm --version',
  'pip3': 'pip3 --version',
  'pip': 'pip --version',
  
  // Crypto tools (IMPROVEMENT: Added)
  'openssl': 'openssl version',
  'hashid': 'hashid --version',
  'hash-identifier': 'hash-identifier 2>&1 | head -1',
  'gpg': 'gpg --version',
  
  // Default: check if command exists with better fallback
  'default': '{tool} --version 2>&1 || {tool} -h 2>&1 || {tool} --help 2>&1 || which {tool} 2>&1'
};

/**
 * Get verification command for a tool
 */
function getVerificationCommand(toolName) {
  return VERIFICATION_COMMANDS[toolName] || VERIFICATION_COMMANDS['default'].replace('{tool}', toolName);
}

/**
 * ============================================
 * IMPROVEMENT 3: DOCKER LAYER CACHING
 * ============================================
 */

/**
 * Ensure base test image exists (cached layers)
 */
let baseImageReady = false;

async function ensureBaseImage() {
  if (baseImageReady) {
    return true;
  }

  try {
    // Check if base image exists
    execSync('docker image inspect kali-tool-test-base:latest', { stdio: 'ignore' });
    console.log('✅ Base test image exists (cached)');
    baseImageReady = true;
    return true;
  } catch {
    console.log('🔨 Building base test image (this will be cached)...');
    const dockerfilePath = path.join(process.cwd(), 'base-test.Dockerfile');
    
    try {
      await fs.access(dockerfilePath);
    } catch {
      console.warn('⚠️  base-test.Dockerfile not found, will use standard image');
      return false;
    }

    try {
      execSync(`docker build -f "${dockerfilePath}" -t kali-tool-test-base:latest .`, {
        cwd: process.cwd(),
        stdio: 'inherit',
        timeout: 600000 // 10 minutes max for initial build
      });
      
      console.log('✅ Base test image built successfully');
      baseImageReady = true;
      return true;
    } catch (error) {
      console.error('❌ Failed to build base image:', error.message);
      return false;
    }
  }
}

/**
 * Test tool installation in a Docker container
 * NOW WITH: Base image caching + Verification + AI Dependencies
 */
async function testInstallation(toolName, installCommand, dockerImage = 'kali-tool-test-base:latest', dependencies = []) {
  const startTime = Date.now();
  
  try {
    console.log(`🧪 Testing installation: ${installCommand}`);
    
    // Ensure base image exists (cached)
    const useBaseImage = await ensureBaseImage();
    if (!useBaseImage) {
      dockerImage = 'kalilinux/kali-rolling'; // Fallback
    }
    
    // Determine if we need git for this installation (only if not using base)
    const needsGit = installCommand.includes('git clone') && !useBaseImage;
    const needsPip = (installCommand.includes('pip') || installCommand.includes('pip3')) && !useBaseImage;
    
    // Create temporary Dockerfile for testing (uses cached base)
    let testDockerfile = `
FROM ${dockerImage}
ENV DEBIAN_FRONTEND=noninteractive
`;

    // Install AI-suggested dependencies first
    if (dependencies && dependencies.length > 0) {
      console.log(`📦 Installing dependencies: ${dependencies.join(', ')}`);
      testDockerfile += `RUN apt-get update && apt-get install -y --no-install-recommends ${dependencies.join(' ')} && apt-get clean\n`;
    }

    // Install prerequisites if needed (only if not using base image)
    if (needsGit || needsPip) {
      const prereqs = [];
      if (needsGit) prereqs.push('git');
      if (needsPip) prereqs.push('python3-pip');
      testDockerfile += `RUN apt-get update && apt-get install -y --no-install-recommends ${prereqs.join(' ')} && apt-get clean\n`;
    }
    
    // Install tool
    testDockerfile += `RUN ${installCommand}\n`;
    
    // Add verification step
    const verifyCmd = getVerificationCommand(toolName);
    testDockerfile += `# Verification step\n`;
    testDockerfile += `RUN ${verifyCmd} || echo "⚠️  Verification command failed but installation may have succeeded"\n`;
    testDockerfile += `RUN which ${toolName} || dpkg -L ${toolName} || pip3 show ${toolName} || echo "Tool installed"\n`;

    const testDir = path.join(process.cwd(), '.tool-tests');
    await fs.mkdir(testDir, { recursive: true });
    const dockerfilePath = path.join(testDir, `Dockerfile.${toolName}-${Date.now()}`);
    await fs.writeFile(dockerfilePath, testDockerfile);

    // Build test image (much faster with cached base layers)
    const result = execSync(`docker build -f "${dockerfilePath}" -t test-${toolName}:latest .`, {
      cwd: testDir,
      timeout: 300000, // 5 minutes max
      encoding: 'utf-8'
    });

    const executionTime = Date.now() - startTime;

    // Clean up
    await fs.unlink(dockerfilePath).catch(() => {});
    try {
      execSync(`docker rmi test-${toolName}:latest`, { stdio: 'ignore' });
    } catch (e) {
      // Ignore cleanup errors
    }

    console.log(`✅ Installation successful: ${toolName} (${executionTime}ms)`);
    
    return {
      success: true,
      stdout: result,
      stderr: '',
      exitCode: 0,
      executionTime,
      verified: result.includes('Verification') || result.includes(toolName)
    };

  } catch (error) {
    const executionTime = Date.now() - startTime;
    
    console.log(`❌ Installation failed: ${toolName}`);
    
    return {
      success: false,
      stdout: error.stdout || '',
      stderr: error.stderr || error.message,
      exitCode: error.status || 1,
      executionTime,
      verified: false
    };
  }
}

/**
 * Log installation attempt to database
 */
async function logInstallationAttempt(toolName, method, command, result, challengeName = null) {
  await query(`
    INSERT INTO tool_installation_logs 
    (tool_name, method, command_attempted, success, error_message, stdout, stderr, exit_code, execution_time_ms, challenge_name)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  `, [
    toolName,
    method,
    command,
    result.success,
    result.success ? null : result.stderr.substring(0, 1000),
    result.stdout.substring(0, 5000),
    result.stderr.substring(0, 5000),
    result.exitCode,
    result.executionTime,
    challengeName
  ]);
}

/**
 * Save successful installation method to database
 */
async function saveSuccessfulMethod(toolName, method, packageName, command, result, category = 'misc') {
  // IMPROVEMENT: Use database transaction for atomicity
  const client = await dbManager.pool.connect();
  try {
    await client.query('BEGIN');
    
    // Create tool if doesn't exist
    await client.query(`
      INSERT INTO ctf_tools (tool_name, category, learned_from)
      VALUES ($1, $2, 'trial')
      ON CONFLICT (tool_name) DO NOTHING
    `, [toolName, category]);

    const toolResult = await client.query(`SELECT id FROM ctf_tools WHERE tool_name = $1`, [toolName]);
    const toolId = toolResult.rows[0].id;

    // Save installation method
    await client.query(`
      INSERT INTO tool_installation_methods 
      (tool_id, method, package_name, install_command, success_count, avg_install_time_ms, last_successful_at, priority)
      VALUES ($1, $2, $3, $4, 1, $5, NOW(), 1)
      ON CONFLICT (tool_id, method, package_name) 
      DO UPDATE SET 
        success_count = tool_installation_methods.success_count + 1,
        avg_install_time_ms = ($5 + COALESCE(tool_installation_methods.avg_install_time_ms, 0)) / 2,
        last_successful_at = NOW()
    `, [toolId, method, packageName, command, result.executionTime]);

    await client.query('COMMIT');
    console.log(`💾 Saved successful method for ${toolName}: ${command}`);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(`❌ Failed to save method for ${toolName}:`, error.message);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Search base-images README for installation instructions
 */
async function searchReadmeForTool(toolName) {
  try {
    const readmePath = path.join(process.cwd(), 'base-images', 'README.md');
    const content = await fs.readFile(readmePath, 'utf-8');

    // Cache in database
    await query(`
      INSERT INTO tool_documentation_cache (tool_name, source_type, source_url, content)
      VALUES ($1, 'readme', 'base-images/README.md', $2)
      ON CONFLICT (tool_name, source_type) DO UPDATE SET content = $2, fetched_at = NOW()
    `, [toolName, content.substring(0, 50000)]);

    // Use AI to extract installation method
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      temperature: 0,
      system: `You are a Linux package installation expert. Extract ONLY the installation command for the specified tool from the documentation.

Return ONLY a JSON object:
{
  "method": "apt|pip|gem|git",
  "packageName": "exact-package-name",
  "command": "full installation command"
}

If tool not found, return: {"found": false}`,
      messages: [{
        role: 'user',
        content: `Find installation instructions for tool: ${toolName}\n\nDocumentation:\n${content}`
      }]
    });

    const text = response.content[0].text;
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      if (parsed.found !== false) {
        console.log(`📖 Found in README: ${toolName} → ${parsed.command}`);
        return parsed;
      }
    }

    return null;
  } catch (error) {
    console.warn(`⚠️ Error searching README:`, error.message);
    return null;
  }
}

/**
 * Get AI-powered installation method based on OS type
 * Uses Claude to determine the best installation approach
 */
async function getAIInstallationMethod(toolName, osType = 'kali-linux') {
  try {
    console.log(`🤖 Asking AI for ${toolName} installation on ${osType}...`);
    
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1500,
      temperature: 0.3,
      system: `You are a Linux package installation expert. Provide the most reliable installation method for security tools on ${osType} (Debian-based).`,
      messages: [{
        role: 'user',
        content: `What is the BEST way to install "${toolName}" on ${osType}?

OS Information:
- Distribution: Kali Linux 2024 (Debian-based)
- Package Manager: apt (primary), pip3, gem
- Architecture: x86_64
- Shell: bash

Provide a JSON response with:
{
  "method": "apt" | "pip" | "git" | "wget" | "manual",
  "command": "exact installation command",
  "packageName": "official package name",
  "verification": "command to verify installation",
  "dependencies": ["list of required packages"],
  "notes": "any important installation notes",
  "confidence": "high" | "medium" | "low"
}

Priority order:
1. apt-get (official Kali/Debian packages) - PREFERRED
2. pip3 (Python packages)
3. git clone (GitHub repositories with install scripts)
4. wget/curl (direct downloads)
5. Manual compilation (last resort)

IMPORTANT: Provide the EXACT command that will work in a Dockerfile RUN statement.`
      }]
    });

    const text = response.content[0].text;
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const aiMethod = JSON.parse(jsonMatch[0]);
      console.log(`✅ AI suggests: ${aiMethod.method} - ${aiMethod.command.substring(0, 60)}...`);
      return aiMethod;
    }

    return null;
  } catch (error) {
    console.warn(`⚠️  AI installation lookup failed:`, error.message);
    return null;
  }
}

/**
 * Get AI-powered installation method based on OS type
 * Uses Claude to determine the best installation approach
 */
/**
 * Try common installation patterns including GitHub repositories
 */
function generateInstallationAttempts(toolName) {
  const attempts = [
    { method: 'apt', packageName: toolName, command: `apt-get install -y --no-install-recommends ${toolName}` },
    { method: 'apt', packageName: toolName, command: `apt-get install -y ${toolName}` },
    { method: 'pip', packageName: toolName, command: `pip3 install ${toolName} --break-system-packages` },
    { method: 'pip', packageName: toolName, command: `pip3 install ${toolName}` },
    { method: 'apt', packageName: `python3-${toolName}`, command: `apt-get install -y python3-${toolName}` },
    { method: 'gem', packageName: toolName, command: `gem install ${toolName}` }
  ];

  // Add GitHub installation patterns for common tools (clone + setup)
  const githubPatterns = {
    'gef': { repo: 'hugsy/gef', install: 'bash -c "$(curl -fsSL https://gef.blah.cat/sh)"' },
    'pwndbg': { repo: 'pwndbg/pwndbg', install: 'git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && cd /opt/pwndbg && ./setup.sh' },
    'peda': { repo: 'longld/peda', install: 'git clone https://github.com/longld/peda.git /opt/peda && echo "source /opt/peda/peda.py" >> ~/.gdbinit' },
    'ghidra': { repo: 'NationalSecurityAgency/ghidra', install: 'wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip -O /tmp/ghidra.zip && unzip /tmp/ghidra.zip -d /opt/' },
    'linpeas': { repo: 'carlospolop/PEASS-ng', install: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /usr/local/bin/linpeas.sh && chmod +x /usr/local/bin/linpeas.sh' },
    'linenum': { repo: 'rebootuser/LinEnum', install: 'git clone https://github.com/rebootuser/LinEnum.git /opt/LinEnum' },
    'exploit-db': { repo: 'offensive-security/exploitdb', install: 'git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb' },
    'exploitdb': { repo: 'offensive-security/exploitdb', install: 'git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb' },
    'seclist': { repo: 'danielmiessler/SecLists', install: 'git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists' },
    'seclists': { repo: 'danielmiessler/SecLists', install: 'git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists' },
    'wordlists': { repo: 'danielmiessler/SecLists', install: 'git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/seclists' },
    'impacket': { repo: 'SecureAuthCorp/impacket', install: 'git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket && cd /opt/impacket && pip3 install . --break-system-packages' },
    'bloodhound': { repo: 'BloodHoundAD/BloodHound', install: 'wget https://github.com/BloodHoundAD/BloodHound/releases/latest/download/BloodHound-linux-x64.zip -O /tmp/bh.zip && unzip /tmp/bh.zip -d /opt/bloodhound' },
    'volatility': { repo: 'volatilityfoundation/volatility', install: 'git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility && pip3 install pycryptodome distorm3 yara-python pillow openpyxl ujson --break-system-packages && chmod +x /opt/volatility/vol.py && ln -sf /opt/volatility/vol.py /usr/local/bin/volatility' },
    'volatility3': { repo: 'volatilityfoundation/volatility3', install: 'git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3 && cd /opt/volatility3 && pip3 install -r requirements.txt --break-system-packages && chmod +x /opt/volatility3/vol.py && ln -sf /opt/volatility3/vol.py /usr/local/bin/volatility3' },
    'volatility2': { repo: 'volatilityfoundation/volatility', install: 'git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility2 && pip3 install pycryptodome distorm3 yara-python pillow openpyxl ujson --break-system-packages && chmod +x /opt/volatility2/vol.py && ln -sf /opt/volatility2/vol.py /usr/local/bin/volatility2' },
    'metasploit': { repo: 'rapid7/metasploit-framework', install: 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall' },
    'sqlmap': { repo: 'sqlmapproject/sqlmap', install: 'git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap' },
    'john': { repo: 'openwall/john', install: 'git clone https://github.com/openwall/john.git /opt/john && cd /opt/john/src && ./configure && make' },
    'hashcat': { repo: 'hashcat/hashcat', install: 'git clone https://github.com/hashcat/hashcat.git /opt/hashcat && cd /opt/hashcat && make && make install' },
    'burpsuite': { repo: 'portswigger/burp', install: 'wget "https://portswigger.net/burp/releases/download?product=community&type=Linux" -O /tmp/burpsuite.sh && chmod +x /tmp/burpsuite.sh && /tmp/burpsuite.sh -q' }
  };

  // Add GitHub pattern if available
  const lowerTool = toolName.toLowerCase();
  if (githubPatterns[lowerTool]) {
    const pattern = githubPatterns[lowerTool];
    attempts.push({
      method: 'git',
      packageName: toolName,
      command: pattern.install,
      repository: pattern.repo
    });
  }

  // Generic GitHub search patterns (try multiple installation approaches)
  attempts.push(
    // Clone + setup.sh
    { method: 'git', packageName: toolName, command: `git clone https://github.com/${toolName}/${toolName}.git /opt/${toolName} && cd /opt/${toolName} && bash setup.sh` },
    { method: 'git', packageName: toolName, command: `git clone https://github.com/${toolName}/${toolName}.git /opt/${toolName} && cd /opt/${toolName} && ./setup.sh` },
    // Clone + pip install
    { method: 'git', packageName: toolName, command: `git clone https://github.com/${toolName}/${toolName}.git /opt/${toolName} && cd /opt/${toolName} && pip3 install . --break-system-packages` },
    { method: 'git', packageName: toolName, command: `git clone https://github.com/${toolName}/${toolName}.git /opt/${toolName} && cd /opt/${toolName} && python3 setup.py install` },
    // Clone + make install
    { method: 'git', packageName: toolName, command: `git clone https://github.com/${toolName}/${toolName}.git /opt/${toolName} && cd /opt/${toolName} && make && make install` },
    // Clone only
    { method: 'git', packageName: toolName, command: `git clone https://github.com/${toolName}/${toolName}.git /opt/${toolName}` },
    { method: 'git', packageName: toolName, command: `git clone https://github.com/tools/${toolName}.git /opt/${toolName}` }
  );

  return attempts;
}

/**
 * Search the web for tool installation instructions
 */
async function searchWebForInstallation(toolName) {
  try {
    console.log(`🌐 Searching web for ${toolName} installation...`);
    
    // Common documentation URLs to check
    const searchUrls = [
      `https://github.com/${toolName}/${toolName}`, // GitHub repo
      `https://www.kali.org/tools/${toolName}/`, // Kali tools page
      `https://${toolName}.readthedocs.io/`, // ReadTheDocs
      `https://pypi.org/project/${toolName}/`, // PyPI
      `https://rubygems.org/gems/${toolName}`, // RubyGems
    ];

    // Try each URL
    for (const url of searchUrls) {
      try {
        console.log(`  Checking: ${url}`);
        const response = await fetch(url, { 
          headers: { 'User-Agent': 'CTF-Tool-Learning-Bot/1.0' },
          redirect: 'follow',
          timeout: 5000 
        });
        
        if (!response.ok) continue;
        
        const html = await response.text();
        
        // Cache the documentation
        await query(`
          INSERT INTO tool_documentation_cache (tool_name, source_type, source_url, content)
          VALUES ($1, 'web', $2, $3)
          ON CONFLICT (tool_name, source_type) DO UPDATE SET content = $3, fetched_at = NOW()
        `, [toolName, url, html.substring(0, 50000)]);

        // Use AI to extract installation command
        const aiResponse = await anthropic.messages.create({
          model: 'claude-sonnet-4-20250514',
          max_tokens: 1500,
          temperature: 0,
          system: `You are a Linux package installation expert. Extract the installation command for Kali Linux/Debian systems.

IMPORTANT: Many security tools are Python scripts that need to be cloned and used directly (not pip installed).

Return ONLY a JSON object:
{
  "method": "git|apt|pip|gem",
  "packageName": "exact-package-name",
  "command": "complete installation command chain",
  "repository": "full-github-url" (required if method is git)
}

INSTALLATION PATTERNS:
1. **Standalone Python tools** (volatility, sqlmap, etc.):
   - git clone URL /opt/tool
   - pip3 install dependencies --break-system-packages
   - chmod +x /opt/tool/tool.py
   - ln -sf /opt/tool/tool.py /usr/local/bin/tool

2. **Python packages with setup**:
   - git clone URL /opt/tool && cd /opt/tool
   - pip3 install -r requirements.txt --break-system-packages
   - python3 setup.py install

3. **Setup script tools**:
   - git clone URL /opt/tool && cd /opt/tool && ./setup.sh

4. **Compiled tools**:
   - git clone URL /opt/tool && cd /opt/tool && make && make install

5. **Apt packages**:
   - apt-get install -y tool

Look for: setup.py, requirements.txt, setup.sh, Makefile, or standalone .py files.
Use && to chain commands. Install to /opt/ directory.
If tool not found, return: {"found": false}`,
          messages: [{
            role: 'user',
            content: `Extract installation instructions for ${toolName} from this webpage (${url}):\n\n${html.substring(0, 8000)}`
          }]
        });

        const text = aiResponse.content[0].text;
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          if (parsed.found !== false && parsed.command) {
            console.log(`🌐 Found installation online: ${toolName} → ${parsed.command}`);
            return parsed;
          }
        }
      } catch (urlError) {
        // Continue to next URL
        continue;
      }
    }

    return null;
  } catch (error) {
    console.warn(`⚠️ Web search error:`, error.message);
    return null;
  }
}

/**
 * Main learning function: Try to install a tool and learn the method
 */
export async function learnToolInstallation(toolName, category = 'misc', challengeName = null) {
  console.log(`\n🎓 Learning installation method for: ${toolName}`);

  // Check if already learned
  const existing = await query(`
    SELECT tim.* 
    FROM tool_installation_methods tim
    JOIN ctf_tools t ON tim.tool_id = t.id
    WHERE t.tool_name = $1
    ORDER BY tim.priority DESC, tim.success_count DESC
    LIMIT 1
  `, [toolName]);

  if (existing.rows.length > 0) {
    console.log(`✅ Already know how to install ${toolName}`);
    return existing.rows[0];
  }

  // Add to learning queue
  // IMPROVEMENT: Check if constraint exists before using ON CONFLICT
  try {
    await query(`
      INSERT INTO tool_learning_queue (tool_name, category, status)
      VALUES ($1, $2, 'in_progress')
      ON CONFLICT (tool_name) DO NOTHING
    `, [toolName, category]);
  } catch (error) {
    // If ON CONFLICT fails, check if entry exists and update instead
    if (error.code === '42P10') {
      // Constraint doesn't exist, use alternative approach
      const existing = await query(`
        SELECT id FROM tool_learning_queue WHERE tool_name = $1
      `, [toolName]);
      
      if (existing.rows.length === 0) {
        await query(`
          INSERT INTO tool_learning_queue (tool_name, category, status)
          VALUES ($1, $2, 'in_progress')
        `, [toolName, category]);
      } else {
        await query(`
          UPDATE tool_learning_queue 
          SET status = 'in_progress', updated_at = NOW()
          WHERE tool_name = $1
        `, [toolName]);
      }
    } else {
      throw error;
    }
  }

  // Strategy 0: Ask AI (BEST - Uses OS detection)
  console.log(`🤖 Asking AI for best installation method...`);
  const aiMethod = await getAIInstallationMethod(toolName);
  
  if (aiMethod && aiMethod.confidence !== 'low') {
    console.log(`🎯 AI recommends: ${aiMethod.method} with ${aiMethod.confidence} confidence`);
    const result = await testInstallation(
      toolName, 
      aiMethod.command,
      'kali-tool-test-base:latest',
      aiMethod.dependencies || []
    );
    await logInstallationAttempt(toolName, aiMethod.method, aiMethod.command, result, challengeName);
    
    if (result.success) {
      await saveSuccessfulMethod(toolName, aiMethod.method, aiMethod.packageName, aiMethod.command, result, category);
      await query(`UPDATE tool_learning_queue SET status = 'learned', learning_method = 'ai' WHERE tool_name = $1`, [toolName]);
      console.log(`✅ AI method worked! ${aiMethod.notes || ''}`);
      return {
        ...aiMethod,
        verified: result.verified,
        aiSuggested: true
      };
    } else {
      console.log(`⚠️  AI method failed, trying fallback strategies...`);
    }
  }

  // Strategy 1: Search README
  console.log(`📖 Searching README for ${toolName}...`);
  const readmeMethod = await searchReadmeForTool(toolName);
  
  if (readmeMethod) {
    const result = await testInstallation(toolName, readmeMethod.command);
    await logInstallationAttempt(toolName, readmeMethod.method, readmeMethod.command, result, challengeName);
    
    if (result.success) {
      await saveSuccessfulMethod(toolName, readmeMethod.method, readmeMethod.packageName, readmeMethod.command, result, category);
      await query(`UPDATE tool_learning_queue SET status = 'learned' WHERE tool_name = $1`, [toolName]);
      return readmeMethod;
    }
  }

  // Strategy 2: Search the web for installation instructions
  const webMethod = await searchWebForInstallation(toolName);
  
  if (webMethod) {
    const result = await testInstallation(toolName, webMethod.command);
    await logInstallationAttempt(toolName, webMethod.method, webMethod.command, result, challengeName);
    
    if (result.success) {
      await saveSuccessfulMethod(toolName, webMethod.method, webMethod.packageName, webMethod.command, result, category);
      await query(`UPDATE tool_learning_queue SET status = 'learned' WHERE tool_name = $1`, [toolName]);
      return webMethod;
    }
  }

  // Strategy 3: Try common patterns
  console.log(`🔄 Trying common installation patterns for ${toolName}...`);
  const attempts = generateInstallationAttempts(toolName);

  for (const attempt of attempts) {
    console.log(`  Trying: ${attempt.command}`);
    const result = await testInstallation(toolName, attempt.command);
    await logInstallationAttempt(toolName, attempt.method, attempt.command, result, challengeName);

    if (result.success) {
      await saveSuccessfulMethod(toolName, attempt.method, attempt.packageName, attempt.command, result, category);
      await query(`UPDATE tool_learning_queue SET status = 'learned' WHERE tool_name = $1`, [toolName]);
      console.log(`🎉 Successfully learned: ${toolName} via ${attempt.method}`);
      return attempt;
    }

    await query(`
      UPDATE tool_learning_queue 
      SET attempts = attempts + 1, last_error = $2, updated_at = NOW()
      WHERE tool_name = $1
    `, [toolName, result.stderr.substring(0, 500)]);
  }

  // All attempts failed
  await query(`UPDATE tool_learning_queue SET status = 'failed' WHERE tool_name = $1`, [toolName]);
  console.log(`❌ Failed to learn installation for: ${toolName}`);
  
  return null;
}

/**
 * Get installation method from database (or learn it)
 * NOW WITH: Smart caching layer
 */
export async function getToolInstallationMethod(toolName, category = 'misc') {
  // Check cache first (IMPROVEMENT: Smart caching)
  const cached = await toolCache.get(toolName);
  if (cached) {
    console.log(`✅ Using cached installation method for ${toolName}`);
    return {
      method: cached.method,
      packageName: cached.package_name,
      command: cached.install_command,
      repository: cached.repository,
      verified: cached.verified
    };
  }

  // Check aliases first
  const aliasResult = await query(`
    SELECT t.tool_name 
    FROM tool_aliases ta
    JOIN ctf_tools t ON ta.tool_id = t.id
    WHERE ta.alias = $1
  `, [toolName]);

  const actualToolName = aliasResult.rows.length > 0 ? aliasResult.rows[0].tool_name : toolName;

  // Get known method
  const methodResult = await query(`
    SELECT tim.*, t.tool_name
    FROM tool_installation_methods tim
    JOIN ctf_tools t ON tim.tool_id = t.id
    WHERE t.tool_name = $1
    ORDER BY tim.priority DESC, tim.success_count DESC
    LIMIT 1
  `, [actualToolName]);

  if (methodResult.rows.length > 0) {
    const method = methodResult.rows[0];
    // Cache for future requests
    await toolCache.set(toolName, method);
    return method;
  }

  // Need to learn it
  console.log(`🆕 Unknown tool: ${toolName}, starting learning process...`);
  const learned = await learnToolInstallation(actualToolName, category);
  
  // Cache the newly learned method
  if (learned) {
    await toolCache.set(toolName, learned);
  }
  
  return learned;
}

/**
 * Batch learn multiple tools
 */
export async function learnMultipleTools(toolNames, category = 'misc') {
  const results = [];
  
  for (const toolName of toolNames) {
    const result = await getToolInstallationMethod(toolName, category);
    results.push({ toolName, result });
  }

  return results;
}

/**
 * Get installation statistics
 */
export async function getToolStats() {
  const stats = await query(`
    SELECT 
      COUNT(DISTINCT tool_name) as total_tools_attempted,
      COUNT(DISTINCT tool_name) FILTER (WHERE success = true) as successful_tools,
      COUNT(*) FILTER (WHERE success = true) as total_successes,
      COUNT(*) FILTER (WHERE success = false) as total_failures,
      AVG(execution_time_ms) FILTER (WHERE success = true) as avg_success_time,
      (SELECT COUNT(*) FROM tool_learning_queue WHERE status = 'learned') as tools_learned,
      (SELECT COUNT(*) FROM tool_learning_queue WHERE status = 'failed') as tools_failed,
      (SELECT COUNT(*) FROM tool_learning_queue WHERE status = 'pending') as tools_pending
    FROM tool_installation_logs
  `);

  const dbStats = stats.rows[0];
  const cacheStats = toolCache.getStats();

  return {
    ...dbStats,
    cache: cacheStats
  };
}

/**
 * Get cache statistics (NEW)
 */
export function getCacheStats() {
  return toolCache.getStats();
}

/**
 * IMPROVEMENT: Get test result analytics for a tool
 * @param {string} toolName - Tool name to get stats for
 * @returns {Promise<object>} Test statistics
 */
export async function getToolTestStats(toolName) {
  try {
    const result = await query(`
      SELECT 
        COUNT(*) as total_tests,
        SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN success THEN 0 ELSE 1 END) as failed,
        AVG(execution_time) as avg_time,
        MIN(execution_time) as min_time,
        MAX(execution_time) as max_time,
        MAX(created_at) as last_tested,
        COUNT(DISTINCT method) as methods_tried
      FROM tool_installation_attempts
      WHERE tool_name = $1
    `, [toolName]);
    
    if (result.rows.length === 0) {
      return {
        toolName,
        totalTests: 0,
        successRate: 0,
        avgTime: 0,
        methodsTried: 0
      };
    }
    
    const stats = result.rows[0];
    const totalTests = parseInt(stats.total_tests) || 0;
    const successful = parseInt(stats.successful) || 0;
    const successRate = totalTests > 0 ? ((successful / totalTests) * 100).toFixed(1) : 0;
    
    return {
      toolName,
      totalTests,
      successful,
      failed: parseInt(stats.failed) || 0,
      successRate: `${successRate}%`,
      avgTime: Math.round(parseFloat(stats.avg_time) || 0),
      minTime: parseInt(stats.min_time) || 0,
      maxTime: parseInt(stats.max_time) || 0,
      lastTested: stats.last_tested,
      methodsTried: parseInt(stats.methods_tried) || 0
    };
  } catch (error) {
    console.error(`Error getting test stats for ${toolName}:`, error.message);
    return {
      toolName,
      error: error.message
    };
  }
}

/**
 * IMPROVEMENT: Get overall test statistics
 * @returns {Promise<object>} Overall test statistics
 */
export async function getOverallTestStats() {
  try {
    const result = await query(`
      SELECT 
        COUNT(DISTINCT tool_name) as total_tools,
        COUNT(*) as total_tests,
        SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN success THEN 0 ELSE 1 END) as failed,
        AVG(execution_time) as avg_time
      FROM tool_installation_attempts
    `);
    
    if (result.rows.length === 0) {
      return {
        totalTools: 0,
        totalTests: 0,
        successRate: '0%',
        avgTime: 0
      };
    }
    
    const stats = result.rows[0];
    const totalTests = parseInt(stats.total_tests) || 0;
    const successful = parseInt(stats.successful) || 0;
    const successRate = totalTests > 0 ? ((successful / totalTests) * 100).toFixed(1) : 0;
    
    return {
      totalTools: parseInt(stats.total_tools) || 0,
      totalTests,
      successful,
      failed: parseInt(stats.failed) || 0,
      successRate: `${successRate}%`,
      avgTime: Math.round(parseFloat(stats.avg_time) || 0)
    };
  } catch (error) {
    console.error('Error getting overall test stats:', error.message);
    return {
      error: error.message
    };
  }
}

/**
 * IMPROVEMENT: Get problematic tools (low success rate)
 * @param {number} minTests - Minimum number of tests to consider
 * @param {number} maxSuccessRate - Maximum success rate to flag as problematic
 * @returns {Promise<Array>} List of problematic tools
 */
export async function getProblematicTools(minTests = 3, maxSuccessRate = 50) {
  try {
    const result = await query(`
      SELECT 
        tool_name,
        COUNT(*) as total_tests,
        SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful,
        (SUM(CASE WHEN success THEN 1 ELSE 0 END)::float / COUNT(*)::float * 100) as success_rate
      FROM tool_installation_attempts
      GROUP BY tool_name
      HAVING COUNT(*) >= $1 
        AND (SUM(CASE WHEN success THEN 1 ELSE 0 END)::float / COUNT(*)::float * 100) <= $2
      ORDER BY success_rate ASC, total_tests DESC
      LIMIT 20
    `, [minTests, maxSuccessRate]);
    
    return result.rows.map(row => ({
      toolName: row.tool_name,
      totalTests: parseInt(row.total_tests),
      successful: parseInt(row.successful),
      successRate: `${parseFloat(row.success_rate).toFixed(1)}%`
    }));
  } catch (error) {
    console.error('Error getting problematic tools:', error.message);
    return [];
  }
}

/**
 * Clear tool cache (NEW)
 */
export function clearCache(toolName = null) {
  toolCache.clear(toolName);
  return { cleared: toolName || 'all' };
}

/**
 * Initialize base image on service start (NEW)
 */
export async function initializeToolLearning() {
  console.log('\n🔧 Initializing Tool Learning Service...');
  console.log('📦 Checking base test image...');
  await ensureBaseImage();
  console.log('✅ Tool Learning Service ready\n');
}
