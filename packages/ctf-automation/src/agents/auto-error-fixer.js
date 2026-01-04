/**
 * Automated Error Detection and Fixing System
 * 
 * This module automatically detects and fixes common deployment errors
 * without requiring AI analysis, making fixes faster and more reliable.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Get project root directory (3 levels up from this file)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

/**
 * Known error patterns and their automatic fixes
 */
const ERROR_PATTERNS = [
  // CentOS EOL Repository Error (any CentOS version)
  {
    pattern: /Cannot find a valid baseurl for repo: base\/7\/x86_64|mirrorlist\.centos\.org.*Unknown error|CentOS.*EOL|FROM centos/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: CentOS EOL repository error - replacing with Rocky Linux 9');
      const fixes = [];
      
      // Find all Dockerfiles
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Replace any CentOS version with Rocky Linux 9
        if (content.includes('FROM centos')) {
          content = content.replace(/FROM centos:\d+/g, 'FROM rockylinux:9');
          content = content.replace(/FROM centos:latest/g, 'FROM rockylinux:9');
          content = content.replace(/FROM centos/g, 'FROM rockylinux:9');
          // Update package manager from yum to dnf
          content = content.replace(/RUN yum install/g, 'RUN dnf install');
          content = content.replace(/yum clean all/g, 'dnf clean all');
          content = content.replace(/yum update/g, 'dnf update');
          modified = true;
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Replaced CentOS with Rocky Linux 9' };
    }
  },
  
  // Alpine telnet package error
  {
    pattern: /telnet.*no such package|ERROR.*unable to select packages.*telnet/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Alpine telnet package error');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        if (content.includes('FROM alpine') || content.includes('FROM alpine:')) {
          const telnetRegex = /(\s|^)telnet(\s|$)/g;
          if (telnetRegex.test(content)) {
            content = content.replace(/(\s|^)telnet(\s|$)/g, '$1busybox-extras$2');
            modified = true;
          }
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Replaced telnet with busybox-extras for Alpine' };
    }
  },
  
  // Package manager mismatch (apt-get on Alpine, etc.)
  {
    pattern: /\/bin\/sh:.*apt-get: command not found|apt-get.*not found/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Package manager mismatch (apt-get not found)');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Check if it's Alpine but using apt-get
        if ((content.includes('FROM alpine') || content.includes('FROM alpine:')) && content.includes('apt-get')) {
          // Replace apt-get with apk
          content = content.replace(/apt-get update/g, 'apk update');
          content = content.replace(/apt-get install -y/g, 'apk add --no-cache');
          content = content.replace(/apt-get clean.*rm -rf.*apt\/lists/g, 'rm -rf /var/cache/apk/*');
          modified = true;
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Fixed package manager mismatch' };
    }
  },
  
  // Invalid COPY command with shell syntax
  {
    pattern: /COPY.*2>|COPY.*\|\||COPY.*&&|COPY.*;/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Invalid COPY command with shell syntax');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Fix COPY commands with shell syntax
        const invalidCopyRegex = /^COPY\s+([^\s]+)\s+([^\s]+)\s+(2>|\|\||&&|;)/m;
        if (invalidCopyRegex.test(content)) {
          content = content.replace(
            /^COPY\s+([^\s]+)\s+([^\s]+)\s+(.*)$/gm,
            (match, source, dest, shellPart) => {
              if (shellPart && (shellPart.includes('2>') || shellPart.includes('||') || shellPart.includes('&&') || shellPart.includes(';'))) {
                modified = true;
                return `RUN cp ${source} ${dest} ${shellPart}`;
              }
              return match;
            }
          );
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Fixed invalid COPY commands' };
    }
  },
  
  // chown invalid user error
  {
    pattern: /chown: invalid user|chown.*failed/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: chown invalid user error');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Find chown commands and ensure user exists
        const chownRegex = /RUN.*chown\s+(-R\s+)?([^\s:]+):([^\s]+)/g;
        const matches = [...content.matchAll(chownRegex)];
        
        for (const match of matches) {
          const user = match[2];
          const group = match[3];
          
          // Check if user creation exists before this chown
          const beforeChown = content.substring(0, content.indexOf(match[0]));
          if (!beforeChown.includes(`useradd`) && !beforeChown.includes(`adduser`)) {
            // Add user creation before chown
            const useraddLine = `RUN useradd -r -s /bin/false ${user} 2>/dev/null || true && \\\n    groupadd -r ${group} 2>/dev/null || true && \\\n    `;
            content = content.replace(match[0], useraddLine + match[0].replace('RUN ', ''));
            modified = true;
          }
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Fixed chown invalid user errors' };
    }
  },
  
  // Port already allocated error
  {
    pattern: /port is already allocated|Bind for.*failed|address already in use/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Port already allocated error');
      const fixes = [];
      
      // Find docker-compose.yml
      const composeFile = path.join(challengePath, 'docker-compose.yml');
      if (fs.existsSync(composeFile)) {
        let content = fs.readFileSync(composeFile, 'utf-8');
        let modified = false;
        
        // Remove all port mappings (CTF challenges should use private IPs only)
        const portMappingRegex = /ports:\s*\n\s*-\s*["']?\d+:\d+["']?/g;
        if (portMappingRegex.test(content)) {
          content = content.replace(/ports:\s*\n\s*-\s*["']?\d+:\d+["']?/g, '');
          modified = true;
        }
        
        if (modified) {
          fs.writeFileSync(composeFile, content, 'utf-8');
          fixes.push({ file: 'docker-compose.yml', fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Removed port mappings (using private IPs only)' };
    }
  },
  
  // Missing file or directory
  {
    pattern: /no such file or directory|COPY failed.*not found|file not found/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Missing file or directory error');
      const fixes = [];
      
      // Extract missing file path from error
      const fileMatch = errorOutput.match(/COPY failed.*['"]([^'"]+)['"]|no such file.*['"]([^'"]+)['"]/i);
      if (fileMatch) {
        const missingFile = fileMatch[1] || fileMatch[2];
        console.log(`   Detected missing file: ${missingFile}`);
        
        // Try to create the missing file or directory
        const fullPath = path.join(challengePath, missingFile);
        const dir = path.dirname(fullPath);
        
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
          fixes.push({ file: missingFile, fixed: true, action: 'created_directory' });
        }
        
        // If it's a file, create an empty one
        if (missingFile.includes('.') && !fs.existsSync(fullPath)) {
          fs.writeFileSync(fullPath, '# Auto-generated placeholder file\n', 'utf-8');
          fixes.push({ file: missingFile, fixed: true, action: 'created_file' });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Created missing files/directories' };
    }
  },
  
  // Invalid package name (service name used as package)
  {
    pattern: /unable to locate package.*netbios|package.*not found.*netbios|package.*not found.*cifs/i,
    severity: 'warning',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Invalid package name (service name used as package)');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      const invalidPackages = ['netbios', 'netbios-ns', 'netbios-ssn', 'netbios-dgm', 'cifs', 'smb2', 'smb3'];
      
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        for (const invalidPkg of invalidPackages) {
          const pkgRegex = new RegExp(`\\s+${invalidPkg}\\s+`, 'g');
          if (pkgRegex.test(content)) {
            content = content.replace(pkgRegex, ' ');
            modified = true;
          }
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Removed invalid package names' };
    }
  },
  
  // Rocky Linux curl-minimal conflict
  {
    pattern: /curl-minimal.*conflicts with curl|conflicting requests.*curl|Problem: problem with installed package curl-minimal/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Rocky Linux curl-minimal conflict');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Check if it's Rocky Linux and has dnf install with curl
        if (content.includes('FROM rockylinux') && content.includes('dnf install') && content.includes('curl')) {
          // Add --allowerasing to dnf install commands to allow replacing curl-minimal with curl
          // Pattern: dnf install -y ... curl ...
          // Replace with: dnf install -y --allowerasing ... curl ...
          if (!content.includes('--allowerasing')) {
            // Find dnf install lines and add --allowerasing
            content = content.replace(
              /(dnf install -y)(\s+--setopt=install_weak_deps=False)?(\s+[^\n]*curl[^\n]*)/g,
              (match, dnfCmd, setopt, rest) => {
                if (!match.includes('--allowerasing')) {
                  modified = true;
                  return `${dnfCmd}${setopt || ''} --allowerasing${rest}`;
                }
                return match;
              }
            );
            
            // Also handle cases without --setopt
            content = content.replace(
              /(dnf install -y)(\s+[^\n]*curl[^\n]*)/g,
              (match, dnfCmd, rest) => {
                if (!match.includes('--allowerasing')) {
                  modified = true;
                  return `${dnfCmd} --allowerasing${rest}`;
                }
                return match;
              }
            );
          }
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Added --allowerasing to resolve curl-minimal conflict' };
    }
  },
  
  // Rocky Linux iputils-ping package name error
  {
    pattern: /No match for argument: iputils-ping|Unable to find a match: iputils-ping|Error: Unable to find a match: iputils-ping/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Rocky Linux iputils-ping package name error');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Check if it's Rocky Linux and has iputils-ping
        if (content.includes('FROM rockylinux') && content.includes('iputils-ping')) {
          // Replace iputils-ping with iputils for Rocky Linux/RHEL
          content = content.replace(/\biputils-ping\b/g, 'iputils');
          modified = true;
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Replaced iputils-ping with iputils for Rocky Linux' };
    }
  },
  
  // Rocky Linux xinetd package not available error
  {
    pattern: /No match for argument: xinetd|Unable to find a match: xinetd|Error: Unable to find a match: xinetd/i,
    severity: 'critical',
    fix: async (challengePath, errorOutput) => {
      console.log('🔧 Auto-fixing: Rocky Linux xinetd package not available');
      const fixes = [];
      
      const dockerfiles = findDockerfiles(challengePath);
      for (const dockerfile of dockerfiles) {
        let content = fs.readFileSync(dockerfile, 'utf-8');
        let modified = false;
        
        // Check if it's Rocky Linux/RHEL and has xinetd
        if (content.includes('FROM rockylinux') && content.includes('xinetd')) {
          // Remove xinetd - it's deprecated and not available in Rocky Linux 9
          // Replace with space to maintain command structure
          content = content.replace(/\s+xinetd\s+/g, ' ');
          content = content.replace(/\s+xinetd$/g, '');
          content = content.replace(/^xinetd\s+/g, '');
          modified = true;
        }
        
        if (modified) {
          fs.writeFileSync(dockerfile, content, 'utf-8');
          fixes.push({ file: path.relative(challengePath, dockerfile), fixed: true });
        }
      }
      
      return { success: fixes.length > 0, fixes, message: 'Removed xinetd (deprecated, not available in Rocky Linux 9)' };
    }
  }
];

/**
 * Find all Dockerfiles in challenge directory
 */
function findDockerfiles(challengePath) {
  const dockerfiles = [];
  
  function searchDir(dir) {
    if (!fs.existsSync(dir)) return;
    
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        searchDir(fullPath);
      } else if (entry.name.includes('Dockerfile')) {
        dockerfiles.push(fullPath);
      }
    }
  }
  
  searchDir(challengePath);
  return dockerfiles;
}

/**
 * Automatically detect and fix deployment errors
 * 
 * @param {string} challengeName - Name of the challenge
 * @param {string} errorOutput - Docker error output
 * @param {Function} progressCallback - Optional progress callback
 * @returns {Promise<Object>} Fix result with success status and applied fixes
 */
export async function autoFixDeploymentError(challengeName, errorOutput, progressCallback = null) {
  console.log(`\n🤖 Auto-fixing deployment errors for: ${challengeName}`);
  
  const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
  
  if (!fs.existsSync(challengePath)) {
    return {
      success: false,
      error: `Challenge path does not exist: ${challengePath}`,
      fixes: []
    };
  }
  
  const appliedFixes = [];
  let fixedAny = false;
  
  // Try each error pattern
  for (const errorPattern of ERROR_PATTERNS) {
    if (errorPattern.pattern.test(errorOutput)) {
      console.log(`\n🔍 Detected error pattern: ${errorPattern.severity} - ${errorPattern.pattern.source}`);
      
      if (progressCallback) {
        progressCallback({ 
          step: 'auto-fix', 
          message: `🔧 Auto-fixing ${errorPattern.severity} error...` 
        });
      }
      
      try {
        const fixResult = await errorPattern.fix(challengePath, errorOutput);
        
        if (fixResult.success && fixResult.fixes.length > 0) {
          appliedFixes.push({
            pattern: errorPattern.pattern.source,
            severity: errorPattern.severity,
            fixes: fixResult.fixes,
            message: fixResult.message
          });
          fixedAny = true;
          console.log(`✅ ${fixResult.message}`);
        }
      } catch (fixError) {
        console.error(`❌ Error applying fix for pattern ${errorPattern.pattern.source}:`, fixError.message);
      }
    }
  }
  
  if (fixedAny) {
    console.log(`\n✅ Auto-fixed ${appliedFixes.length} error pattern(s)`);
    return {
      success: true,
      fixesApplied: true,
      fixes: appliedFixes,
      message: `Automatically fixed ${appliedFixes.length} error pattern(s)`
    };
  } else {
    console.log('⚠️  No automatic fixes available for this error');
    return {
      success: false,
      fixesApplied: false,
      fixes: [],
      message: 'No automatic fixes matched this error pattern'
    };
  }
}

/**
 * Comprehensive error detection and fixing with retry logic
 * 
 * @param {string} challengeName - Name of the challenge
 * @param {Function} deployFunction - Function to call for deployment
 * @param {Function} progressCallback - Optional progress callback
 * @param {number} maxRetries - Maximum number of retry attempts (default: 3)
 * @returns {Promise<Object>} Deployment result
 */
export async function deployWithAutoFix(challengeName, deployFunction, progressCallback = null, maxRetries = 3) {
  let lastError = null;
  let attempt = 0;
  
  while (attempt < maxRetries) {
    attempt++;
    
    try {
      console.log(`\n🚀 Deployment attempt ${attempt}/${maxRetries}...`);
      if (progressCallback) {
        progressCallback({ 
          step: 'deploy-attempt', 
          message: `🚀 Deployment attempt ${attempt}/${maxRetries}...` 
        });
      }
      
      const result = await deployFunction();
      console.log('✅ Deployment successful!');
      return { success: true, result, attempts: attempt };
      
    } catch (error) {
      lastError = error;
      console.error(`❌ Deployment attempt ${attempt} failed:`, error.message);
      
      // Check if we have error output to analyze
      const errorOutput = error.dockerOutput?.fullOutput || error.message || '';
      
      if (attempt < maxRetries && errorOutput) {
        console.log(`\n🤖 Attempting auto-fix (attempt ${attempt}/${maxRetries})...`);
        
        // Try automatic fixes
        const fixResult = await autoFixDeploymentError(challengeName, errorOutput, progressCallback);
        
        if (fixResult.fixesApplied) {
          console.log(`✅ Applied ${fixResult.fixes.length} automatic fix(es), retrying...`);
          if (progressCallback) {
            progressCallback({ 
              step: 'retry-after-fix', 
              message: `🔄 Retrying after ${fixResult.fixes.length} fix(es)...` 
            });
          }
          // Continue to next iteration (retry)
          continue;
        } else {
          // No automatic fixes available, try AI analysis
          console.log('🤖 No automatic fixes available, trying AI analysis...');
          try {
            const { analyzeDockerOutput } = await import('./pre-deploy-validator-agent.js');
            const aiAnalysis = await analyzeDockerOutput(challengeName, errorOutput, progressCallback);
            
            if (aiAnalysis.fixesApplied && aiAnalysis.shouldRetry) {
              console.log('✅ AI fixes applied, retrying...');
              continue;
            }
          } catch (aiError) {
            console.warn('⚠️  AI analysis failed:', aiError.message);
          }
        }
      }
      
      // If we're out of retries or no fixes available, break
      if (attempt >= maxRetries) {
        break;
      }
    }
  }
  
  // All retries exhausted
  console.error(`\n❌ Deployment failed after ${attempt} attempt(s)`);
  return {
    success: false,
    error: lastError?.message || 'Deployment failed',
    attempts: attempt,
    lastError
  };
}

export default {
  autoFixDeploymentError,
  deployWithAutoFix,
  ERROR_PATTERNS
};

