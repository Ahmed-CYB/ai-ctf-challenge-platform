import Anthropic from '@anthropic-ai/sdk';
import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { fileURLToPath } from 'url';

// Get project root directory (3 levels up from this file)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const getClonePath = () => process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const SYSTEM_PROMPT = `You are an expert DevOps and Docker engineer specializing in CTF challenge deployment validation.

Your job is to analyze challenge files BEFORE deployment and identify any issues that would cause docker compose to fail.

**PACKAGE NAME VALIDATION (CRITICAL):**
Kali Linux does not have these packages - they MUST be replaced:
- ❌ mysql-server → ✅ mariadb-server
- ❌ mysql-client → ✅ mariadb-client
- ❌ mysql → ✅ mariadb-server
- ❌ web-server → ✅ apache2
- ❌ http-server → ✅ apache2
- ❌ database → ✅ mariadb-server

**SERVICE NAME vs PACKAGE NAME (CRITICAL):**
These are SERVICE NAMES/PORTS, NOT packages - they MUST be removed from apt-get install:
- ❌ netbios - service name, not a package (part of Samba)
- ❌ netbios-ns (port 137) - part of Samba, not a package
- ❌ netbios-ssn (port 139) - part of Samba, not a package
- ❌ netbios-dgm (port 138) - part of Samba, not a package
- ❌ cifs - protocol, not a package (comes with Samba)
- ❌ smb2, smb3 - protocols, not packages (come with Samba)

If Samba is needed, install ONLY "samba" package - it includes all NetBIOS services automatically.

ANY apt-get install command with these invalid packages will fail.
Check ALL Dockerfiles for these problematic package names and fix them BEFORE deployment.

**SYSTEM USERNAME CONFLICTS (CRITICAL):**
These usernames already exist in Kali Linux base image and WILL cause "useradd: user already exists" errors:
- ❌ FORBIDDEN: backup, admin, daemon, bin, sys, sync, games, man, lp, mail, news, uucp, proxy, www-data, list, irc, gnats, nobody, systemd-network, systemd-resolve, messagebus, systemd-timesync, syslog, _apt, tss, uuidd, tcpdump, landscape, pollinate, sshd, systemd-coredump, lxd, usbmux, dnsmasq, libvirt-qemu, libvirt-dnsmasq, fwupd-refresh, colord, pulse, geoclue, gnome-initial-setup, gdm, postgres, mysql, redis, mongodb, named, postfix
- ✅ USE INSTEAD: ftpuser, webadmin, dbadmin, smbuser, appuser, devuser, testuser, clientA, vendor123, employee01, ftpadmin, ftpbackup, webbackup, dbbackup
- Check ALL "useradd" commands in Dockerfiles for these conflicts
- Solution: Replace with challenge-specific usernames OR use conditional: useradd username 2>/dev/null || true

**DOCKERFILE PERMISSION ERRORS (CRITICAL):**
- ❌ chmod/chown WILL FAIL if directories don't exist
- ✅ ALWAYS create directories with mkdir -p BEFORE chmod/chown
- Example: RUN mkdir -p /var/ftp/uploads && chmod 777 /var/ftp/uploads
- Check ALL chmod/chown commands have corresponding mkdir -p first
- OR use conditional: chmod 777 /path 2>/dev/null || true

**USER EXISTENCE IN CHOWN COMMANDS (CRITICAL):**
- ❌ chown -R ftp:ftp WILL FAIL if 'ftp' user doesn't exist
- ❌ chown -R www-data:www-data WILL FAIL if 'www-data' user doesn't exist
- ✅ ALWAYS create the user BEFORE using it in chown commands
- ✅ For FTP: Use 'ftpuser' (which is created) OR create 'ftp' user first
- ✅ For web: Use 'www-data' only if it exists, otherwise use 'nobody' or create the user
- Example fix: 
  \`\`\`dockerfile
  RUN useradd -r -s /bin/false ftp 2>/dev/null || true && \\
      chown -R ftp:ftp /var/ftp/pub
  \`\`\`
- OR use existing users: chown -R ftpuser:ftpuser (if ftpuser was created)
- Check ALL chown commands reference users that exist or are created in the same RUN command

Common issues to check:
1. **Dockerfile Path Mismatches**: 
   - docker-compose.yml says "dockerfile: Dockerfile" but file is at "victim/Dockerfile"
   - docker-compose.yml says "context: ." but Dockerfile is in subdirectory
   - Solution: Update docker-compose.yml to match actual file locations

2. **Missing Files**:
   - docker-compose.yml references files that don't exist (e.g., Dockerfile for victim service)
   - COPY commands reference non-existent files
   - Solution: Create missing files with appropriate content OR update references
   - When creating Dockerfiles, provide COMPLETE, WORKING file content

3. **Invalid Docker Syntax**:
   - Multi-stage build issues (COPY --from=builder /root/.local)
   - Invalid YAML syntax
   - Missing required fields

4. **Port Conflicts and Private IPs**:
   - Host port mappings that would conflict or are not allowed
   - Solution: NEVER use port mappings - ALL challenges MUST use private IPs only
   - docker-compose.yml MUST have custom networks with IPAM configuration
   - Services MUST have static private IPs (e.g., 172.23.193.10, 172.23.193.100)
   - NO ports: section allowed in docker-compose.yml
   - Attacker container should ONLY be on challenge network for security isolation

**PRIVATE IP REQUIREMENTS:**
All CTF challenges use isolated private networks with static IP addresses. NEVER create port mappings.

Example correct docker-compose.yml structure (NO port mappings allowed):
- Services MUST have static IPs: victim=172.X.193.10, attacker=172.X.193.100
- Networks MUST have IPAM configuration with subnet/gateway
- Attacker stays ONLY on challenge network (no ctf-instances-network) for security
- NO "ports:" sections anywhere in docker-compose.yml

**YAML SYNTAX VALIDATION (CRITICAL):**
- Check for "[object Object]" in YAML - this indicates JavaScript object serialization error
- Subnet and gateway MUST be strings, not objects: subnet: "172.29.193.0/24" (correct) vs subnet: [object Object] (WRONG)
- All YAML values must be properly quoted strings or valid YAML primitives
- Check for duplicate network definitions
- Check for malformed indentation (especially in ipam config sections)

**DOCKERFILE COPY COMMAND VALIDATION (CRITICAL):**
- ❌ NEVER use shell syntax in COPY commands: COPY *.py /usr/local/bin/ 2>/dev/null || true (WRONG)
- ✅ COPY commands are simple file operations: COPY *.py /usr/local/bin/ (correct)
- ❌ COPY does NOT support: shell redirection (2>/dev/null), operators (|| true), conditionals (if/then)
- ✅ If files might not exist, use RUN with shell instead: RUN cp *.py /usr/local/bin/ 2>/dev/null || true
- ✅ Or check existence first: RUN if [ -f *.py ]; then cp *.py /usr/local/bin/; fi
- Check ALL COPY commands for shell syntax and fix them immediately

CRITICAL RESPONSE FORMAT:
You must respond with a JSON object in this EXACT format:

{
  "valid": true|false,
  "issues": [
    {
      "file": "docker-compose.yml",
      "issue": "Dockerfile path mismatch",
      "details": "docker-compose.yml references 'Dockerfile' in context '.' but actual file is at 'victim/Dockerfile'",
      "severity": "critical|warning|info"
    }
  ],
  "fixes": [
    {
      "file": "docker-compose.yml",
      "action": "modify",
      "changes": [
        {
          "type": "replace",
          "find": "context: .\\n      dockerfile: Dockerfile",
          "replace": "context: ./victim\\n      dockerfile: Dockerfile"
        }
      ],
      "explanation": "Updated build context to ./victim to match actual Dockerfile location"
    },
    {
      "file": "Dockerfile",
      "action": "create",
      "content": "FROM ubuntu:20.04\\nRUN apt-get update && apt-get install -y vsftpd\\nCOPY flag.txt /root/flag.txt\\nEXPOSE 21\\nCMD [\\\"vsftpd\\\"]",
      "explanation": "Created missing Dockerfile for victim service with FTP server configuration"
    }
  ],
  "canDeploy": true|false,
  "summary": "Brief summary of validation results"
}

**IMPORTANT FOR FILE CREATION:**
- When action is "create", you MUST provide the "content" field with complete, working file content
- Do not leave content undefined or empty
- Provide full Dockerfile content based on the challenge requirements
- Use \\n for newlines in JSON strings

If there are NO issues, return:
{
  "valid": true,
  "issues": [],
  "fixes": [],
  "canDeploy": true,
  "summary": "All validation checks passed, ready to deploy"
}

Be precise with your fixes - provide exact text to find and replace.`;

/**
 * Gather all files in the challenge directory
 */
async function gatherChallengeFiles(challengePath) {
  const files = {};
  
  // Read all files recursively
  function readDir(dir, relativePath = '') {
    try {
      const items = fs.readdirSync(dir);
      
      for (const item of items) {
        const fullPath = path.join(dir, item);
        const relPath = path.join(relativePath, item);
        
        try {
          const stat = fs.statSync(fullPath);
          
          if (stat.isDirectory()) {
            readDir(fullPath, relPath);
          } else {
            try {
              // Skip binary files and large files
              if (stat.size > 1024 * 1024) {  // Skip files larger than 1MB
                console.warn(`⚠️  Skipping large file: ${relPath} (${stat.size} bytes)`);
                continue;
              }
              
              // Skip node_modules and other common directories
              if (relPath.includes('node_modules') || relPath.includes('.git')) {
                continue;
              }
              
              // Try to read as text, skip if it fails (likely binary)
              const content = fs.readFileSync(fullPath, 'utf-8');
              
              // Basic check for binary content
              if (content.includes('\0')) {
                console.warn(`⚠️  Skipping binary file: ${relPath}`);
                continue;
              }
              
              // IMPROVEMENT: Validate file content doesn't contain dangerous patterns
              // Skip files that look like they might cause issues if accidentally executed
              if (relPath.endsWith('.js') && (content.includes('eval(') || content.includes('Function('))) {
                console.warn(`⚠️  Skipping potentially unsafe JavaScript file: ${relPath}`);
                continue;
              }
              
              files[relPath.replace(/\\/g, '/')] = content;
            } catch (err) {
              console.warn(`⚠️  Could not read ${relPath}: ${err.message}`);
              // Continue without this file rather than failing
            }
          }
        } catch (statError) {
          console.warn(`⚠️  Could not stat ${relPath}: ${statError.message}`);
          // Continue without this file
        }
      }
    } catch (readError) {
      console.warn(`⚠️  Could not read directory ${dir}: ${readError.message}`);
      // Continue without this directory
    }
  }
  
  readDir(challengePath);
  return files;
}

/**
 * Apply fixes to files
 */
async function applyFixes(challengePath, fixes) {
  const appliedFixes = [];
  
  for (const fix of fixes) {
    const filePath = path.join(challengePath, fix.file);
    
    try {
      if (fix.action === 'modify') {
        let content = fs.readFileSync(filePath, 'utf-8');
        let modified = false;
        
        for (const change of fix.changes) {
          if (change.type === 'replace') {
            const oldContent = content;
            content = content.replace(change.find, change.replace);
            if (content !== oldContent) {
              modified = true;
              console.log(`✅ Applied fix to ${fix.file}: ${fix.explanation}`);
            }
          }
        }
        
        // IMPROVEMENT: Post-process to fix invalid COPY commands with shell syntax
        if (fix.file.includes('Dockerfile')) {
          const invalidCopyRegex = /^COPY\s+([^\s]+)\s+([^\s]+)\s+(2>|\|\||&&|;)/m;
          if (invalidCopyRegex.test(content)) {
            const oldContent = content;
            // Fix: COPY *.py /usr/local/bin/ 2>/dev/null || true
            // To: RUN cp *.py /usr/local/bin/ 2>/dev/null || true
            content = content.replace(
              /^COPY\s+([^\s]+)\s+([^\s]+)\s+(.*)$/gm,
              (match, source, dest, shellPart) => {
                if (shellPart && (shellPart.includes('2>') || shellPart.includes('||') || shellPart.includes('&&') || shellPart.includes(';'))) {
                  return `RUN cp ${source} ${dest} ${shellPart}`;
                }
                return match;
              }
            );
            if (content !== oldContent) {
              modified = true;
              console.log(`✅ Fixed invalid COPY command in ${fix.file}`);
            }
          }
        }
        
        if (modified) {
          fs.writeFileSync(filePath, content, 'utf-8');
          appliedFixes.push({
            file: fix.file,
            explanation: fix.explanation,
            success: true
          });
        }
      } else if (fix.action === 'create') {
        // Validate content exists
        if (!fix.content) {
          console.error(`❌ Cannot create ${fix.file}: content is undefined`);
          appliedFixes.push({
            file: fix.file,
            explanation: fix.explanation,
            success: false,
            error: 'Content is undefined - Claude must provide file content for creation'
          });
          continue;
        }
        
        // Create directory if needed
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        
        fs.writeFileSync(filePath, fix.content, 'utf-8');
        console.log(`✅ Created ${fix.file}: ${fix.explanation}`);
        appliedFixes.push({
          file: fix.file,
          explanation: fix.explanation,
          success: true
        });
      } else if (fix.action === 'delete') {
        fs.unlinkSync(filePath);
        console.log(`✅ Deleted ${fix.file}: ${fix.explanation}`);
        appliedFixes.push({
          file: fix.file,
          explanation: fix.explanation,
          success: true
        });
      }
    } catch (err) {
      console.error(`❌ Failed to apply fix to ${fix.file}: ${err.message}`);
      appliedFixes.push({
        file: fix.file,
        explanation: fix.explanation,
        success: false,
        error: err.message
      });
    }
  }
  
  return appliedFixes;
}

/**
 * Validate challenge files before deployment using Claude Sonnet 4.5
 */
export async function validateBeforeDeployment(challengeName, progressCallback = null) {
  console.log(`\n🔍 Pre-deployment validation for: ${challengeName}`);
  
  const CLONE_PATH = getClonePath();
  const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
  
  if (!fs.existsSync(challengePath)) {
    return {
      success: false,
      error: `Challenge path does not exist: ${challengePath}`
    };
  }
  
  try {
    // Gather all files
    console.log('📁 Gathering challenge files...');
    if (progressCallback) progressCallback({ step: 'validation-gather', message: '📁 Analyzing challenge files...' });
    
    const files = await gatherChallengeFiles(challengePath);
    const fileList = Object.keys(files).join('\n');
    
    console.log(`📋 Found ${Object.keys(files).length} files`);
    
    // IMPROVEMENT: Validate YAML syntax for docker-compose.yml before AI analysis
    const composeFile = Object.keys(files).find(f => f.includes('docker-compose.yml'));
    if (composeFile) {
      try {
        const yamlContent = files[composeFile];
        
        // Check for common YAML errors
        if (yamlContent.includes('[object Object]')) {
          return {
            success: false,
            error: `Invalid YAML in ${composeFile}: JavaScript object serialized incorrectly (found "[object Object]"). This usually means a JavaScript object was inserted directly into YAML instead of its string property.`,
            issues: [{
              file: composeFile,
              issue: 'Invalid YAML: [object Object] detected',
              details: 'A JavaScript object was serialized incorrectly. Check subnet, gateway, or other object properties in docker-compose.yml generation.',
              severity: 'critical'
            }]
          };
        }
        
        // Try to parse YAML to catch syntax errors
        try {
          const parsed = yaml.load(yamlContent);
          if (!parsed || typeof parsed !== 'object') {
            throw new Error('YAML parsed to non-object');
          }
          console.log('✅ YAML syntax validation passed');
        } catch (yamlError) {
          return {
            success: false,
            error: `Invalid YAML syntax in ${composeFile}: ${yamlError.message}`,
            issues: [{
              file: composeFile,
              issue: 'Invalid YAML syntax',
              details: yamlError.message,
              severity: 'critical'
            }]
          };
        }
      } catch (validationError) {
        console.warn('⚠️  YAML validation error:', validationError.message);
        // Continue with AI validation even if YAML check fails
      }
    }
    
    // IMPROVEMENT: Validate Dockerfile COPY commands for invalid shell syntax
    const dockerfiles = Object.keys(files).filter(f => f.includes('Dockerfile'));
    for (const dockerfilePath of dockerfiles) {
      try {
        const dockerfileContent = files[dockerfilePath];
        
        // Check for invalid COPY commands with shell syntax
        const invalidCopyPatterns = [
          /COPY\s+[^\n]+\s+2>/i,  // Shell redirection in COPY
          /COPY\s+[^\n]+\s+\|\|/i,  // Shell operator in COPY
          /COPY\s+[^\n]+\s+&&/i,   // Shell operator in COPY
          /COPY\s+[^\n]+\s+;/i     // Shell command separator in COPY
        ];
        
        for (const pattern of invalidCopyPatterns) {
          if (pattern.test(dockerfileContent)) {
            const match = dockerfileContent.match(new RegExp(`(${pattern.source})[^\\n]*`, 'i'));
            const invalidLine = match ? match[0] : 'unknown';
            
            return {
              success: false,
              error: `Invalid Dockerfile syntax in ${dockerfilePath}: COPY command contains shell syntax which is not supported. Found: ${invalidLine.trim()}`,
              issues: [{
                file: dockerfilePath,
                issue: 'Invalid COPY command with shell syntax',
                details: `COPY commands cannot use shell redirection (2>/dev/null), operators (|| true), or conditionals. Use RUN with shell instead if you need conditional logic.`,
                severity: 'critical',
                fix: {
                  action: 'modify',
                  changes: [{
                    type: 'replace',
                    find: invalidLine,
                    replace: invalidLine.replace(/COPY\s+([^\s]+)\s+([^\s]+)\s+.*/, 'RUN cp $1 $2 2>/dev/null || true')
                  }]
                }
              }]
            };
          }
        }
        
        // IMPROVEMENT: Check for invalid package names (service names used as packages)
        const invalidPackageNames = ['netbios', 'netbios-ns', 'netbios-ssn', 'netbios-dgm', 'cifs', 'smb2', 'smb3'];
        for (const invalidPkg of invalidPackageNames) {
          // Check in apt-get install lines
          const invalidPkgRegex = new RegExp(`apt-get\\s+install[^\\n]*\\b${invalidPkg}\\b[^\\n]*`, 'i');
          if (invalidPkgRegex.test(dockerfileContent)) {
            return {
              success: false,
              error: `Invalid package name in ${dockerfilePath}: "${invalidPkg}" is a service name/port, not a package. It's part of Samba - install only "samba" package.`,
              issues: [{
                file: dockerfilePath,
                issue: `Invalid package: ${invalidPkg}`,
                details: `${invalidPkg} is a service name/port, not a package. If Samba is needed, install only "samba" package which includes all NetBIOS services automatically.`,
                severity: 'critical',
                fix: {
                  action: 'modify',
                  changes: [{
                    type: 'replace',
                    find: new RegExp(`\\s+${invalidPkg}\\s+`, 'g'),
                    replace: ' '
                  }]
                }
              }]
            };
          }
        }
        
        console.log(`✅ Dockerfile COPY syntax validation passed for ${dockerfilePath}`);
        console.log(`✅ Dockerfile package name validation passed for ${dockerfilePath}`);
      } catch (validationError) {
        console.warn(`⚠️  Dockerfile validation error for ${dockerfilePath}:`, validationError.message);
        // Continue with AI validation even if Dockerfile check fails
      }
    }
    
    // Build prompt with file structure and contents
    const userMessage = `Validate this CTF challenge before deployment:

CHALLENGE NAME: ${challengeName}

FILE STRUCTURE:
${fileList}

FILE CONTENTS:
${Object.entries(files).map(([name, content]) => {
  return `=== ${name} ===
${content}
`;
}).join('\n')}

Analyze these files and check for:
1. Dockerfile path mismatches in docker-compose.yml
2. Missing files referenced in docker-compose.yml or Dockerfiles
3. Invalid Docker syntax
4. Any issues that would cause "docker compose up" to fail

Respond ONLY with valid JSON in the exact format specified in the system prompt.`;

    // Call Claude Sonnet 4.5
    console.log('🤖 Analyzing with Claude Sonnet 4.5...');
    if (progressCallback) progressCallback({ step: 'validation-analyze', message: '🤖 AI analyzing deployment configuration...' });
    
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      temperature: 0,
      system: SYSTEM_PROMPT,
      messages: [
        { role: 'user', content: userMessage }
      ]
    });
    
    const responseText = message.content[0].text.trim();
    console.log('📝 Claude response received');
    
    // IMPROVEMENT: Post-process Dockerfiles to fix invalid COPY commands and package names before validation
    for (const dockerfilePath of Object.keys(files).filter(f => f.includes('Dockerfile'))) {
      let dockerfileContent = files[dockerfilePath];
      let modified = false;
      
      // Fix invalid COPY commands with shell syntax
      // Pattern: COPY *.py /usr/local/bin/ 2>/dev/null || true
      // Replace with: RUN cp *.py /usr/local/bin/ 2>/dev/null || true
      const invalidCopyRegex = /^COPY\s+([^\s]+)\s+([^\s]+)\s+(2>|\|\||&&|;)/m;
      if (invalidCopyRegex.test(dockerfileContent)) {
        console.log(`⚠️  Fixing invalid COPY command in ${dockerfilePath}...`);
        dockerfileContent = dockerfileContent.replace(
          /^COPY\s+([^\s]+)\s+([^\s]+)\s+(.*)$/gm,
          (match, source, dest, shellPart) => {
            if (shellPart && (shellPart.includes('2>') || shellPart.includes('||') || shellPart.includes('&&') || shellPart.includes(';'))) {
              modified = true;
              return `RUN cp ${source} ${dest} ${shellPart}`;
            }
            return match;
          }
        );
        
        if (modified) {
          files[dockerfilePath] = dockerfileContent;
          console.log(`✅ Fixed invalid COPY command in ${dockerfilePath}`);
        }
      }
      
      // ✅ FIX: Replace any CentOS (EOL) with Rocky Linux 9
      // CentOS is deprecated and repositories are no longer available - must use Rocky Linux
      if (dockerfileContent.includes('FROM centos')) {
        console.log(`⚠️  Fixing CentOS (EOL) in ${dockerfilePath} - replacing with Rocky Linux 9...`);
        dockerfileContent = dockerfileContent.replace(/FROM centos:\d+/g, 'FROM rockylinux:9');
        dockerfileContent = dockerfileContent.replace(/FROM centos:latest/g, 'FROM rockylinux:9');
        dockerfileContent = dockerfileContent.replace(/FROM centos/g, 'FROM rockylinux:9');
        // Replace yum with dnf (Rocky Linux uses dnf)
        dockerfileContent = dockerfileContent.replace(/RUN yum install/g, 'RUN dnf install');
        dockerfileContent = dockerfileContent.replace(/yum clean all/g, 'dnf clean all');
        dockerfileContent = dockerfileContent.replace(/yum update/g, 'dnf update');
        modified = true;
      }
      
      // ✅ FIX: Add --allowerasing to Rocky Linux dnf install commands that include curl
      // Rocky Linux 9 has curl-minimal by default, which conflicts with curl package
      if (dockerfileContent.includes('FROM rockylinux') && dockerfileContent.includes('dnf install') && dockerfileContent.includes('curl')) {
        if (!dockerfileContent.includes('--allowerasing')) {
          console.log(`⚠️  Adding --allowerasing to Rocky Linux dnf install (curl conflict fix) in ${dockerfilePath}...`);
          // Add --allowerasing after dnf install -y
          dockerfileContent = dockerfileContent.replace(
            /(dnf install -y)(\s+--setopt=install_weak_deps=False)?(\s+[^\n]*curl[^\n]*)/g,
            (match, dnfCmd, setopt, rest) => {
              return `${dnfCmd}${setopt || ''} --allowerasing${rest}`;
            }
          );
          // Also handle cases without --setopt
          dockerfileContent = dockerfileContent.replace(
            /(dnf install -y)(\s+[^\n]*curl[^\n]*)/g,
            (match, dnfCmd, rest) => {
              if (!match.includes('--allowerasing')) {
                return `${dnfCmd} --allowerasing${rest}`;
              }
              return match;
            }
          );
          modified = true;
        }
      }
      
      // ✅ FIX: Replace iputils-ping with iputils for Rocky Linux/RHEL
      // Rocky Linux and RHEL use 'iputils' package, not 'iputils-ping' (Debian/Ubuntu naming)
      if (dockerfileContent.includes('FROM rockylinux') && dockerfileContent.includes('iputils-ping')) {
        console.log(`⚠️  Replacing iputils-ping with iputils for Rocky Linux/RHEL in ${dockerfilePath}...`);
        dockerfileContent = dockerfileContent.replace(/\biputils-ping\b/g, 'iputils');
        modified = true;
      }
      
      // ✅ FIX: Remove xinetd for Rocky Linux/RHEL
      // xinetd is deprecated and not available in Rocky Linux 9 (replaced by systemd)
      if (dockerfileContent.includes('FROM rockylinux') && dockerfileContent.includes('xinetd')) {
        console.log(`⚠️  Removing xinetd for Rocky Linux/RHEL (deprecated, not available) in ${dockerfilePath}...`);
        dockerfileContent = dockerfileContent.replace(/\s+xinetd\s+/g, ' ');
        dockerfileContent = dockerfileContent.replace(/\s+xinetd$/g, '');
        dockerfileContent = dockerfileContent.replace(/^xinetd\s+/g, '');
        modified = true;
      }
      
      // ✅ FIX: Replace 'telnet' with 'busybox-extras' for Alpine Linux Dockerfiles
      if (dockerfileContent.includes('FROM alpine') || dockerfileContent.includes('FROM alpine:')) {
        const telnetRegex = /(\s|^)telnet(\s|$)/g;
        if (telnetRegex.test(dockerfileContent)) {
          console.log(`⚠️  Fixing Alpine telnet package in ${dockerfilePath}...`);
          dockerfileContent = dockerfileContent.replace(/(\s|^)telnet(\s|$)/g, '$1busybox-extras$2');
          modified = true;
        }
      }
      
      // IMPROVEMENT: Remove invalid package names (service names that are not packages)
      const invalidPackages = ['netbios', 'netbios-ns', 'netbios-ssn', 'netbios-dgm', 'cifs', 'smb2', 'smb3'];
      for (const invalidPkg of invalidPackages) {
        // Remove from apt-get install lines
        const pkgRegex = new RegExp(`\\s+${invalidPkg}\\s+`, 'g');
        if (pkgRegex.test(dockerfileContent)) {
          const oldContent = dockerfileContent;
          dockerfileContent = dockerfileContent.replace(pkgRegex, ' ');
          if (dockerfileContent !== oldContent) {
            modified = true;
            console.log(`⚠️  Removing invalid package "${invalidPkg}" from ${dockerfilePath} (it's a service name, not a package)`);
          }
        }
      }
      
      // Save all modifications to the file (both in memory and on disk)
      if (modified) {
        files[dockerfilePath] = dockerfileContent;
        // Write the fixed content back to disk
        const fullPath = path.join(challengePath, dockerfilePath);
        fs.writeFileSync(fullPath, dockerfileContent, 'utf-8');
        console.log(`✅ Applied fixes to ${dockerfilePath} and saved to disk`);
      }
    }
    
    // Parse JSON response
    let validationResult;
    try {
      // Extract JSON from markdown code blocks if present
      let jsonText = responseText;
      const jsonMatch = responseText.match(/```(?:json)?\n?([\s\S]*?)\n?```/);
      if (jsonMatch) {
        jsonText = jsonMatch[1];
      }
      
      // Try to extract JSON object if wrapped in text
      const jsonObjectMatch = jsonText.match(/\{[\s\S]*\}/);
      if (jsonObjectMatch) {
        jsonText = jsonObjectMatch[0];
      }
      
      validationResult = JSON.parse(jsonText);
    } catch (parseError) {
      console.error('❌ Failed to parse Claude response:', parseError.message);
      console.error('Response preview:', responseText.substring(0, 500));
      // Return a safe default that allows deployment to continue
      return {
        success: true,  // Allow deployment even if validation parsing fails
        valid: true,
        issues: [],
        fixes: [],
        summary: 'Validation response parsing failed, but continuing with deployment',
        warning: 'Could not parse validation response: ' + parseError.message
      };
    }
    
    // Check validation results
    if (validationResult.valid && validationResult.canDeploy) {
      console.log('✅ Validation passed - No issues found');
      if (progressCallback) progressCallback({ step: 'validation-pass', message: '✅ Pre-deployment validation passed' });
      
      return {
        success: true,
        valid: true,
        issues: [],
        fixes: [],
        summary: validationResult.summary
      };
    }
    
    // Issues found - apply fixes
    console.log(`⚠️  Found ${validationResult.issues.length} issues`);
    for (const issue of validationResult.issues) {
      console.log(`   [${issue.severity}] ${issue.file}: ${issue.issue}`);
    }
    
    if (validationResult.fixes && validationResult.fixes.length > 0) {
      console.log(`🔧 Applying ${validationResult.fixes.length} fixes...`);
      if (progressCallback) progressCallback({ step: 'validation-fix', message: `🔧 Applying ${validationResult.fixes.length} automatic fixes...` });
      
      const appliedFixes = await applyFixes(challengePath, validationResult.fixes);
      const successfulFixes = appliedFixes.filter(f => f.success).length;
      
      console.log(`✅ Applied ${successfulFixes}/${appliedFixes.length} fixes`);
      if (progressCallback) progressCallback({ step: 'validation-fixed', message: `✅ Applied ${successfulFixes} fixes, ready to deploy` });
      
      return {
        success: true,
        valid: false,
        fixesApplied: true,
        issues: validationResult.issues,
        fixes: appliedFixes,
        summary: `Found ${validationResult.issues.length} issues, applied ${successfulFixes} fixes`,
        canDeployAfterFixes: validationResult.canDeploy
      };
    } else {
      console.log('❌ Issues found but no fixes available');
      if (progressCallback) progressCallback({ step: 'validation-fail', message: '❌ Validation failed, cannot deploy' });
      
      return {
        success: false,
        valid: false,
        issues: validationResult.issues,
        fixes: [],
        summary: validationResult.summary || 'Validation failed with issues',
        canDeploy: false
      };
    }
    
  } catch (error) {
    console.error('❌ Pre-deployment validation error:', error);
    return {
      success: false,
      error: 'Validation failed',
      details: error.message
    };
  }
}

/**
 * Analyze Docker deployment output using Claude to determine if deployment was successful
 */
export async function analyzeDockerOutput(challengeName, dockerOutput, progressCallback = null) {
  console.log(`\n🔍 Post-deployment analysis for: ${challengeName}`);
  
  const DOCKER_ANALYSIS_PROMPT = `You are an expert Docker and DevOps engineer analyzing docker compose deployment output.

Your job is to analyze the output from "docker compose up --build -d" and determine if the deployment was successful or if there were errors.

Common success indicators:
✅ "Built" messages for services
✅ "Created" messages for containers
✅ "Started" messages for containers
✅ No error messages in stderr
✅ Exit code 0

Common failure indicators:
❌ "failed to solve" errors
❌ "no such file or directory" errors
❌ "COPY failed" errors
❌ Build errors (syntax, missing files, etc.)
❌ Network creation failures
❌ Container creation/start failures
❌ Port binding failures (e.g., "port is already allocated")
❌ "chown: invalid user" errors (e.g., "chown: invalid user: 'ftp:ftp'")
❌ Repository errors (e.g., "Cannot find a valid baseurl for repo")
❌ Package manager errors (e.g., "command not found", "unable to locate package")
❌ Non-zero exit code

**CRITICAL: CentOS Repository Errors:**
If you see "Cannot find a valid baseurl for repo" or similar CentOS repository errors:
- CentOS is deprecated (EOL) and repositories are no longer available at the default URLs
- Fix: Replace CentOS with a supported alternative:
  - Option 1: Use Rocky Linux 9 (RHEL-compatible, uses dnf) - RECOMMENDED
  - Option 2: Use Ubuntu 22.04 (Debian-based, uses apt-get)
- Example fix: Change FROM centos:7 (or any CentOS version) to FROM rockylinux:9 and update package manager from yum to dnf
- Also update any CentOS-specific package names to their Rocky/Ubuntu equivalents

**CRITICAL: Package Manager Errors:**
If you see "command not found" for package managers (apt-get, yum, dnf, apk, pacman):
- The base image doesn't have that package manager
- Fix: Change the base image to one that matches the package manager being used
- Example: If Dockerfile uses apt-get but base image is Alpine (uses apk), change base image to Ubuntu/Debian

**CRITICAL: chown USER ERRORS:**
If you see "chown: invalid user: 'ftp:ftp'" or similar:
- The user referenced in chown doesn't exist
- Fix: Create the user BEFORE using it in chown, OR use an existing user
- Example fix for "chown -R ftp:ftp /var/ftp/pub":
  \`\`\`dockerfile
  RUN useradd -r -s /bin/false ftp 2>/dev/null || true && \\
      chown -R ftp:ftp /var/ftp/pub
  \`\`\`
- OR replace with existing user: chown -R ftpuser:ftpuser (if ftpuser exists)

**IMPORTANT:** If you see "port is already allocated" errors, the fix is to REMOVE all port mappings and use private IPs only.
All CTF challenges MUST use isolated private networks with static IP addresses (NO host port mappings).

CRITICAL RESPONSE FORMAT:
You must respond with a JSON object in this EXACT format:

{
  "success": true|false,
  "deploymentStatus": "success|partial|failed",
  "containers": {
    "victim": "running|failed|unknown",
    "attacker": "running|failed|unknown"
  },
  "issues": [
    {
      "type": "build_error|runtime_error|warning",
      "service": "victim|attacker",
      "message": "Brief description",
      "details": "Full error details",
      "severity": "critical|warning|info"
    }
  ],
  "recommendations": [
    "Specific action to fix the issue"
  ],
  "summary": "Brief summary of deployment result"
}

If deployment was successful, return:
{
  "success": true,
  "deploymentStatus": "success",
  "containers": {
    "victim": "running",
    "attacker": "running"
  },
  "issues": [],
  "fixes": [],
  "recommendations": [],
  "summary": "All containers built and started successfully"
}

If there are fixable issues, include a "fixes" array:
{
  "fixes": [
    {
      "file": "docker-compose.yml",
      "action": "modify",
      "changes": [{
        "type": "replace",
        "find": "context: .\\n      dockerfile: Dockerfile",
        "replace": "context: ./victim\\n      dockerfile: Dockerfile"
      }],
      "explanation": "Updated build context to match actual file location"
    },
    {
      "file": "Dockerfile",
      "action": "modify",
      "changes": [{
        "type": "replace",
        "find": "FROM centos",
        "replace": "FROM rockylinux:9"
      }, {
        "type": "replace",
        "find": "RUN yum install",
        "replace": "RUN dnf install"
      }],
      "explanation": "Replaced CentOS (EOL) with Rocky Linux 9 and updated package manager"
    },
    {
      "file": "Dockerfile",
      "action": "create",
      "content": "FROM ubuntu:20.04\\nRUN apt-get update && apt-get install -y vsftpd\\nCOPY flag.txt /root/flag.txt\\nEXPOSE 21\\nCMD [\\\"vsftpd\\\"]",
      "explanation": "Created missing Dockerfile for FTP service"
    }
  ]
}

**CRITICAL:** When creating files (action: "create"), ALWAYS provide complete file "content". Never leave it undefined.

**CRITICAL: CentOS Repository Fix:**
When you see "Cannot find a valid baseurl for repo" or any CentOS repository errors:
- Replace "FROM centos" (any version) with "FROM rockylinux:9" (or "FROM ubuntu:22.04")
- Replace "yum" with "dnf" (for Rocky) or keep "apt-get" (for Ubuntu)
- Update package names if needed (e.g., "httpd" for Rocky, "apache2" for Ubuntu)
- Provide the complete fixed Dockerfile content in the fix`;

  try {
    console.log('🤖 Analyzing Docker output with Claude...');
    if (progressCallback) progressCallback({ step: 'docker-analysis', message: '🤖 Analyzing deployment output...' });
    
    const CLONE_PATH = getClonePath();
    const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
    
    // Gather challenge files for context
    const files = await gatherChallengeFiles(challengePath);
    const fileList = Object.keys(files).join('\n');
    
    const userMessage = `Analyze this Docker deployment output and provide fixes if needed:

CHALLENGE: ${challengeName}

FILE STRUCTURE:
${fileList}

KEY FILE CONTENTS:
${files['docker-compose.yml'] ? `=== docker-compose.yml ===\n${files['docker-compose.yml']}\n\n` : ''}
${Object.entries(files).filter(([name]) => name.includes('Dockerfile')).map(([name, content]) => 
  `=== ${name} ===\n${content}\n`).join('\n')}

DOCKER COMPOSE OUTPUT:
${dockerOutput}

Analyze the output, identify issues, and provide specific fixes. Respond with JSON only.`;

    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      temperature: 0,
      system: DOCKER_ANALYSIS_PROMPT,
      messages: [
        { role: 'user', content: userMessage }
      ]
    });
    
    const responseText = message.content[0].text.trim();
    console.log('📝 Claude analysis received');
    
    // Parse JSON response
    let analysisResult;
    try {
      let jsonText = responseText;
      const jsonMatch = responseText.match(/```json\n([\s\S]*?)\n```/);
      if (jsonMatch) {
        jsonText = jsonMatch[1];
      }
      
      analysisResult = JSON.parse(jsonText);
    } catch (parseError) {
      console.error('❌ Failed to parse Claude response:', responseText);
      return {
        success: false,
        error: 'Failed to parse analysis response',
        details: parseError.message,
        rawResponse: responseText
      };
    }
    
    // Log results
    if (analysisResult.success) {
      console.log('✅ Deployment successful according to Claude analysis');
      if (progressCallback) progressCallback({ step: 'docker-success', message: '✅ Deployment verified successful' });
      
      return {
        success: true,
        analysis: analysisResult,
        deploymentSuccessful: true,
        fixesApplied: false,
        summary: analysisResult.summary
      };
    } else {
      console.log('⚠️ Deployment issues detected:');
      for (const issue of analysisResult.issues || []) {
        console.log(`   [${issue.severity}] ${issue.service}: ${issue.message}`);
      }
      
      // Check if Claude provided fixes
      if (analysisResult.fixes && analysisResult.fixes.length > 0) {
        console.log(`🔧 Applying ${analysisResult.fixes.length} fixes from Claude analysis...`);
        if (progressCallback) progressCallback({ step: 'docker-fix', message: `🔧 Applying ${analysisResult.fixes.length} fixes...` });
        
        const appliedFixes = await applyFixes(challengePath, analysisResult.fixes);
        const successfulFixes = appliedFixes.filter(f => f.success).length;
        
        console.log(`✅ Applied ${successfulFixes}/${appliedFixes.length} fixes`);
        
        return {
          success: true,
          analysis: analysisResult,
          deploymentSuccessful: false,
          fixesApplied: true,
          fixes: appliedFixes,
          summary: `Detected ${analysisResult.issues.length} issues, applied ${successfulFixes} fixes. Ready to retry deployment.`,
          shouldRetry: successfulFixes > 0
        };
      } else {
        // No fixes available
        console.log('❌ Issues found but no automatic fixes available');
        if (progressCallback) progressCallback({ step: 'docker-issues', message: `❌ Detected ${analysisResult.issues?.length || 0} issues, no automatic fixes` });
        
        return {
          success: true,
          analysis: analysisResult,
          deploymentSuccessful: false,
          fixesApplied: false,
          summary: analysisResult.summary,
          shouldRetry: false
        };
      }
    }
    
  } catch (error) {
    console.error('❌ Docker output analysis error:', error);
    return {
      success: false,
      error: 'Analysis failed',
      details: error.message
    };
  }
}

export default {
  validateBeforeDeployment,
  analyzeDockerOutput
};
