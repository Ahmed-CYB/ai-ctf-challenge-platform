import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';
import { normalizeContent, validateContentSchema } from '../../content-schema.js';
import { generateVariationParams, injectVariationsIntoPrompt, generateUniqueFlag } from '../../content-variation-manager.js';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const NETWORK_CONTENT_PROMPT = `You are an expert network security CTF challenge creator. Generate network services and challenges.

🔧 PRIMARY REFERENCE FOR DOCKER CONFIGURATIONS - VULHUB:
- **ALWAYS reference Vulhub** (https://github.com/vulhub/vulhub) for correct service configurations
- Vulhub provides 200+ WORKING Dockerfiles, docker-compose.yml, and service configs that are TESTED and VERIFIED
- **Search Vulhub repository** for relevant examples matching your challenge type (FTP, Samba, SSH, Web, Database, etc.)
- Use Vulhub examples to ensure:
  * Correct configuration file syntax
  * Proper directory structures (/var/ftp/, /srv/samba/, etc.)
  * Working service startup commands
  * Correct file permissions and ownership
  * Proper docker-compose.yml patterns

CRITICAL REQUIREMENTS - NO PLACEHOLDERS:
❌ NEVER use: TODO, FIXME, XXX, [PLACEHOLDER], <REPLACE>, ..., [INSERT], [ADD HERE]
✅ ALWAYS generate COMPLETE, WORKING configurations with real values
✅ Use actual file paths, usernames, passwords, and configuration values
✅ Generate complete file contents - never leave sections empty or marked for later
✅ Reference Vulhub examples to ensure configurations are correct and working

SECURITY REQUIREMENTS - NO REAL SECRETS:
❌ NEVER generate realistic API keys, tokens, or secrets (e.g., sk_live_*, AKIA*, JWT tokens)
❌ NEVER use patterns that match real secret formats (Stripe keys, AWS keys, etc.)
✅ Use simple, fake values like "test_key_12345", "dummy_token", "example_api_key"
✅ For passwords, use simple CTF-style passwords like "admin123", "password", "user"
✅ For keys/tokens, use short, clearly fake values that won't trigger secret scanners

SUPPORTED CHALLENGE TYPES:
1. FTP: Misconfigured FTP servers, anonymous access, weak credentials
   - **CRITICAL for anonymous FTP challenges**: vsftpd.conf MUST include:
     * anonymous_enable=YES (REQUIRED for anonymous access)
     * anon_root=/var/ftp (REQUIRED)
     * no_anon_password=YES (allows empty password)
     * anon_upload_enable=NO (security best practice)
     * anon_mkdir_write_enable=NO (security best practice)
   - If challenge description mentions "anonymous", "anonymous access", or "no authentication", you MUST enable anonymous_enable=YES
2. Samba: Linux SMB/CIFS share enumeration, null sessions, sensitive files (NO Windows SMB support)
3. SSH: Weak passwords, key misconfigurations
4. PCAP Analysis: Network packet captures with hidden data
5. Network Scanning: Port scanning, service enumeration
6. Protocol Exploitation: Telnet, RDP, custom services

IMPORTANT: 
- Use "samba" for Linux SMB shares (NOT "smb" which is Windows-only)
- Windows vulnerabilities are NOT supported - only Linux-based challenges

OUTPUT REQUIREMENTS:
- Generate COMPLETE service configurations with ALL values filled in
- Include realistic misconfigurations with actual configuration values
- Provide complete exploit path with real commands
- PCAP files if needed (generation method with actual commands)
- All file contents must be complete and executable - no placeholders
- Include decoyPorts array in configuration based on difficulty:
  * Easy: [] (no decoy ports)
  * Medium: [25, 53, 1433] or similar (2-3 decoy ports)
  * Hard: [25, 53, 1433, 3306, 5432, 6379, 8080, 8443] or similar (5-8 decoy ports)
- Decoy ports should be common but non-vulnerable services (SMTP, DNS, MSSQL, MySQL, PostgreSQL, Redis, HTTP-alt, HTTPS-alt)

⚠️ CRITICAL - SETUP COMMANDS ARE MANDATORY:
- The "setup" field in configuration is MANDATORY and MUST be provided
- Setup commands are executed at container startup to start services
- Without setup commands, services will NOT start and the challenge will fail
- Setup must include:
  1. Service configuration file copying (if needed)
  2. Service startup commands (e.g., "service vsftpd start" or "/usr/sbin/vsftpd &")
  3. Any initialization scripts or commands needed
- Example setup for FTP (reference Vulhub's FTP configurations):
  "setup": "cp /challenge/vsftpd.conf /etc/vsftpd.conf && mkdir -p /var/run/vsftpd/empty && mkdir -p /var/ftp/data/classified && chmod 555 /var/ftp && chmod 755 /var/ftp/data && chmod 755 /var/ftp/data/classified && cp /challenge/flag.txt /var/ftp/data/classified/flag.txt && chmod 644 /var/ftp/data/classified/flag.txt && chown ftp:ftp /var/ftp/data/classified/flag.txt && service vsftpd start || /usr/sbin/vsftpd &"
  - **Reference Vulhub**: Search Vulhub repository for FTP/vsftpd examples to find correct vsftpd.conf patterns (anonymous_enable=YES, anon_root=/var/ftp, etc.)
  - **Directory structure**: Use /var/ftp/ as root (not /ftp/) - match Vulhub patterns
  - **Permissions**: Root directory must NOT be writable (chmod 555) for chroot to work
- Example setup for Samba:
  "setup": "cp /challenge/smb.conf /etc/samba/smb.conf && service smbd start || /usr/sbin/smbd -D & && service nmbd start || /usr/sbin/nmbd -D &"
- Setup commands must be executable shell commands that start the service
- Use "service <name> start" for systemd-based systems, or direct binary execution with "&" for background

Return JSON:
{
  "files": [
    {
      "name": "vsftpd.conf",
      "path": "",
      "content": "<complete FTP config>"
    },
    {
      "name": "flag.txt",
      "path": "data",
      "content": "CTF{flag}"
    },
    {
      "name": "traffic.pcap",
      "path": "",
      "content": "<pcap generation method>"
    }
  ],
  "flag": "CTF{actual_flag}",
  "configuration": {
    "serviceType": "ftp|samba|ssh|pcap",
    "misconfiguration": "description of weakness",
    "exploitPath": "how to exploit",
    "tools": ["nmap", "wireshark", "ftp"],
    "servicePort": 21,
    "setup": "service setup commands",
    "decoyPorts": [25, 53, 1433]
  }
}`;

/**
 * Generate network service challenge content
 */
export async function generateNetworkContent({ machineName, services, scenario, dependencies }) {
  // IMPROVEMENT: Check cache first
  try {
    const { getCachedContent } = await import('../../content-cache.js');
    const cached = await getCachedContent('network', scenario);
    if (cached) {
      console.log('✅ Using cached network content');
      return cached;
    }
  } catch (cacheError) {
    console.warn('⚠️  Cache check failed:', cacheError.message);
  }

  // IMPROVEMENT: Retry logic - try AI generation up to 3 times before using fallback
  const maxRetries = 3;
  let lastError = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🤖 AI generation attempt ${attempt}/${maxRetries} for network content...`);
      // IMPROVEMENT: Enhanced scenario context utilization
      const scenarioContext = {
      title: scenario.title || 'Network Challenge',
      description: scenario.description || '',
      difficulty: scenario.difficulty || 'medium',
      learningObjectives: scenario.learningObjectives || [],
      complexity: scenario.complexity || 'intermediate',
      tags: scenario.tags || []
    };

    // IMPROVEMENT: Generate variation parameters for uniqueness
    const variations = generateVariationParams('network', scenario);
    
    const basePrompt = `Create a network security challenge for this scenario:

Scenario: ${scenarioContext.title}
Machine: ${machineName}
Services: ${services.join(', ')}
Context: ${scenarioContext.description}
Difficulty: ${scenarioContext.difficulty}
Complexity: ${scenarioContext.complexity}
Learning Objectives: ${scenarioContext.learningObjectives.join(', ') || 'Network security fundamentals'}
Tags: ${scenarioContext.tags.join(', ') || 'network, security'}
Dependencies: ${dependencies.join('; ')}

Generate complete service configurations with realistic misconfigurations and embedded flag that:
- Matches the difficulty level (${scenarioContext.difficulty})
- Teaches the specified learning objectives
- Is realistic and exploitable
- Includes appropriate hints without revealing the solution
- Is UNIQUE and different from previous challenges`;

    // IMPROVEMENT: Inject variations into prompt
    const prompt = injectVariationsIntoPrompt(basePrompt, variations);

    // IMPROVEMENT: Variable temperature for uniqueness (0.7-0.9)
    const temperature = 0.7 + (Math.random() * 0.2);
    
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 16000, // IMPROVEMENT: Increased to handle larger responses
      temperature: temperature, // IMPROVEMENT: Variable for uniqueness
      system: NETWORK_CONTENT_PROMPT + `\n\nCRITICAL: Generate UNIQUE content that differs from previous challenges. Use creative variations in service configurations, misconfigurations, and scenario details. IMPORTANT: Always provide COMPLETE, valid JSON. Do not truncate or use placeholders.${attempt > 1 ? '\n\n⚠️ PREVIOUS ATTEMPT FAILED: The previous generation contained placeholders or incomplete content. You MUST generate COMPLETE, working configurations with ALL values filled in. NO TODO, FIXME, XXX, [PLACEHOLDER], or any incomplete sections allowed.' : ''}`,
      messages: [{
        role: 'user',
        content: prompt
      }]
    });

    let responseText = response.content[0].text;
    
    // IMPROVEMENT: Check if response was truncated and request continuation if needed
    if (response.stop_reason === 'max_tokens') {
      console.warn('⚠️  Response was truncated, requesting continuation...');
      const continuation = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 8000,
        temperature: temperature,
        messages: [{
          role: 'user',
          content: `Continue the JSON response from where it was cut off. Complete the JSON object properly:\n\n${responseText.substring(responseText.lastIndexOf('{'))}`
        }]
      });
      responseText += continuation.content[0].text;
    }
    
    // Try multiple JSON extraction strategies
    let content;
    try {
      // Strategy 1: Find JSON between code blocks (greedy to get full content)
      const codeBlockMatch = responseText.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (codeBlockMatch) {
        content = JSON.parse(codeBlockMatch[1].trim());
      } else {
        // Strategy 2: Find first complete JSON object from start to balanced closing brace
        const jsonStart = responseText.indexOf('{');
        if (jsonStart === -1) {
          throw new Error('No JSON object found in response');
        }
        
        // Find matching closing brace by counting braces (handle strings properly)
        let braceCount = 0;
        let jsonEnd = -1;
        let inString = false;
        let escapeNext = false;
        
        for (let i = jsonStart; i < responseText.length; i++) {
          const char = responseText[i];
          
          if (escapeNext) {
            escapeNext = false;
            continue;
          }
          
          if (char === '\\') {
            escapeNext = true;
            continue;
          }
          
          if (char === '"' && !escapeNext) {
            inString = !inString;
            continue;
          }
          
          if (!inString) {
            if (char === '{') braceCount++;
            if (char === '}') {
              braceCount--;
              if (braceCount === 0) {
                jsonEnd = i + 1;
                break;
              }
            }
          }
        }
        
        if (jsonEnd === -1) {
          // Try to find the last closing brace as fallback
          const lastBrace = responseText.lastIndexOf('}');
          if (lastBrace > jsonStart) {
            console.warn('⚠️  Using last closing brace as fallback');
            jsonEnd = lastBrace + 1;
          } else {
            throw new Error('Incomplete JSON object in response');
          }
        }
        
        const jsonString = responseText.substring(jsonStart, jsonEnd);
        content = JSON.parse(jsonString);
      }
    } catch (parseError) {
      console.error('❌ JSON parsing failed:', parseError.message);
      console.error('Response preview:', responseText.substring(0, 2000));
      throw new Error(`Invalid JSON from network agent: ${parseError.message}`);
    }

    // IMPROVEMENT: Normalize and validate schema
    content = normalizeContent(content);
    const schemaValidation = validateContentSchema(content);
    if (!schemaValidation.valid) {
      console.warn('⚠️  Schema validation issues:', schemaValidation.issues);
      
      // ✅ CRITICAL: Setup commands are MANDATORY - throw error to trigger retry
      if (schemaValidation.issues.some(issue => issue.includes('setup'))) {
        throw new Error(`MANDATORY setup commands missing in configuration. The setup field must contain service startup commands that will be executed at container startup. Example: "setup": "cp /challenge/config.conf /etc/service.conf && service servicename start || /usr/sbin/servicename &"`);
      }
      
      // Fix common issues (non-critical)
      if (!content.configuration.difficulty) {
        content.configuration.difficulty = 'medium';
      }
      if (!content.configuration.tools) {
        content.configuration.tools = [];
      }
    }

    // Validate content
    if (!content.files || content.files.length === 0) {
      throw new Error('Network content must include files');
    }

    // IMPROVEMENT: Generate unique flag with variations
    if (!content.flag || !/^CTF\{[a-zA-Z0-9_\-]{10,}\}$/.test(content.flag)) {
      content.flag = generateUniqueFlag('network', scenario, variations);
    }

    // IMPROVEMENT: Validate content quality
    try {
      const { validateContentQuality } = await import('../../content-quality-validator.js');
      const qualityCheck = await validateContentQuality(content, 'network');
      
      if (!qualityCheck.valid) {
        console.warn('⚠️  Content quality issues:', qualityCheck.issues);
        throw new Error(`Content quality validation failed: ${qualityCheck.issues.join(', ')}`);
      }
      
      if (qualityCheck.warnings.length > 0) {
        console.warn('⚠️  Content quality warnings:', qualityCheck.warnings);
      }
      
      console.log(`✅ Generated network content: ${content.files.length} files (quality: ${(qualityCheck.overallScore * 100).toFixed(1)}%)`);
      
      // IMPROVEMENT: Cache high-quality content
      if (qualityCheck.overallScore >= 0.7) {
        try {
          const { saveToCache } = await import('../../content-cache.js');
          await saveToCache('network', scenario, content, qualityCheck.overallScore);
        } catch (cacheError) {
          console.warn('⚠️  Failed to cache content:', cacheError.message);
        }
      }
    } catch (qualityError) {
      console.warn('⚠️  Quality validation failed:', qualityError.message);
      // Continue anyway if validation fails
    }

    // IMPROVEMENT: Validate no obvious placeholders (smarter check - only in file content, not filenames)
    // Only check file content, not filenames (filenames may legitimately contain words like "TODO")
    for (const file of content.files) {
      const fileContent = file.content || '';
      
      // IMPROVEMENT: More precise placeholder patterns - only flag actual placeholders, not legitimate content
      const placeholderPatterns = [
        // Explicit placeholder markers (high confidence)
        /\[PLACEHOLDER[^\]]*\]/i,  // [PLACEHOLDER] or [PLACEHOLDER: ...]
        /<REPLACE[^>]*>/i,          // <REPLACE> or <REPLACE: ...>
        /\[INSERT[^\]]*HERE[^\]]*\]/i,  // [INSERT HERE] or [INSERT ... HERE]
        /\[ADD[^\]]*HERE[^\]]*\]/i,     // [ADD HERE] or [ADD ... HERE]
        /\[FILL[^\]]*IN[^\]]*\]/i,      // [FILL IN] or [FILL ... IN]
        /\[\.\.\.\]/i,                   // [...]
        
        // TODO/FIXME/XXX only if they appear to be actual placeholders (not in comments or legitimate text)
        // Check for TODO: at start of line or after whitespace, followed by action words
        /(?:^|\s)(?:TODO|FIXME|XXX):\s*(?:ADD|INSERT|REPLACE|FILL|IMPLEMENT|COMPLETE)/i,
        
        // Three dots patterns - only flag if they appear to be placeholders (not in log files or legitimate ellipsis)
        // Only flag if ... appears alone on a line or followed by placeholder-like text
        /^\s*\.\.\.\s*$/m,  // ... alone on a line
        /\.\.\.\s*\[(?:PLACEHOLDER|INSERT|ADD|FILL)/i  // ... followed by placeholder marker
      ];
      
      // IMPROVEMENT: Skip placeholder check for log files and certain file types that may legitimately contain these patterns
      const skipPlaceholderCheck = /\.(log|txt|conf|config|ini|json|xml)$/i.test(file.name) && 
                                   (fileContent.length > 1000 || fileContent.split('\n').length > 20);
      
      if (!skipPlaceholderCheck) {
        for (const pattern of placeholderPatterns) {
          if (pattern.test(fileContent)) {
            console.warn(`⚠️  Placeholder detected in ${file.name}: ${pattern}`);
            throw new Error(`Placeholder detected in ${file.name}`);
          }
        }
      } else {
        // For log/config files, only check for explicit placeholder markers, not TODO or ...
        const strictPlaceholderPatterns = [
          /\[PLACEHOLDER[^\]]*\]/i,
          /<REPLACE[^>]*>/i,
          /\[INSERT[^\]]*HERE[^\]]*\]/i,
          /\[ADD[^\]]*HERE[^\]]*\]/i,
          /\[FILL[^\]]*IN[^\]]*\]/i
        ];
        
        for (const pattern of strictPlaceholderPatterns) {
          if (pattern.test(fileContent)) {
            console.warn(`⚠️  Placeholder detected in ${file.name}: ${pattern}`);
            throw new Error(`Placeholder detected in ${file.name}`);
          }
        }
      }
    }

      console.log(`✅ Successfully generated network content on attempt ${attempt}`);
      return content;

    } catch (error) {
      console.error(`❌ Network content generation attempt ${attempt} failed:`, error.message);
      lastError = error;
      
      // If this is not the last attempt, continue to retry
      if (attempt < maxRetries) {
        console.log(`🔄 Retrying AI generation... (${attempt + 1}/${maxRetries})`);
        // Small delay before retry to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }
    }
  }

  // All retries failed - only use fallback as absolute last resort
  console.error('❌ All AI generation attempts failed. Using fallback as last resort.');
  console.error('Last error:', lastError?.message);
  
  const { getFallbackContent } = await import('../../content-fallback-manager.js');
  const difficulty = scenario.difficulty || 'easy';
  console.log(`⚠️  Using fallback content for network (${difficulty}) - this should be rare`);
  return getFallbackContent('network', difficulty, scenario);
}

/**
 * Fallback network content if AI generation fails
 */
function generateFallbackNetworkContent() {
  const flag = `CTF{network_${generateRandomString(12)}}`;

  const ftpConfig = `# vsftpd configuration
listen=YES
listen_ipv6=NO
anonymous_enable=YES
anon_upload_enable=NO
anon_mkdir_write_enable=NO
anon_root=/var/ftp
no_anon_password=YES
write_enable=YES
local_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
pasv_enable=YES
pasv_min_port=21100
pasv_max_port=21110
userlist_enable=NO`;

  const startupScript = `#!/bin/bash
# FTP Server Startup Script

# Create FTP directory structure
mkdir -p /var/ftp/data/classified /var/run/vsftpd/empty

# Set permissions (root must NOT be writable for chroot)
chmod 555 /var/ftp
chmod 755 /var/ftp/data
chmod 755 /var/ftp/data/classified

# Place flag in classified directory
echo "${flag}" > /var/ftp/data/classified/flag.txt
chmod 644 /var/ftp/data/classified/flag.txt
chown ftp:ftp /var/ftp/data/classified/flag.txt

# Copy vsftpd config if it exists
if [ -f /challenge/vsftpd.conf ]; then
  cp /challenge/vsftpd.conf /etc/vsftpd.conf
fi

# Start vsftpd
service vsftpd start || /usr/sbin/vsftpd &

# Keep container running
wait`;

  return {
    files: [
      {
        name: 'vsftpd.conf',
        path: '',
        content: ftpConfig
      },
      {
        name: 'start.sh',
        path: '',
        content: startupScript
      },
      {
        name: 'README.txt',
        path: '',
        content: `FTP Challenge

An FTP server is running on this machine with anonymous access enabled.

Objectives:
1. Connect to the FTP server anonymously
2. List available directories
3. Navigate to find sensitive files
4. Download and read the flag

Tools to use:
- nmap: Scan for FTP service
- ftp: Connect to FTP server
- wget/curl: Download files`
      }
    ],
    flag: flag,
    configuration: {
      serviceType: 'ftp',
      misconfiguration: 'Anonymous FTP access enabled with sensitive files',
      exploitPath: 'Connect via anonymous FTP and navigate to /data directory',
      tools: ['nmap', 'ftp', 'wget'],
      servicePort: 21,
      setup: `cp /challenge/vsftpd.conf /etc/vsftpd.conf && mkdir -p /var/run/vsftpd/empty && mkdir -p /var/ftp/data/classified && cp /challenge/flag.txt /var/ftp/data/classified/flag.txt && chmod 644 /var/ftp/data/classified/flag.txt && chown ftp:ftp /var/ftp/data/classified/flag.txt && service vsftpd start || /usr/sbin/vsftpd &`,
      decoyPorts: [] // No decoys for fallback (easy difficulty)
    }
  };
}

/**
 * Generate random string
 */
function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
