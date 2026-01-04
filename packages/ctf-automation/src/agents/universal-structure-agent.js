import Anthropic from '@anthropic-ai/sdk';
import crypto from 'crypto';
import { gitManager } from '../git-manager.js';
import { generateAttackerDockerfile, generateDockerCompose } from '../attacker-image-generator.js';
import { generateToolInstallationDockerfile, generateVictimDockerfileWithSSH } from './tool-installation-agent.js';
import { subnetAllocator } from '../subnet-allocator.js';
import { checkpointManager } from '../checkpoint-manager.js';
import { getValidatedOSImages, isValidOSImage, getOSImageInfo } from '../os-image-validator.js';
import dotenv from 'dotenv';

dotenv.config();

// Validate API key is set
if (!process.env.ANTHROPIC_API_KEY) {
  console.error('❌ ANTHROPIC_API_KEY is not set!');
  console.error('   Please create a .env file in the project root with:');
  console.error('   ANTHROPIC_API_KEY=your_api_key_here');
  console.error('   See API_KEY_SETUP.md for details.');
}

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

/**
 * Package name mappings for Kali Linux
 * Maps common package names to their correct Kali equivalents
 */
const PACKAGE_ALIASES = {
  'mysql-server': 'mariadb-server',
  'mysql-client': 'mariadb-client',
  'mysql': 'mariadb-server',
  'rdp': 'xrdp',
  'web-server': 'apache2',
  'http-server': 'apache2',
  'database': 'mariadb-server',
  'db-server': 'mariadb-server',
  'postgresql': 'postgresql postgresql-contrib',
  'postgres': 'postgresql postgresql-contrib',
  'volatility': 'volatility3',
  'ruby-dev': 'ruby ruby-dev',
  'nodejs': 'nodejs npm'
};

/**
 * Resolve package name to correct Kali package
 */
function resolvePackageName(packageName) {
  const normalized = packageName.toLowerCase().trim();
  return PACKAGE_ALIASES[normalized] || packageName;
}

/**
 * Fix package names in apt install command
 */
function fixAptPackages(aptCommand) {
  // Extract package names from apt-get install command
  const match = aptCommand.match(/apt-get install.*?(?:-y)?(?:--no-install-recommends)?\s+(.+?)(?:\s*&&|\s*$)/);
  if (!match) return aptCommand;
  
  const packages = match[1].split(/\s+/).filter(p => p && !p.startsWith('-'));
  const fixedPackages = packages.map(pkg => resolvePackageName(pkg)).join(' ');
  
  return aptCommand.replace(match[1], fixedPackages);
}

const SCENARIO_ANALYSIS_PROMPT = `You are an expert CTF scenario planner. Analyze user requests and plan multi-machine CTF challenges.

PLATFORM RESTRICTIONS (CRITICAL):
- **ONLY support these challenge types:**
  1. Network Security (FTP, SSH, Samba (Linux SMB), Telnet, network protocols)
  2. Cryptography (encryption, encoding, hashing, ciphers)
  3. Simple Web CTFs (SQL injection, XSS, basic web vulnerabilities)
- **DO NOT create:** Forensics, Reverse Engineering, Binary Exploitation, Pwnable, Windows vulnerabilities, or complex multi-stage challenges
- **NO Windows support:** Use "samba" for Linux SMB shares, NOT "smb" (Windows-only)
- If user requests unsupported types, set needsUserConfirmation=true with a message explaining the restriction

CRITICAL RULES:
1. **FOLLOW USER REQUEST EXACTLY** - Don't add extra machines or complexity
   - If user says "FTP with encrypted flag" = 1 victim machine (FTP server) + 1 attacker
   - Do NOT add "internal networks", "lateral movement", or "multi-stage" unless EXPLICITLY requested
   - Keep it simple and match what the user asked for
2. Maximum 5 machines per scenario (including attacker)
3. Each machine must have a clear purpose
4. Identify all categories involved - **ONLY use: crypto, web, network** (no forensics, pwn, etc.)
5. Plan dependencies between machines ONLY if user implied them
6. **Set needsUserConfirmation to false** unless the request is extremely complex, ambiguous, or requests unsupported types
   - Most requests should proceed directly to creation
   - Only set to true if the request genuinely needs clarification (e.g., conflicting requirements) or requests unsupported challenge types

**MULTI-OS DETECTION:**
- If user requests "multiple OS", "different operating systems", "multiple machines", or similar:
  - Create multiple victim machines with DIFFERENT OS types
  - Use only validated/tested Docker OS images (system validates automatically)
  - Each machine can be configured with open ports and vulnerabilities as needed
  - Mix different package managers for variety (apt-get, apk, dnf/yum)

**CRITICAL: SERVICES vs TOOLS (IMPORTANT DISTINCTION):**
- **SERVICES** (for victim machines): Actual network services that run on the machine:
  - ssh, ftp, samba (Linux SMB - NOT Windows smb), http, https, telnet, dns, ldap, snmp, nfs, mysql, postgresql, redis, etc.
  - These are services that LISTEN on ports and provide functionality
- **TOOLS** (for attacker machines ONLY): Network scanning/analysis tools:
  - nmap, netcat, ping, traceroute, tcpdump, wireshark, masscan, hping3, etc.
  - These are tools used to SCAN/ATTACK, NOT services to run on victims
- **NEVER** put tools (nmap, netcat, ping, traceroute) in victim machine "services" array
- **ONLY** put actual network services (ssh, ftp, samba, http) in victim machine "services" array
- **NO Windows services:** Use "samba" for Linux SMB shares, NOT "smb" (Windows-only)

Return JSON format:
{
  "machineCount": <number>,
  "needsUserConfirmation": <boolean> (usually false),
  "confirmationReason": "<reason if needed, empty string if false>",
  "machines": [
    {
      "name": "machine-name",
      "type": "victim|attacker",
      "role": "description of purpose",
      "services": ["service1", "service2"],  // ONLY actual services (ssh, ftp, smb, http) - NOT tools!
      "contains": ["what content this machine holds"],
      "categories": ["crypto", "web", etc.]
    }
  ],
  "dependencies": [
    "Machine A contains files from Machine B",
    "Challenge requires completing step X before Y"
  ],
  "categories": ["list of all categories"],
  "scenario": {
    "title": "Scenario title",
    "description": "Brief scenario description",
    "stages": ["Stage 1 description", "Stage 2", etc.]
  }
}`;

/**
 * Universal Structure Agent - Orchestrates all CTF challenge creation
 * Handles multi-machine scenarios, coordinates content agents, ensures structural consistency
 */
export async function createUniversalChallenge(userMessage, conversationHistory = [], progressCallback = null, classification = {}) {
  // Store original user message for multi-OS detection
  const originalUserMessage = userMessage.toLowerCase();
  // Check API key before proceeding
  if (!process.env.ANTHROPIC_API_KEY) {
    const errorMsg = 'ANTHROPIC_API_KEY is not set. Please create a .env file in the project root with your API key. See API_KEY_SETUP.md for details.';
    console.error('❌', errorMsg);
    return {
      success: false,
      message: errorMsg,
      error: 'API_KEY_MISSING'
    };
  }

  // ===== PHASE 0: VALIDATE CHALLENGE TYPE (BEFORE ANALYSIS) =====
  // PLATFORM RESTRICTION: Only support Network, Crypto, and Simple Web CTFs
  const SUPPORTED_TYPES = ['network', 'crypto', 'web'];
  const SUPPORTED_TYPE_ALIASES = {
    'network': ['network', 'networking', 'network security', 'ftp', 'ssh', 'smb', 'samba', 'telnet', 'tcp', 'udp'],
    'crypto': ['crypto', 'cryptography', 'encryption', 'encoding', 'hashing', 'cipher', 'rsa', 'aes'],
    'web': ['web', 'web exploitation', 'web security', 'sql injection', 'xss', 'csrf', 'http', 'api']
  };
  
  const UNSUPPORTED_TYPES = ['forensics', 'forensic', 'reverse engineering', 'reversing', 'pwn', 'pwnable', 'binary', 'exploitation'];
  
  // Check if user requested an unsupported type
  const messageLower = userMessage.toLowerCase();
  
  // First, check if classification already detected a supported type
  const detectedType = classification.challengeType?.toLowerCase();
  const detectedTypes = classification.challengeTypes?.map(t => t.toLowerCase()) || (detectedType ? [detectedType] : []);
  const isSupportedByClassification = detectedTypes.length > 0 && detectedTypes.some(type => {
    return SUPPORTED_TYPES.includes(type) ||
           Object.values(SUPPORTED_TYPE_ALIASES).some(aliases => aliases.includes(type));
  });
  
  // Check for supported keywords in message
  const hasSupportedKeyword = Object.entries(SUPPORTED_TYPE_ALIASES).some(([supportedType, aliases]) =>
    aliases.some(alias => messageLower.includes(alias))
  );
  
  // Debug logging
  console.log(`🔍 Universal Agent Validation:`);
  console.log(`   Detected Type: ${detectedType}`);
  console.log(`   Detected Types: ${detectedTypes.join(', ')}`);
  console.log(`   Is Supported by Classification: ${isSupportedByClassification}`);
  console.log(`   Has Supported Keyword: ${hasSupportedKeyword}`);
  
  // Only check for unsupported keywords if classification didn't detect a supported type AND no supported keywords found
  // If classification says it's supported, trust it and proceed
  if (isSupportedByClassification || hasSupportedKeyword) {
    console.log('✅ Challenge type is supported, proceeding with creation...');
    // Continue to challenge creation - don't check for unsupported types
  } else {
    // Only check for unsupported keywords if we're not sure it's supported
    const requestedUnsupported = UNSUPPORTED_TYPES.some(type => messageLower.includes(type));
    
    if (requestedUnsupported) {
      const unsupportedType = UNSUPPORTED_TYPES.find(type => messageLower.includes(type));
      const clarificationQuestion = `❌ **Challenge Type Not Supported**

I'm sorry, but this platform currently supports only the following challenge types:

✅ **Supported Types:**
1. **Network Security** - FTP, SSH, SMB, Telnet, and other network protocols
2. **Cryptography** - Encryption, encoding, hashing, ciphers
3. **Simple Web CTFs** - SQL injection, XSS, basic web vulnerabilities

❌ **Not Supported:**
- Forensics challenges
- Reverse engineering / Binary exploitation
- Pwnable challenges
- Complex multi-stage challenges

**What you can do:**
- Request a network security challenge (e.g., "FTP misconfiguration", "SSH brute force")
- Request a cryptography challenge (e.g., "Caesar cipher", "RSA encryption")
- Request a simple web challenge (e.g., "SQL injection", "XSS vulnerability")

**Example requests:**
- "Create a medium difficulty network security challenge with FTP"
- "Create a crypto challenge with base64 encoding"
- "Create a simple web challenge with SQL injection"

Would you like to create a challenge from one of the supported types? 🚀`;

      return {
        needsUserInput: true,
        question: clarificationQuestion
      };
    }
  }
  
  // ===== PHASE 0.5: CHECK IF REQUEST IS TOO VAGUE (BEFORE ANALYSIS) =====
  // IMPROVEMENT: Check if request needs clarification BEFORE doing expensive analysis
  const vaguePatterns = [
    /^create\s+(ctf\s+)?challenge$/i,
    /^create\s+challenge$/i,
    /^make\s+(a\s+)?challenge$/i,
    /^generate\s+(a\s+)?challenge$/i
  ];
  
  const isVague = vaguePatterns.some(pattern => pattern.test(userMessage.trim())) ||
                  userMessage.trim().length < 20; // Very short messages are likely vague
  
  // Reuse variables already declared above (detectedType, detectedTypes, hasSupportedKeyword, isSupportedByClassification)
  
  // Check if any detected type is supported (enhanced check)
  const isSupportedType = isSupportedByClassification || 
    (detectedTypes.length > 0 && detectedTypes.some(type => {
      return SUPPORTED_TYPES.includes(type) ||
             Object.values(SUPPORTED_TYPE_ALIASES).some(aliases => aliases.includes(type)) ||
             // Also check if the type matches any alias (e.g., 'ftp' matches 'network')
             Object.entries(SUPPORTED_TYPE_ALIASES).some(([supportedType, aliases]) => 
               aliases.some(alias => type.includes(alias) || alias.includes(type))
             );
    }));
  
  // If we have a supported type OR supported keywords in the message, proceed
  const shouldProceed = isSupportedType || hasSupportedKeyword;
  
  // Only ask for clarification if:
  // 1. Message is vague AND no supported type/keyword detected, OR
  // 2. No detected type AND no supported keywords in message
  if ((isVague && !shouldProceed) || (!detectedType && !hasSupportedKeyword)) {
    // Ask for clarification BEFORE doing any analysis
    const clarificationQuestion = `❓ **I'd like to create the perfect challenge for you, but I need a bit more information:**

To create the perfect CTF challenge for you, please tell me:

1. **Challenge Type:** What category are you interested in?
   - **Network Security** (FTP, SSH, SMB, Telnet, etc.)
   - **Cryptography** (encryption, encoding, hashing, ciphers)
   - **Simple Web CTFs** (SQL injection, XSS, basic web vulnerabilities)

2. **Difficulty Level:** 
   - Easy (beginner-friendly)
   - Medium (intermediate)
   - Hard (advanced)

3. **Specific Requirements (optional):**
   - Any particular vulnerability or technique you want to focus on?
   - Any specific tools or services you want to include?

**Example:** "Create a medium difficulty network security challenge with FTP misconfiguration"

Once you provide these details, I'll create a customized challenge for you! 🚀`;

    return {
      needsUserInput: true,
      question: clarificationQuestion
    };
  }

  const maxRetries = 2;
  let lastError = null;
  let challengeName = null; // Declare outside try block for error cleanup

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      progressCallback?.({ step: 'init', message: `🎯 Analyzing CTF scenario (attempt ${attempt}/${maxRetries})...` });

      // ===== PHASE 1: SCENARIO ANALYSIS =====
      let analysisPrompt = `Analyze this CTF challenge request and plan the machine architecture:

User Request: "${userMessage}"

Detected Categories: ${classification.challengeType || 'not specified'}
Required Tools: ${classification.requiredTools?.join(', ') || 'none'}

Plan a complete CTF scenario with appropriate machines.`;

      if (attempt > 1 && lastError) {
        analysisPrompt += `\n\n⚠️ PREVIOUS ATTEMPT FAILED: ${lastError}
Please generate valid, complete content with no placeholders.`;
        
        // ✅ IMPROVEMENT: If error is about missing setup, add specific guidance
        if (lastError.includes('setup') || lastError.includes('setup commands')) {
          analysisPrompt += `\n\n🔴 CRITICAL: The previous attempt failed because setup commands were missing. 
The "setup" field in configuration is MANDATORY and must contain service startup commands.
Example: "setup": "cp /challenge/config.conf /etc/service.conf && service servicename start || /usr/sbin/servicename &"
Make sure ALL content agents generate setup commands in their configuration.setup field.`;
        }
      }

      // IMPROVEMENT: Add randomness to temperature for variation
      // Higher temperature = more creative/varied responses
      const temperature = 0.7 + (Math.random() * 0.2); // 0.7-0.9 for variation
      
      // ✅ CRITICAL: Get existing challenges to avoid duplicates
      const existingChallenges = await gitManager.listChallenges();
      const existingTitles = existingChallenges.map(name => {
        // Convert challenge names back to readable titles for context
        return name.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
      });
      
      let uniquenessContext = '';
      if (existingChallenges.length > 0) {
        uniquenessContext = `\n\n⚠️ CRITICAL: The following challenges already exist (DO NOT reuse these titles or create similar ones):\n${existingChallenges.slice(0, 10).map((name, idx) => `  ${idx + 1}. ${name}`).join('\n')}\n\nYou MUST generate a COMPLETELY NEW and UNIQUE scenario title that is different from all existing challenges. Use creative variations, different contexts, or different vulnerability focuses.`;
      }
      
      const analysisResponse = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4000,
        temperature: temperature, // IMPROVEMENT: Variable temperature for uniqueness
        system: SCENARIO_ANALYSIS_PROMPT + '\n\nIMPORTANT: Generate a UNIQUE scenario that differs from previous challenges. Use creative variations in scenario details, machine configurations, and vulnerability implementations.',
        messages: [{
          role: 'user',
          content: analysisPrompt + uniquenessContext + '\n\nGenerate a COMPLETELY NEW and UNIQUE challenge scenario with creative variations. The scenario title MUST be different from any existing challenges. Use different contexts, different company names, different vulnerability focuses, or different attack scenarios.'
        }]
      });

      const analysisText = analysisResponse.content[0].text;
      const analysisMatch = analysisText.match(/\{[\s\S]*\}/);
      if (!analysisMatch) {
        throw new Error('Failed to extract scenario analysis JSON');
      }

      const scenarioPlan = JSON.parse(analysisMatch[0]);
      console.log('📋 Scenario Plan:', JSON.stringify(scenarioPlan, null, 2));

      // ===== VALIDATE SCENARIO PLAN CATEGORIES =====
      // PLATFORM RESTRICTION: Ensure all categories in the plan are supported
      const planCategories = scenarioPlan.categories || [];
      const unsupportedCategories = planCategories.filter(cat => {
        const catLower = cat.toLowerCase();
        const isSupported = SUPPORTED_TYPES.some(supported => 
          catLower === supported || 
          SUPPORTED_TYPE_ALIASES[supported]?.some(alias => catLower.includes(alias))
        );
        return !isSupported;
      });
      
      if (unsupportedCategories.length > 0) {
        return {
          needsUserInput: true,
          question: `❌ **Unsupported Challenge Categories Detected**

The scenario plan includes categories that are not supported by this platform:
${unsupportedCategories.map(cat => `- ${cat}`).join('\n')}

**Supported Categories:**
- Network Security
- Cryptography  
- Simple Web CTFs

Please modify your request to focus on one of the supported categories, or I can suggest a similar challenge using supported types.

**Example:** Instead of a forensics challenge, I could create a network security challenge with file transfer protocols, or a crypto challenge with encoding/decoding.

Would you like me to suggest an alternative using supported challenge types? 🚀`
        };
      }

      // Note: Checkpoint will be saved after challenge name is determined in Phase 2

      // Check machine count limit
      if (scenarioPlan.machineCount > 5) {
        return {
          needsUserInput: true,
          question: `This scenario requires ${scenarioPlan.machineCount} machines, but the system supports a maximum of 5 machines.\n\nOptions:\n1. Simplify to 5 machines (combine some services)\n2. Split into multiple separate challenges\n\nPlease reply with option 1 or 2.`
        };
      }

      // Only check needsUserConfirmation if it's a complex scenario that needs approval
      // For most cases, proceed with creation
      if (scenarioPlan.needsUserConfirmation && scenarioPlan.confirmationReason) {
        return {
          needsUserInput: true,
          question: scenarioPlan.confirmationReason
        };
      }

      progressCallback?.({ step: 'scenario-planned', message: `✅ Scenario: ${scenarioPlan.scenario.title} (${scenarioPlan.machineCount} machines)` });

      // ===== PHASE 2: ALLOCATE NETWORK RESOURCES =====
      // Generate unique challenge name by checking existing challenges in GitHub
      progressCallback?.({ step: 'name-check', message: '🔍 Checking for name uniqueness...' });
      challengeName = await gitManager.generateUniqueChallengeName(scenarioPlan.scenario.title);
      progressCallback?.({ step: 'name-ready', message: `✅ Challenge name: ${challengeName}` });
      
      // IMPROVEMENT: Save checkpoint after challenge name is determined
      await checkpointManager.saveCheckpoint(challengeName, 'scenario-analysis', {
        scenarioPlan,
        challengeName,
        timestamp: Date.now()
      });

      const subnet = await subnetAllocator.allocateSubnet(challengeName, 'default');
      
      // Assign IPs to machines using subnet allocator IPs
      const machineIPs = {};
      let victimCounter = 0;
      const baseIP = subnet.subnet.split('/')[0].split('.').slice(0, 3).join('.');
      
      for (const machine of scenarioPlan.machines) {
        if (machine.type === 'attacker') {
          machineIPs[machine.name] = subnet.ips.attacker; // Use allocated attacker IP (e.g., .3)
        } else {
          // Use victim IP from subnet allocator for first victim, then sequential
          if (victimCounter === 0) {
            machineIPs[machine.name] = subnet.ips.victim; // Use allocated victim IP (e.g., .138)
          } else {
            machineIPs[machine.name] = `${baseIP}.${10 + victimCounter}`; // Additional victims start from .11
          }
          victimCounter++;
        }
      }

      console.log('🌐 IP Allocation:', machineIPs);
      progressCallback?.({ step: 'ips-allocated', message: `🌐 Subnet: ${subnet.subnet}` });

      // ===== PHASE 3: CALL CONTENT AGENTS (PARALLELIZED) =====
      // IMPROVEMENT: Parallelize content generation for faster challenge creation
      progressCallback?.({ step: 'content-generation', message: '🤖 Generating challenge content from specialized agents...' });

      const contentAgents = await loadContentAgents();
      const machineContents = {};

      // Separate attacker and victim machines
      const attackerMachines = scenarioPlan.machines.filter(m => m.type === 'attacker');
      const victimMachines = scenarioPlan.machines.filter(m => m.type !== 'attacker');

      // Handle attacker machines (no content generation needed)
      for (const machine of attackerMachines) {
        machineContents[machine.name] = {
          type: 'attacker',
          tools: await collectAllTools(scenarioPlan.categories, classification.requiredTools)
        };
      }

      // IMPROVEMENT: Generate content for victim machines in parallel
      if (victimMachines.length > 0) {
        const contentPromises = victimMachines.map(machine => 
          generateMachineContent(machine, scenarioPlan, contentAgents, progressCallback)
        );
        
        const machineContentsArray = await Promise.all(contentPromises);
        
        // Map results back to machine names
        victimMachines.forEach((machine, index) => {
          machineContents[machine.name] = machineContentsArray[index];
        });
      }

      progressCallback?.({ step: 'content-complete', message: '✅ Content generation complete' });

      // IMPROVEMENT: Save checkpoint after content generation
      await checkpointManager.saveCheckpoint(challengeName, 'content-generation', {
        machineContents,
        machineIPs,
        timestamp: Date.now()
      });

      // ===== PHASE 4: COMPILE INTO COMPLETE CHALLENGE =====
      progressCallback?.({ step: 'compilation', message: '🔧 Compiling multi-machine challenge...' });

      const compiledChallenge = await compileScenario({
        scenarioPlan,
        machineContents,
        machineIPs,
        subnet,
        challengeName,
        originalUserMessage: originalUserMessage // Pass original message for multi-OS detection
      });

      // ===== PHASE 5: VALIDATE STRUCTURE =====
      progressCallback?.({ step: 'validation', message: '🔍 Validating challenge structure...' });

      await validateChallengeStructure(compiledChallenge);

      progressCallback?.({ step: 'validation-passed', message: '✅ Structure validation passed' });

      // ===== PHASE 6: GENERATE DOCKER FILES =====
      progressCallback?.({ step: 'docker-generation', message: '🐳 Generating Docker configuration...' });

      const dockerFiles = await generateDockerConfiguration(
        compiledChallenge,
        machineIPs,
        subnet
      );

      // IMPROVEMENT: Score challenge quality (after Docker files are generated)
      try {
        const { scoreChallengeQuality, validateDifficulty } = await import('../challenge-quality-scorer.js');
        
        // Extract Dockerfile content from dockerFiles
        const dockerfileContent = dockerFiles.find(f => f.name === 'Dockerfile' || f.name.includes('Dockerfile'))?.content || '';
        const dockerComposeContent = dockerFiles.find(f => f.name === 'docker-compose.yml')?.content || '';
        
        const qualityScore = scoreChallengeQuality({
          metadata: compiledChallenge.metadata || {},
          dockerFiles: { 
            victim: dockerfileContent,
            attacker: dockerfileContent
          },
          additionalFiles: compiledChallenge.additionalFiles || [],
          flag: compiledChallenge.finalFlag
        });
        const difficultyValidation = validateDifficulty({
          metadata: compiledChallenge.metadata || {}
        });
        
        console.log(`\n📊 Challenge Quality Assessment:`);
        console.log(`   Score: ${qualityScore.score}/${qualityScore.maxScore} (${qualityScore.percentage}%)`);
        console.log(`   Grade: ${qualityScore.grade}`);
        console.log(`   Breakdown:`, JSON.stringify(qualityScore.breakdown, null, 2));
        
        if (qualityScore.recommendations.length > 0) {
          console.log(`\n💡 Recommendations:`);
          qualityScore.recommendations.forEach(rec => console.log(`   - ${rec}`));
        }
        
        if (!difficultyValidation.valid) {
          console.warn(`\n⚠️  Difficulty Validation Issue: ${difficultyValidation.issue}`);
          if (difficultyValidation.suggestedDifficulty) {
            console.warn(`   Suggested difficulty: ${difficultyValidation.suggestedDifficulty}`);
          }
        } else if (difficultyValidation.warning) {
          console.warn(`\n⚠️  Difficulty Validation Warning: ${difficultyValidation.warning}`);
        }
        
        // Store quality score in compiled challenge
        compiledChallenge.qualityScore = qualityScore;
        compiledChallenge.difficultyValidation = difficultyValidation;
      } catch (qualityError) {
        console.warn('⚠️  Quality scoring failed:', qualityError.message);
      }

      // ===== PHASE 6.5: WRITE FILES TO DISK (BEFORE VALIDATION) =====
      // IMPROVEMENT: Write files to disk first so validation can read them
      progressCallback?.({ step: 'write-files', message: '📝 Writing challenge files to repository...' });

      const allFiles = [
        ...dockerFiles,
        ...compiledChallenge.additionalFiles
      ];

      // Write all files to disk (gitManager.addFile writes to disk and stages for git)
      for (const file of allFiles) {
        const fileName = file.path ? `challenges/${challengeName}/${file.path}/${file.name}` : `challenges/${challengeName}/${file.name}`;
        await gitManager.addFile(fileName, file.content);
      }

      // ===== PHASE 6.6: PRE-DEPLOYMENT VALIDATION (AFTER FILES WRITTEN, BEFORE GITHUB PUSH) =====
      // IMPROVEMENT: Validate after files are written but before pushing to GitHub
      progressCallback?.({ step: 'pre-validate', message: '🔍 Validating challenge configuration before push...' });
      
      try {
        const { validateBeforeDeployment } = await import('./pre-deploy-validator-agent.js');
        const validationResult = await validateBeforeDeployment(challengeName, progressCallback);
        
        if (!validationResult.success) {
          // Cleanup subnet allocation on validation failure
          await subnetAllocator.releaseSubnet(challengeName, 'default');
          throw new Error(`Pre-deployment validation failed: ${validationResult.error || validationResult.summary}`);
        }
        
        if (validationResult.fixesApplied) {
          console.log(`✅ Applied ${validationResult.fixes.length} automatic fixes`);
          progressCallback?.({ step: 'fixes-applied', message: `✅ Applied ${validationResult.fixes.length} automatic fixes` });
          
          // Re-generate Docker files if fixes were applied
          if (validationResult.fixes.some(f => f.file.includes('docker-compose') || f.file.includes('Dockerfile'))) {
            console.log('🔄 Re-generating Docker files after fixes...');
            const updatedDockerFiles = await generateDockerConfiguration(
              compiledChallenge,
              machineIPs,
              subnet
            );
            
            // Write updated files to disk
            for (const file of updatedDockerFiles) {
              const fileName = file.path ? `challenges/${challengeName}/${file.path}/${file.name}` : `challenges/${challengeName}/${file.name}`;
              await gitManager.addFile(fileName, file.content);
            }
          }
        }
        
        progressCallback?.({ step: 'validation-passed', message: '✅ Pre-deployment validation passed' });
      } catch (validationError) {
        // Cleanup subnet allocation on validation failure
        await subnetAllocator.releaseSubnet(challengeName, 'default');
        console.error('❌ Pre-deployment validation error:', validationError);
        throw validationError;
      }

      // ===== PHASE 7: COMMIT AND PUSH TO GITHUB (Only if validation passed) =====
      progressCallback?.({ step: 'git-push', message: '📤 Committing and pushing to GitHub...' });

      // IMPROVEMENT: Add error handling with rollback for GitHub push
      let gitResult;
      try {
        // Commit and push (files are already staged by gitManager.addFile)
        const commitMessage = `Add challenge: ${challengeName} (${scenarioPlan.categories.join(', ')})`;
        gitResult = await gitManager.commitAndPush(commitMessage);
      } catch (gitError) {
        // Rollback: Clean up files from disk if GitHub push fails
        console.error('❌ GitHub push failed, cleaning up files:', gitError.message);
        try {
          await gitManager.cleanupFailedCommit(challengeName);
        } catch (cleanupError) {
          console.warn('⚠️  Failed to cleanup files after GitHub push failure:', cleanupError.message);
        }
        // Release subnet allocation
        await subnetAllocator.releaseSubnet(challengeName, 'default');
        throw new Error(`Failed to push challenge to GitHub: ${gitError.message}`);
      }

      progressCallback?.({ step: 'complete', message: '✅ Challenge creation complete!' });

      // IMPROVEMENT: Cleanup checkpoints on successful completion
      await checkpointManager.cleanup(challengeName);

      // Extract challenge metadata for user-friendly response
      const metadata = compiledChallenge.metadata || {};
      const challengeDescription = metadata.description || scenarioPlan.scenario?.description || 'A CTF challenge';
      const challengeType = scenarioPlan.categories?.join(', ') || classification.challengeType || 'General';
      const difficulty = metadata.difficulty || scenarioPlan.scenario?.difficulty || 'Medium';

      return {
        success: true,
        readyForDeployment: true, // Flag to indicate challenge is ready but needs user confirmation
        challengeName: challengeName,
        description: challengeDescription,
        type: challengeType,
        difficulty: difficulty,
        scenario: scenarioPlan.scenario,
        machines: scenarioPlan.machines,
        machineIPs: machineIPs,
        subnet: subnet,
        flag: compiledChallenge.finalFlag,
        gitResult: gitResult,
        challenge: {
          name: challengeName,
          description: challengeDescription,
          type: challengeType,
          difficulty: difficulty,
          category: challengeType,
          flag: compiledChallenge.finalFlag,
          machines: scenarioPlan.machines.map(m => ({
            name: m.name,
            type: m.type,
            role: m.role,
            services: m.services
          }))
        }
      };

    } catch (error) {
      console.error(`Universal agent attempt ${attempt} error:`, error);
      lastError = error.message;

      // IMPROVEMENT: Cleanup subnet allocation on failure
      try {
        if (challengeName) {
          await subnetAllocator.releaseSubnet(challengeName, 'default');
          console.log(`🗑️  Released subnet allocation for ${challengeName} due to error`);
        }
      } catch (cleanupError) {
        console.warn('⚠️  Failed to cleanup subnet allocation:', cleanupError.message);
      }

      if (attempt === maxRetries) {
        throw error;
      }
    }
  }

  throw new Error(`Failed after ${maxRetries} attempts. Last error: ${lastError}`);
}

/**
 * Load all content agents dynamically
 */
async function loadContentAgents() {
  const agents = {};
  
  try {
    const cryptoAgent = await import('./content/crypto-content-agent.js');
    agents.crypto = cryptoAgent.generateCryptoContent;
  } catch (e) {
    console.warn('Crypto agent not available:', e.message);
  }

  try {
    const webAgent = await import('./content/web-content-agent.js');
    agents.web = webAgent.generateWebContent;
  } catch (e) {
    console.warn('Web agent not available:', e.message);
  }

  try {
    const networkAgent = await import('./content/network-content-agent.js');
    agents.network = networkAgent.generateNetworkContent;
  } catch (e) {
    console.warn('Network agent not available:', e.message);
  }

  return agents;
}

/**
 * Generate content for a specific machine by calling appropriate content agents
 */
async function generateMachineContent(machine, scenarioPlan, contentAgents, progressCallback) {
  const machineContent = {
    name: machine.name,
    type: machine.type,
    role: machine.role,
    services: machine.services,
    files: [],
    configurations: {}
  };

  // Call content agents based on machine categories
  for (const category of machine.categories || []) {
    const agent = contentAgents[category];
    if (!agent) {
      console.warn(`No content agent available for category: ${category}`);
      continue;
    }

    progressCallback?.({ step: `content-${category}`, message: `🎨 Generating ${category} content for ${machine.name}...` });

    try {
      const content = await agent({
        machineName: machine.name,
        services: machine.services,
        scenario: scenarioPlan.scenario,
        dependencies: scenarioPlan.dependencies
      });

      // Merge content into machine
      machineContent.files.push(...content.files);
      machineContent.configurations[category] = content.configuration;
      
      if (content.flag) {
        machineContent.flag = content.flag;
      }

    } catch (error) {
      console.error(`Error generating ${category} content:`, error);
      throw new Error(`Failed to generate ${category} content for ${machine.name}: ${error.message}`);
    }
  }

  return machineContent;
}

/**
 * Collect all required tools based on categories (from database)
 */
async function collectAllTools(categories, additionalTools = []) {
  const { getToolsByCategory } = await import('../package-mapping-db-manager.js');
  
  const tools = new Set(additionalTools);
  for (const category of categories) {
    const categoryTools = await getToolsByCategory(category);
    categoryTools.forEach(tool => tools.add(tool));
  }

  return Array.from(tools);
}

/**
 * Compile all machine contents into a cohesive scenario
 */
async function compileScenario({ scenarioPlan, machineContents, machineIPs, subnet, challengeName, originalUserMessage = '' }) {
  // Find the final flag (from last stage or most complex machine)
  let finalFlag = null;
  for (const machineName in machineContents) {
    const content = machineContents[machineName];
    if (content.flag) {
      finalFlag = content.flag;
      break;
    }
  }

  // IMPROVEMENT: Generate unique flag with timestamp and variation
  if (!finalFlag) {
    const timestamp = Date.now().toString(36).substring(0, 6);
    const random = crypto.randomBytes(6).toString('hex');
    const category = scenarioPlan.categories[0] || 'misc';
    finalFlag = `CTF{${category}_${timestamp}_${random}}`;
  }

  // Generate comprehensive README
  const readme = generateScenarioReadme({
    scenario: scenarioPlan.scenario,
    machines: scenarioPlan.machines,
    machineIPs: machineIPs,
    stages: scenarioPlan.scenario.stages,
    categories: scenarioPlan.categories
  });

  // Generate metadata
  const metadata = {
    name: challengeName,
    title: scenarioPlan.scenario.title,
    description: scenarioPlan.scenario.description,
    category: scenarioPlan.categories[0], // Primary category
    subcategories: scenarioPlan.categories,
    difficulty: determineDifficulty(scenarioPlan),
    flag: finalFlag,
    machines: scenarioPlan.machines.length,
    machineDetails: scenarioPlan.machines.map(m => ({
      name: m.name,
      type: m.type,
      ip: machineIPs[m.name],
      services: m.services
    })),
    stages: scenarioPlan.scenario.stages.length,
    created: new Date().toISOString(),
    generator: 'universal-structure-agent'
  };

  return {
    scenarioPlan,
    machineContents,
    machineIPs,
    subnet,
    finalFlag,
    readme,
    originalUserMessage: originalUserMessage, // Store for multi-OS detection
    metadata,
    additionalFiles: [
      { name: 'README.md', path: '', content: readme },
      { name: 'metadata.json', path: '', content: JSON.stringify(metadata, null, 2) }
    ]
  };
}

/**
 * Validate the complete challenge structure
 */
async function validateChallengeStructure(compiledChallenge) {
  // Check for placeholders in README
  const placeholderPatterns = [
    /\.{3,}/,
    /\[PLACEHOLDER\]/i,
    /\[INSERT[^\]]*\]/i,
    /\[TODO[^\]]*\]/i
  ];

  for (const pattern of placeholderPatterns) {
    if (pattern.test(compiledChallenge.readme)) {
      throw new Error(`Placeholder detected in README: ${pattern}`);
    }
  }

  // Validate flag format
  if (!compiledChallenge.finalFlag || !/^CTF\{[a-zA-Z0-9_\-]{10,}\}$/.test(compiledChallenge.finalFlag)) {
    throw new Error('Invalid flag format');
  }

  // Validate machine IPs are in subnet
  const subnetPrefix = compiledChallenge.subnet.subnet.split('/')[0].split('.').slice(0, 3).join('.');
  for (const machineName in compiledChallenge.machineIPs) {
    const ip = compiledChallenge.machineIPs[machineName];
    if (!ip.startsWith(subnetPrefix)) {
      throw new Error(`Machine ${machineName} IP ${ip} not in subnet ${compiledChallenge.subnet.subnet}`);
    }
  }

  return true;
}

/**
 * Select OS image for a machine based on context
 * BEST PRACTICE: Unified logic to avoid code duplication
 */
async function selectOSImage({ isMultiOSChallenge, machineIndex, machineNameLower, machineRole, services, validatedOSImages }) {
  let osImage = 'ubuntu:22.04'; // Default
  let packageManager = 'apt-get';
  
  // Automatic OS assignment for multi-OS challenges (ensures variety using validated images)
  if (isMultiOSChallenge && machineIndex >= 0 && validatedOSImages.length > 0) {
    // Use validated images, cycling through different OS types for variety
    const selectedImage = validatedOSImages[machineIndex % validatedOSImages.length];
    osImage = selectedImage.image;
    packageManager = selectedImage.manager;
  }
  
  // Override based on machine name/role (applies to both multi-OS and single-OS challenges)
  if (machineNameLower.includes('alpine') || machineRole.includes('alpine') || machineRole.includes('minimal')) {
    osImage = 'alpine:latest';
    packageManager = 'apk';
  } else if (machineNameLower.includes('rocky') || machineNameLower.includes('enterprise') || machineNameLower.includes('rhel') || machineRole.includes('enterprise')) {
    osImage = 'rockylinux:9';
    packageManager = 'dnf';
  } else if (machineNameLower.includes('debian') || machineRole.includes('debian')) {
    osImage = 'debian:bookworm';
    packageManager = 'apt-get';
  } else if (machineNameLower.includes('samba') || machineRole.includes('samba') || services?.includes('samba')) {
    // Linux Samba (SMB protocol on Linux) - Use Ubuntu with Samba
    // Note: Windows is NOT supported - all machines must be Linux
    osImage = 'ubuntu:22.04';
    packageManager = 'apt-get';
  } else if (machineNameLower.includes('windows') || machineRole.includes('windows') || services?.includes('smb')) {
    // Windows detected - convert to Linux (Ubuntu with Samba for SMB functionality)
    // CRITICAL: Platform only supports Linux - Windows vulnerabilities are NOT supported
    console.warn(`⚠️  Windows machine detected (${machineNameLower}) - converting to Linux (Ubuntu with Samba). Windows is NOT supported.`);
    osImage = 'ubuntu:22.04';
    packageManager = 'apt-get';
  } else if (machineNameLower.includes('ubuntu') || machineRole.includes('ubuntu')) {
    osImage = 'ubuntu:22.04';
    packageManager = 'apt-get';
  } else if (machineNameLower.includes('fedora') || machineRole.includes('fedora')) {
    osImage = 'fedora:latest';
    packageManager = 'dnf';
  } else if (machineNameLower.includes('arch') || machineRole.includes('arch')) {
    osImage = 'archlinux:latest';
    packageManager = 'pacman';
  }
  
  // Validate selected image (best practice: validate all selections)
  // CRITICAL: Ensure only Linux images are used - Windows is NOT supported
  const imageLower = osImage.toLowerCase();
  if (imageLower.includes('windows') || osImage.includes('mcr.microsoft.com')) {
    console.warn(`❌ Windows image detected: ${osImage}. Converting to Linux (Ubuntu 22.04). Windows is NOT supported.`);
    osImage = 'ubuntu:22.04';
    packageManager = 'apt-get';
  }
  
  const isValid = await isValidOSImage(osImage);
  if (!isValid) {
    console.warn(`⚠️  Selected image ${osImage} not in validated list, using default`);
    osImage = 'ubuntu:22.04';
    packageManager = 'apt-get';
  } else {
    // CRITICAL: Double-check package manager matches the selected image
    // Get the actual package manager from the database for the selected image
    const imageInfo = await getOSImageInfo(osImage);
    if (imageInfo && imageInfo.manager) {
      packageManager = imageInfo.manager;
      console.log(`✅ Verified package manager for ${osImage}: ${packageManager}`);
    } else {
      // Fallback to detection if database doesn't have it
      packageManager = detectPackageManagerFromImage(osImage);
      console.log(`⚠️  Using detected package manager for ${osImage}: ${packageManager}`);
    }
  }
  
  return { osImage, packageManager };
}

/**
 * Generate Docker configuration for all machines
 */
async function generateDockerConfiguration(compiledChallenge, machineIPs, subnet) {
  const files = [];

  // Generate Dockerfiles for each machine
  for (const machineName in compiledChallenge.machineContents) {
    const content = compiledChallenge.machineContents[machineName];

    if (content.type === 'attacker') {
      // Generate attacker Dockerfile using tool installation agent
      const attackerDockerfile = await generateToolInstallationDockerfile({
        category: compiledChallenge.scenarioPlan.categories[0],
        challengeType: compiledChallenge.scenarioPlan.scenario.title,
        scenario: compiledChallenge.scenarioPlan.scenario.description,
        requiredTools: content.tools
      });

      files.push({
        name: 'Dockerfile.attacker',
        path: 'attacker',
        content: attackerDockerfile
      });
    } else {
      // IMPROVEMENT: Determine OS image based on machine name/role for multi-OS support
      // Use validated/tested Docker OS images that support port configuration and service installation
      const machineNameLower = machineName.toLowerCase();
      const machineRole = content.role?.toLowerCase() || '';
      
      // Multi-OS detection: Check original user message, scenario description, and title
      const originalMessage = compiledChallenge.originalUserMessage || '';
      const scenarioDesc = compiledChallenge.scenarioPlan.scenario.description?.toLowerCase() || '';
      const scenarioTitle = compiledChallenge.scenarioPlan.scenario.title?.toLowerCase() || '';
      
      const multiOSKeywords = [
        'multiple os', 'multi-os', 'multi os', 'different os', 'different operating systems',
        'various os', 'various operating systems', 'different machines', 'multiple machines',
        'nmap', 'network scanning', 'os detection', 'fingerprinting'
      ];
      
      const isMultiOSChallenge = multiOSKeywords.some(keyword => 
        originalMessage.includes(keyword) || 
        scenarioDesc.includes(keyword) || 
        scenarioTitle.includes(keyword)
      );
      
      // Get all victim machines to assign OS images by index
      const victimMachines = Object.keys(compiledChallenge.machineContents).filter(name => 
        compiledChallenge.machineContents[name].type !== 'attacker'
      );
      const machineIndex = victimMachines.indexOf(machineName);
      
      // Load validated OS images from test results
      const validatedOSImages = await getValidatedOSImages();
      
      // Select OS image using unified logic (BEST PRACTICE: No code duplication)
      const { osImage, packageManager } = await selectOSImage({
        isMultiOSChallenge,
        machineIndex,
        machineNameLower,
        machineRole,
        services: content.services,
        validatedOSImages
      });
      
      // Generate victim machine Dockerfile with SSH and selected OS image
      const victimDockerfile = await generateVictimDockerfileWithSSH({
        category: compiledChallenge.scenarioPlan.categories[0],
        services: content.services,
        scenario: compiledChallenge.scenarioPlan.scenario.description,
        osImage: osImage,
        packageManager: packageManager,
        machineName: machineName,
        configurations: content.configurations || {}, // Pass AI-generated service configurations
        difficulty: compiledChallenge.metadata?.difficulty || 'medium', // Pass difficulty for decoy ports
        isAttacker: false // Victim machines don't expose SSH
      });
      
      files.push({
        name: 'Dockerfile',
        path: content.name,
        content: victimDockerfile
      });

      // Add machine-specific files
      for (const file of content.files) {
        files.push({
          name: file.name,
          path: `${content.name}/${file.path || ''}`,
          content: file.content
        });
      }
    }
  }

  // Generate docker-compose.yml
  const dockerCompose = generateMultiMachineDockerCompose(
    compiledChallenge,
    machineIPs,
    subnet
  );

  files.push({
    name: 'docker-compose.yml',
    path: '',
    content: dockerCompose
  });

  return files;
}

/**
 * Generate multi-machine docker-compose.yml
 */
function generateMultiMachineDockerCompose(compiledChallenge, machineIPs, subnet) {
  const challengeName = compiledChallenge.scenarioPlan.scenario.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-');

  // ✅ FIX: Remove obsolete version attribute (docker compose v2 doesn't need it)
  let compose = `services:\n`;

  // Add each machine as a service
  for (const machineName in compiledChallenge.machineContents) {
    const content = compiledChallenge.machineContents[machineName];
    
    // Normalize attacker machine name to always be 'attacker' for consistent container naming
    const normalizedName = content.type === 'attacker' ? 'attacker' : machineName;
    const serviceName = `ctf-${challengeName}-${normalizedName}`;
    const ip = machineIPs[machineName];

    compose += `  ${serviceName}:\n`;

    if (content.type === 'attacker') {
      compose += `    build:\n`;
      compose += `      context: ./attacker\n`;
      compose += `      dockerfile: Dockerfile.attacker\n`;
    } else {
      compose += `    build:\n`;
      compose += `      context: ./${machineName}\n`;
      compose += `      dockerfile: Dockerfile\n`;
    }

    compose += `    container_name: ${serviceName}\n`;
    compose += `    hostname: ${machineName}\n`;
    compose += `    labels:\n`;
    compose += `      com.ctf.machine.type: "${content.type}"\n`;
    compose += `      com.ctf.challenge: "${challengeName}"\n`;
    compose += `    networks:\n`;
    compose += `      ctf-${challengeName}-net:\n`;
    compose += `        ipv4_address: ${ip}\n`;
    
    // Add ctf-instances-network for attacker (Guacamole access)
    // Guacamole will connect to challenge network IP, but needs routing
    if (content.type === 'attacker') {
      compose += `      ctf-instances-network:\n`;
    }
    
    // ✅ FIX: Add NET_RAW and NET_ADMIN capabilities for nmap (needed for binary execution)
    // Even with unprivileged mode wrapper, the binary needs capabilities to execute
    if (content.type === 'attacker') {
      compose += `    cap_add:\n`;
      compose += `      - NET_RAW\n`;
      compose += `      - NET_ADMIN\n`;
    }

    // Add port mappings for victim services
    if (content.type !== 'attacker' && content.services && content.services.length > 0) {
      const portMap = {
        'http': 80,
        'https': 443,
        'ftp': 21,
        'smb': 445,
        'ssh': 22
      };

      const ports = content.services.map(s => portMap[s]).filter(p => p);
      if (ports.length > 0) {
        compose += `    ports:\n`;
        for (const port of ports) {
          compose += `      - "${port}"\n`;
        }
      }
    }

    compose += `    stdin_open: true\n`;
    compose += `    tty: true\n\n`;
  }

  // Add network configuration
  compose += `networks:\n`;
  compose += `  ctf-${challengeName}-net:\n`;
  compose += `    driver: bridge\n`;
  compose += `    ipam:\n`;
  compose += `      config:\n`;
  // Extract subnet string from allocation object
  const subnetCidr = typeof subnet === 'string' ? subnet : (subnet.subnet || subnet.cidr || '172.29.0.0/24');
  const gatewayIP = typeof subnet === 'string' ? subnet.split('/')[0].split('.').slice(0, 3).join('.') + '.1' : (subnet.gateway || '172.29.0.1');
  compose += `        - subnet: ${subnetCidr}\n`;
  compose += `          gateway: ${gatewayIP}\n`;
  compose += `  ctf-instances-network:\n`;
  compose += `    external: true\n`;

  return compose;
}

/**
 * Generate comprehensive README for scenario
 */
function generateScenarioReadme({ scenario, machines, machineIPs, stages, categories }) {
  let readme = `# ${scenario.title}\n\n`;
  readme += `## Scenario Description\n\n`;
  readme += `${scenario.description}\n\n`;

  readme += `## Challenge Information\n\n`;
  readme += `- **Categories:** ${categories.join(', ')}\n`;
  readme += `- **Machines:** ${machines.length}\n`;
  readme += `- **Stages:** ${stages.length}\n\n`;

  readme += `## Network Architecture\n\n`;
  readme += `| Machine | Type | IP Address | Services |\n`;
  readme += `|---------|------|------------|----------|\n`;
  for (const machine of machines) {
    const ip = machineIPs[machine.name];
    const services = machine.services?.join(', ') || 'N/A';
    readme += `| ${machine.name} | ${machine.type} | ${ip} | ${services} |\n`;
  }
  readme += `\n`;

  readme += `## Challenge Stages\n\n`;
  stages.forEach((stage, i) => {
    readme += `### Stage ${i + 1}\n\n`;
    readme += `${stage}\n\n`;
  });

  readme += `## Getting Started\n\n`;
  readme += `1. Access the attacker machine via Guacamole\n`;
  readme += `2. Scan the network to identify target machines\n`;
  readme += `3. Follow the scenario stages to progress\n`;
  readme += `4. Capture the flag!\n\n`;

  readme += `## Learning Objectives\n\n`;
  for (const category of categories) {
    readme += `- ${getCategoryDescription(category)}\n`;
  }

  return readme;
}

/**
 * Get description for category
 */
function getCategoryDescription(category) {
  const descriptions = {
    'crypto': 'Cryptographic analysis and decryption techniques',
    'web': 'Web application vulnerability exploitation',
    'network': 'Network scanning and service exploitation'
  };
  return descriptions[category] || category;
}

/**
 * Determine difficulty based on scenario complexity
 */
function determineDifficulty(scenarioPlan) {
  const machineCount = scenarioPlan.machineCount;
  const categoryCount = scenarioPlan.categories.length;
  const stageCount = scenarioPlan.scenario.stages.length;

  const score = machineCount + categoryCount + stageCount;

  if (score <= 5) return 'easy';
  if (score <= 10) return 'medium';
  return 'hard';
}

/**
 * Generate random string for flags
 */
function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
