/**
 * Challenge Designer - AI-powered challenge design
 * 
 * Responsibilities:
 * - Generate perfect challenge designs using AI
 * - Ensure all required fields are present
 * - Validate design completeness
 * - Reference Vulhub for correctness
 */

import Anthropic from '@anthropic-ai/sdk';
import { Logger } from '../core/logger.js';
import { linuxOnlyValidator } from '../core/linux-only-validator.js';
import dotenv from 'dotenv';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const DESIGN_SYSTEM_PROMPT = `You are an expert CTF challenge designer. Your task is to create PERFECT, COMPLETE challenge designs that are ready for implementation.

CRITICAL REQUIREMENTS:
1. **COMPLETE DESIGNS ONLY** - Every field must be filled with real, working values
2. **NO PLACEHOLDERS** - Never use TODO, FIXME, [PLACEHOLDER], ..., etc.
3. **VULHUB REFERENCE** - Always reference Vulhub (https://github.com/vulhub/vulhub) for correct configurations
4. **WORKING CONFIGURATIONS** - All configurations must be tested patterns from Vulhub
5. **COMPLETE SETUP COMMANDS** - Setup commands are MANDATORY and must be complete

VULHUB INTEGRATION (CRITICAL):
- Vulhub provides 200+ pre-built vulnerable environments with WORKING configurations
- Use Vulhub as PRIMARY reference for:
  * Dockerfile syntax and patterns
  * docker-compose.yml structures
  * Service configurations (vsftpd.conf, smb.conf, sshd_config, etc.)
  * Directory structures and file permissions
  * Service startup commands

SUPPORTED CHALLENGE TYPES:
1. **Network Security**: FTP, SSH, Samba (Linux SMB), Telnet
   - **EternalBlue/MS17-010**: Use Samba misconfiguration on Linux (Windows EternalBlue not supported)
   - **SMB vulnerabilities**: Null session, guest access, anonymous shares, SMB relay
   - **FTP vulnerabilities**: Anonymous access, weak credentials, writable directories
2. **Cryptography**: Encryption, encoding, hashing, ciphers
3. **Simple Web**: SQL injection, XSS, basic web vulnerabilities

SPECIFIC VULNERABILITY HANDLING:
- When user requests a SPECIFIC vulnerability, you MUST:
  1. Identify the vulnerability from the user's request
  2. Determine the appropriate service/protocol:
     * **EternalBlue / MS17-010** (CVE-2017-0144/0145) → SMB/Samba service (ports 445, 139)
     * **BlueKeep** (CVE-2019-0708) → RDP service (port 3389) - NOT SUPPORTED (Windows only)
     * **SQL injection** → Database/Web service
     * **XSS** → HTTP/Web service
  3. Create a challenge focused ENTIRELY on that vulnerability
  4. Use correct service configurations
  5. **CRITICAL**: Include the service in the "services" array (e.g., ["samba", "ssh"] for EternalBlue)
- Do NOT create a generic challenge when a specific vulnerability is requested
- If user requests BlueKeep, explain it's Windows-only and suggest EternalBlue (SMB) instead
- Use your knowledge of vulnerabilities to map them to correct services and configurations

RESTRICTIONS:
- NO Windows vulnerabilities (only Linux)
- NO Forensics, Reverse Engineering, Binary Exploitation
- NO complex multi-stage challenges

OUTPUT FORMAT (JSON):
{
  "name": "unique-challenge-name",
  "type": "network|crypto|web",
  "difficulty": "easy|medium|hard",
  "description": "Clear, engaging description",
  "scenario": "Realistic scenario description",
  "machines": [
    {
      "name": "machine-name",
      "role": "attacker|victim",
      "os": "ubuntu:22.04|rockylinux:9|alpine:latest",
      "services": ["ftp", "ssh"],
      "vulnerabilities": ["weak-credentials", "misconfiguration"],
      "flagLocation": "/path/to/flag.txt",
      "flagFormat": "CTF{...}"
    }
  ],
  "requirements": {
    "tools": ["nmap", "ftp", "wireshark"],
    "skills": ["network-scanning", "ftp-exploitation"]
  },
  "hints": [
    "Vague hint",
    "More specific hint",
    "Very specific hint"
  ]
}

CRITICAL - SETUP COMMANDS:
Every machine MUST have complete setup commands that:
1. Copy configuration files to correct locations
2. Create necessary directories with correct permissions
3. Start services in background
4. Place flags in correct locations
5. Set correct file ownership

Example setup for FTP:
"setup": "cp /challenge/vsftpd.conf /etc/vsftpd.conf && mkdir -p /var/run/vsftpd/empty /var/ftp/data/classified && chmod 555 /var/ftp && chmod 755 /var/ftp/data /var/ftp/data/classified && cp /challenge/flag.txt /var/ftp/data/classified/flag.txt && chmod 644 /var/ftp/data/classified/flag.txt && chown ftp:ftp /var/ftp/data/classified/flag.txt && /usr/sbin/vsftpd /etc/vsftpd.conf &"

Remember: Reference Vulhub examples to ensure your setup commands are correct and working.`;

export class ChallengeDesigner {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Design a challenge based on requirements
   */
  async design(requirements, conversationHistory = []) {
    try {
      this.logger.info('ChallengeDesigner', 'Starting challenge design');

      if (!process.env.ANTHROPIC_API_KEY) {
        return {
          success: false,
          error: 'ANTHROPIC_API_KEY is not set',
          message: 'Please set ANTHROPIC_API_KEY in your .env file'
        };
      }

      // Build design prompt
      const designPrompt = this.buildDesignPrompt(requirements, conversationHistory);

      // Generate design using AI
      const response = await anthropic.messages.create({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
        max_tokens: 4000,
        temperature: 0.7,
        system: DESIGN_SYSTEM_PROMPT,
        messages: [{
          role: 'user',
          content: designPrompt
        }]
      });

      const content = response.content[0].text;
      this.logger.debug('ChallengeDesigner', 'AI response received', { length: content.length });

      // Parse JSON from response
      const design = this.parseDesign(content);

      // Validate design
      const validation = this.validateDesign(design);
      if (!validation.valid) {
        this.logger.warn('ChallengeDesigner', 'Design validation failed', validation.errors);
        
        // Retry with error feedback
        return await this.retryDesign(requirements, conversationHistory, validation.errors);
      }

      // 🔒 CRITICAL: Validate Linux-only requirement
      const linuxValidation = linuxOnlyValidator.validateDesignMachines(design.machines);
      if (!linuxValidation.valid) {
        this.logger.error('ChallengeDesigner', 'Windows OS detected in design', linuxValidation.errors);
        
        // Retry with Linux-only feedback
        const linuxErrors = [
          'CRITICAL: Windows OS detected in challenge design. This platform ONLY supports Linux-based challenges.',
          'All machines MUST use Linux base images: ubuntu:22.04, rockylinux:9, alpine:latest, or kalilinux/kali-rolling:latest',
          ...linuxValidation.errors
        ];
        return await this.retryDesign(requirements, conversationHistory, linuxErrors);
      }

      if (linuxValidation.warnings.length > 0) {
        this.logger.warn('ChallengeDesigner', 'Linux validation warnings', linuxValidation.warnings);
      }

      this.logger.success('ChallengeDesigner', 'Challenge design completed', { name: design.name });

      return {
        success: true,
        data: design
      };

    } catch (error) {
      this.logger.error('ChallengeDesigner', 'Design failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Build design prompt from requirements
   */
  buildDesignPrompt(requirements, conversationHistory) {
    let prompt = `Create a perfect CTF challenge with the following requirements:\n\n`;

    // Get original user message to preserve full context - let AI understand naturally
    const originalMessage = this.extractOriginalMessage(conversationHistory);
    
    // Include the original user request so AI can understand the specific vulnerability
    if (originalMessage) {
      prompt += `**USER REQUEST:** "${originalMessage}"\n\n`;
      prompt += `CRITICAL: Analyze the user's request carefully. If they mentioned a SPECIFIC vulnerability, you MUST:\n`;
      prompt += `1. Identify the EXACT vulnerability from the user's request\n`;
      prompt += `   - "EternalBlue" or "MS17-010" (CVE-2017-0144) → SMB/Samba service (ports 445, 139)\n`;
      prompt += `   - "BlueKeep" (CVE-2019-0708) → RDP service (port 3389) - NOT SUPPORTED (Windows only, suggest EternalBlue instead)\n`;
      prompt += `   - Other vulnerabilities → Map to appropriate service\n`;
      prompt += `2. Determine the appropriate service/protocol\n`;
      prompt += `3. Create a challenge focused ENTIRELY on that vulnerability\n`;
      prompt += `4. **MANDATORY**: Include the service in the machine's "services" array (e.g., ["samba", "ssh"] for EternalBlue)\n`;
      prompt += `5. Use correct service configurations (EternalBlue/MS17-010 → Samba on Linux, not Windows)\n\n`;
    }

    if (requirements.challengeType) {
      prompt += `Challenge Type: ${requirements.challengeType}\n`;
    }

    if (requirements.difficulty) {
      prompt += `**CRITICAL - DIFFICULTY REQUIREMENT:**\n`;
      prompt += `The user has specified difficulty: ${requirements.difficulty}\n`;
      prompt += `You MUST set "difficulty" field to exactly "${requirements.difficulty}" in your JSON response.\n`;
      prompt += `Do NOT use "medium" as default - use the specified difficulty: ${requirements.difficulty}\n\n`;
    } else {
      // If no difficulty specified, analyze the request for implicit difficulty
      if (originalMessage) {
        const originalLower = originalMessage.toLowerCase();
        if (originalLower.includes('simple') || originalLower.includes('basic') || originalLower.includes('easy') || originalLower.includes('beginner')) {
          prompt += `**IMPORTANT - DIFFICULTY DETECTION:**\n`;
          prompt += `The user's request suggests a simple/easy challenge. Set "difficulty" to "easy" in your JSON response.\n\n`;
        } else if (originalLower.includes('complex') || originalLower.includes('advanced') || originalLower.includes('hard') || originalLower.includes('expert')) {
          prompt += `**IMPORTANT - DIFFICULTY DETECTION:**\n`;
          prompt += `The user's request suggests a complex/advanced challenge. Set "difficulty" to "hard" in your JSON response.\n\n`;
        }
      }
    }

    if (requirements.services && requirements.services.length > 0) {
      prompt += `Services: ${requirements.services.join(', ')}\n`;
    }

    if (requirements.scenario) {
      prompt += `Scenario Context: ${requirements.scenario}\n`;
    }

    if (requirements.machines) {
      prompt += `Number of Machines: ${requirements.machines}\n`;
    }

    prompt += `\nIMPORTANT:\n`;
    prompt += `- Generate a COMPLETE, WORKING challenge design\n`;
    prompt += `- Reference Vulhub for correct service configurations\n`;
    prompt += `- Include ALL setup commands (MANDATORY)\n`;
    prompt += `- Use real, working values (no placeholders)\n`;
    prompt += `- Ensure the challenge is solvable and educational\n`;
    prompt += `- **CRITICAL - DIFFICULTY**: Use the difficulty specified above (${requirements.difficulty || 'analyze from user request'}). Do NOT default to "medium" unless explicitly requested.\n`;
    prompt += `- If user requested a specific vulnerability, focus the ENTIRE challenge on that vulnerability\n`;
    prompt += `- **CRITICAL**: For SMB/Samba challenges (EternalBlue), the victim machine MUST have "samba" in the services array: ["samba", "ssh"]\n`;
    prompt += `- **CRITICAL**: For each service in the services array, ensure the service will actually run (install package, configure, start service)\n`;

    return prompt;
  }

  /**
   * Extract original user message from conversation history
   */
  extractOriginalMessage(conversationHistory) {
    if (!conversationHistory || conversationHistory.length === 0) {
      return null;
    }
    
    // Get the most recent user message
    for (let i = conversationHistory.length - 1; i >= 0; i--) {
      if (conversationHistory[i].role === 'user') {
        return conversationHistory[i].content;
      }
    }
    
    return null;
  }


  /**
   * Parse design from AI response
   */
  parseDesign(content) {
    try {
      // Extract JSON from markdown code blocks if present
      const jsonMatch = content.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
      const jsonString = jsonMatch ? jsonMatch[1] : content;

      // Try to find JSON object
      const jsonObjectMatch = jsonString.match(/\{[\s\S]*\}/);
      if (jsonObjectMatch) {
        return JSON.parse(jsonObjectMatch[0]);
      }

      throw new Error('No JSON object found in response');
    } catch (error) {
      this.logger.error('ChallengeDesigner', 'Failed to parse design', error.stack);
      throw new Error(`Failed to parse design: ${error.message}`);
    }
  }

  /**
   * Validate design completeness
   */
  validateDesign(design) {
    const errors = [];

    // Required fields
    if (!design.name || typeof design.name !== 'string') {
      errors.push('Missing or invalid "name" field');
    }

    if (!design.type || !['network', 'crypto', 'web'].includes(design.type)) {
      errors.push('Missing or invalid "type" field (must be network, crypto, or web)');
    }

    if (!design.difficulty || !['easy', 'medium', 'hard'].includes(design.difficulty)) {
      errors.push('Missing or invalid "difficulty" field');
    }

    if (!design.machines || !Array.isArray(design.machines) || design.machines.length === 0) {
      errors.push('Missing or invalid "machines" array');
    }

    // Validate each machine
    if (design.machines) {
      design.machines.forEach((machine, index) => {
        if (!machine.name) {
          errors.push(`Machine ${index}: Missing "name" field`);
        }
        if (!machine.role || !['attacker', 'victim'].includes(machine.role)) {
          errors.push(`Machine ${index}: Missing or invalid "role" field`);
        }
        if (!machine.os) {
          errors.push(`Machine ${index}: Missing "os" field`);
        } else {
          // Validate OS is Linux-based
          const osLower = machine.os.toLowerCase();
          const isWindows = /windows|win32|win64|mcr\.microsoft\.com|microsoft/i.test(osLower);
          if (isWindows) {
            errors.push(
              `Machine ${index} (${machine.name || 'unnamed'}): Windows OS detected: "${machine.os}". ` +
              `Only Linux-based OS are supported (e.g., ubuntu:22.04, rockylinux:9, alpine:latest, kalilinux/kali-rolling:latest)`
            );
          }
        }
        if (machine.role === 'victim' && (!machine.services || machine.services.length === 0)) {
          errors.push(`Machine ${index}: Victim machine must have at least one service`);
        }
        
        // Validate service-vulnerability matching
        if (machine.role === 'victim' && machine.services) {
          const servicesLower = machine.services.map(s => s.toLowerCase());
          const descriptionLower = (design.description || '').toLowerCase();
          const scenarioLower = (design.scenario || '').toLowerCase();
          const combinedText = descriptionLower + ' ' + scenarioLower;
          
          // Check for SMB/Samba/EternalBlue mentions
          if ((combinedText.includes('eternalblue') || combinedText.includes('ms17-010') || 
               combinedText.includes('samba') || combinedText.includes('smb')) &&
              !servicesLower.includes('samba') && !servicesLower.includes('smb')) {
            errors.push(`Machine ${index}: Challenge mentions SMB/Samba/EternalBlue but services array doesn't include "samba" or "smb"`);
          }
        }
      });
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Retry design with error feedback
   */
  async retryDesign(requirements, conversationHistory, errors) {
    this.logger.info('ChallengeDesigner', 'Retrying design with error feedback');

    const errorPrompt = `Previous design had validation errors:\n${errors.join('\n')}\n\nPlease fix these errors and generate a complete, valid design.`;

    const response = await anthropic.messages.create({
      model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
      max_tokens: 4000,
      temperature: 0.7,
      system: DESIGN_SYSTEM_PROMPT,
      messages: [
        {
          role: 'user',
          content: this.buildDesignPrompt(requirements, conversationHistory)
        },
        {
          role: 'assistant',
          content: 'I will generate a complete challenge design.'
        },
        {
          role: 'user',
          content: errorPrompt
        }
      ]
    });

    const content = response.content[0].text;
    const design = this.parseDesign(content);
    const validation = this.validateDesign(design);

    if (!validation.valid) {
      return {
        success: false,
        error: 'Design validation failed after retry',
        details: validation.errors
      };
    }

    return {
      success: true,
      data: design
    };
  }
}


