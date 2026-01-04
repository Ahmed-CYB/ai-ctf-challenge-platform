/**
 * Request Validator - Validates and classifies user requests
 * 
 * Responsibilities:
 * - Validate input format
 * - Classify request type (create, deploy, question, etc.)
 * - Extract requirements using AI context awareness
 * - Return structured validation result
 */

import { classify } from '../classifier.js';
import { contextAgent } from '../agents/context-agent.js';
import { osDetectionAgent } from '../agents/os-detection-agent.js';
import { Logger } from './logger.js';

export class RequestValidator {
  constructor() {
    this.logger = new Logger();
  }
  /**
   * Validate and classify a request
   */
  async validate(message, conversationHistory = []) {
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return {
        valid: false,
        error: 'Message is required and must be a non-empty string'
      };
    }

    // 🔒 AI-Powered OS Detection: Check if vulnerability is Windows-specific
    // This uses AI to intelligently detect Windows vulnerabilities, not just static patterns
    const osDetection = await osDetectionAgent.detectOS(message, conversationHistory);
    if (osDetection.isWindows) {
      this.logger.info('RequestValidator', 'Windows vulnerability detected by AI', {
        vulnerability: osDetection.vulnerability,
        cve: osDetection.cve,
        confidence: osDetection.confidence,
        reasoning: osDetection.reasoning
      });
      
      return {
        valid: false,
        error: 'Windows challenges are not supported',
        message: osDetection.message || 'Windows challenges are not supported. This platform only supports Linux-based challenges.',
        type: 'windows_not_supported',
        detection: {
          os: osDetection.os,
          confidence: osDetection.confidence,
          reasoning: osDetection.reasoning,
          vulnerability: osDetection.vulnerability,
          cve: osDetection.cve
        }
      };
    }

    // Classify the request
    const classification = await classify(message, conversationHistory);

    // Extract context using AI (for challenge names and intent)
    const context = await contextAgent.extractContext(message, conversationHistory);

    // Extract requirements based on classification and context
    const requirements = this.extractRequirements(message, classification, context);

    // Use context to override classification if needed
    let requestType = classification.category?.toLowerCase() || 'unknown';
    if (context.intent !== 'unknown' && (requestType === 'unknown' || context.confidence > 0.7)) {
      requestType = context.intent;
    }

    return {
      valid: true,
      type: requestType,
      category: classification.challengeType || null,
      requirements,
      classification,
      context
    };
  }

  /**
   * Extract requirements from message, classification, and AI context
   */
  extractRequirements(message, classification, context = {}) {
    const messageLower = message.toLowerCase();
    const requestType = classification.category?.toLowerCase() || context.intent || 'unknown';
    
    // Extract challenge name - prioritize in this order:
    // 1. Explicitly mentioned in current message
    // 2. From AI context extraction (from conversation history)
    // 3. From classification
    // 4. From message parsing
    let challengeName = this.extractChallengeNameFromMessage(message) || 
                       context.challengeName || 
                       classification.challengeName || 
                       null;
    
    // If deploy/run request and no challenge name, try context again
    if ((requestType === 'deploy' || requestType === 'run' || messageLower.startsWith('deploy') || messageLower.startsWith('run')) && !challengeName) {
      // Context agent should have found it, but try one more time
      if (context.challengeName) {
        challengeName = context.challengeName;
      } else {
        challengeName = this.extractChallengeNameFromMessage(message);
      }
    }
    
    const requirements = {
      challengeName,
      challengeType: classification.challengeType || null,
      difficulty: this.extractDifficulty(messageLower),
      services: this.extractServices(messageLower),
      scenario: this.extractScenario(message),
      machines: this.extractMachineCount(messageLower)
    };

    return requirements;
  }

  /**
   * Extract challenge name from deployment message
   * Examples: "deploy corporate-ftp-breach" -> "corporate-ftp-breach"
   *           "run corporate-ftp-breach" -> "corporate-ftp-breach"
   *           "deploy it" -> null (needs context - handled by AI)
   */
  extractChallengeNameFromMessage(message) {
    const messageLower = message.toLowerCase().trim();
    
    // Patterns: "deploy <challenge-name>", "run <challenge-name>", "start <challenge-name>"
    const patterns = [
      /(?:deploy|run|start)\s+(.+?)(?:\s|$)/,
      /(?:deploy|run|start)\s+([a-z0-9-]+)/i
    ];
    
    for (const pattern of patterns) {
      const match = messageLower.match(pattern);
      if (match && match[1]) {
        const challengeName = match[1].trim();
        // Filter out common words that aren't challenge names
        const skipWords = ['it', 'the', 'challenge', 'this', 'that', 'last', 'recent', 'now', 'please'];
        if (!skipWords.includes(challengeName) && challengeName.length > 2) {
          return challengeName;
        }
      }
    }
    
    // Try to find kebab-case challenge name anywhere in message
    const kebabCaseMatch = message.match(/([a-z0-9]+(?:-[a-z0-9]+)+)/i);
    if (kebabCaseMatch && kebabCaseMatch[1]) {
      return kebabCaseMatch[1];
    }
    
    return null;
  }

  /**
   * Extract difficulty level from message
   */
  extractDifficulty(message) {
    if (message.includes('easy') || message.includes('beginner')) {
      return 'easy';
    }
    if (message.includes('hard') || message.includes('advanced') || message.includes('expert')) {
      return 'hard';
    }
    return 'medium'; // default
  }

  /**
   * Extract services from message
   */
  extractServices(message) {
    const services = [];
    const messageLower = message.toLowerCase();
    
    // Check for specific vulnerabilities first (they map to services)
    if (messageLower.includes('eternal blue') || 
        messageLower.includes('eternalblue') || 
        messageLower.includes('ms17-010') ||
        messageLower.includes('ms17_010') ||
        messageLower.includes('cve-2017-0144') ||
        messageLower.includes('cve-2017-0145')) {
      services.push('samba'); // EternalBlue is SMB/Samba vulnerability
    }
    
    const serviceKeywords = {
      'ftp': ['ftp', 'file transfer'],
      'ssh': ['ssh', 'secure shell'],
      'samba': ['samba', 'smb', 'samba server', 'smb server'],
      'http': ['http', 'web', 'website'],
      'https': ['https', 'ssl', 'tls'],
      'telnet': ['telnet'],
      'mysql': ['mysql', 'database', 'db'],
      'postgresql': ['postgres', 'postgresql']
    };

    for (const [service, keywords] of Object.entries(serviceKeywords)) {
      if (keywords.some(keyword => messageLower.includes(keyword))) {
        // Don't add duplicate
        if (!services.includes(service)) {
          services.push(service);
        }
      }
    }

    return services.length > 0 ? services : null;
  }

  /**
   * Extract scenario description from message
   */
  extractScenario(message) {
    // Look for scenario indicators
    if (message.includes('scenario') || message.includes('story') || message.includes('company')) {
      // Return the full message as scenario context
      return message;
    }
    return null;
  }

  /**
   * Extract machine count from message
   */
  extractMachineCount(message) {
    const countMatch = message.match(/(\d+)\s*(machine|victim|server|container)/i);
    if (countMatch) {
      return parseInt(countMatch[1]);
    }
    return 1; // default: 1 victim machine
  }

  /**
   * Check if the request is for a Windows-specific vulnerability
   * Returns object with isWindowsVuln flag and user-friendly message
   */
  checkWindowsVulnerability(message) {
    // Normalize message: remove spaces, hyphens, underscores for better matching
    const messageLower = message.toLowerCase();
    const normalizedMessage = messageLower.replace(/[\s\-_]/g, ''); // Remove spaces, hyphens, underscores
    
    // Windows-specific vulnerabilities with all variations
    const windowsVulns = {
      'bluekeep': {
        variations: ['bluekeep', 'blue keep', 'blue-keep', 'blue_keep'],
        cve: 'CVE-2019-0708',
        name: 'BlueKeep',
        service: 'RDP (Remote Desktop Protocol)',
        description: 'BlueKeep is a critical Windows RDP vulnerability that affects Windows systems. This platform only supports Linux-based challenges.'
      },
      'printnightmare': {
        variations: ['printnightmare', 'print nightmare', 'print-nightmare', 'print_nightmare'],
        cve: 'CVE-2021-1675, CVE-2021-34527',
        name: 'PrintNightmare',
        service: 'Windows Print Spooler',
        description: 'PrintNightmare is a Windows Print Spooler vulnerability. This platform only supports Linux-based challenges.'
      },
      'zerologon': {
        variations: ['zerologon', 'zero logon', 'zero-logon', 'zero_logon'],
        cve: 'CVE-2020-1472',
        name: 'Zerologon',
        service: 'Netlogon',
        description: 'Zerologon is a Windows Netlogon vulnerability. This platform only supports Linux-based challenges.'
      },
      'ms08-067': {
        variations: ['ms08-067', 'ms08 067', 'ms08067', 'ms08_067'],
        cve: 'MS08-067',
        name: 'Windows Server Service RPC',
        service: 'Windows SMB',
        description: 'MS08-067 is a Windows SMB vulnerability. This platform only supports Linux-based challenges (Samba).'
      },
      'eternalromance': {
        variations: ['eternalromance', 'eternal romance', 'eternal-romance', 'eternal_romance'],
        cve: 'CVE-2017-0145',
        name: 'EternalRomance',
        service: 'Windows SMB',
        description: 'EternalRomance is a Windows SMB vulnerability. This platform only supports Linux-based challenges (Samba).'
      },
      'eternalchampion': {
        variations: ['eternalchampion', 'eternal champion', 'eternal-champion', 'eternal_champion'],
        cve: 'CVE-2017-0146',
        name: 'EternalChampion',
        service: 'Windows SMB',
        description: 'EternalChampion is a Windows SMB vulnerability. This platform only supports Linux-based challenges (Samba).'
      }
    };

    // Check for Windows-specific vulnerability mentions
    for (const [key, vuln] of Object.entries(windowsVulns)) {
      // Check normalized message (handles spaces, hyphens, underscores)
      const normalizedKey = key.replace(/[\s\-_]/g, '');
      if (normalizedMessage.includes(normalizedKey)) {
        return {
          isWindowsVuln: true,
          message: `❌ Windows challenges are not supported\n\n` +
                   `The vulnerability "${vuln.name}" (${vuln.cve}) is a Windows-specific vulnerability affecting ${vuln.service}.\n\n` +
                   `**This platform only supports Linux-based challenges.**\n\n` +
                   `**Alternative suggestions:**\n` +
                   `• For SMB vulnerabilities: Try "EternalBlue" or "Samba" challenges (Linux SMB)\n` +
                   `• For other network challenges: Try FTP, SSH, or other Linux services\n\n` +
                   `Would you like to create a Linux-based challenge instead?`
        };
      }
      
      // Check variations explicitly
      for (const variation of vuln.variations) {
        if (messageLower.includes(variation)) {
          return {
            isWindowsVuln: true,
            message: `❌ Windows challenges are not supported\n\n` +
                     `The vulnerability "${vuln.name}" (${vuln.cve}) is a Windows-specific vulnerability affecting ${vuln.service}.\n\n` +
                     `**This platform only supports Linux-based challenges.**\n\n` +
                     `**Alternative suggestions:**\n` +
                     `• For SMB vulnerabilities: Try "EternalBlue" or "Samba" challenges (Linux SMB)\n` +
                     `• For other network challenges: Try FTP, SSH, or other Linux services\n\n` +
                     `Would you like to create a Linux-based challenge instead?`
          };
        }
      }
      
      // Check CVE and name
      if (messageLower.includes(vuln.cve.toLowerCase()) ||
          messageLower.includes(vuln.name.toLowerCase())) {
        return {
          isWindowsVuln: true,
          message: `❌ Windows challenges are not supported\n\n` +
                   `The vulnerability "${vuln.name}" (${vuln.cve}) is a Windows-specific vulnerability affecting ${vuln.service}.\n\n` +
                   `**This platform only supports Linux-based challenges.**\n\n` +
                   `**Alternative suggestions:**\n` +
                   `• For SMB vulnerabilities: Try "EternalBlue" or "Samba" challenges (Linux SMB)\n` +
                   `• For other network challenges: Try FTP, SSH, or other Linux services\n\n` +
                   `Would you like to create a Linux-based challenge instead?`
        };
      }
    }

    // Check for Windows OS mentions
    const windowsKeywords = [
      'windows', 'win32', 'win64', 'microsoft windows',
      'active directory', 'ad', 'domain controller',
      'rdp', 'remote desktop', 'terminal services',
      'windows server', 'windows 10', 'windows 11',
      'powershell', 'cmd.exe', 'iis', 'internet information services'
    ];

    // Only flag as Windows if it's clearly about Windows vulnerabilities/challenges
    // Not just casual mentions
    const windowsContext = [
      'windows vulnerability', 'windows exploit', 'windows ctf',
      'windows challenge', 'windows vuln', 'windows cve',
      'rdp vulnerability', 'rdp exploit', 'rdp challenge',
      'active directory vulnerability', 'ad exploit', 'ad challenge'
    ];

    for (const context of windowsContext) {
      if (messageLower.includes(context)) {
        return {
          isWindowsVuln: true,
          message: `❌ Windows challenges are not supported\n\n` +
                   `Your request mentions Windows-specific vulnerabilities or challenges.\n\n` +
                   `**This platform only supports Linux-based challenges.**\n\n` +
                   `**Alternative suggestions:**\n` +
                   `• For SMB vulnerabilities: Try "EternalBlue" or "Samba" challenges (Linux SMB)\n` +
                   `• For network challenges: Try FTP, SSH, or other Linux services\n` +
                   `• For web challenges: Try Linux-based web servers (Apache, Nginx)\n\n` +
                   `Would you like to create a Linux-based challenge instead?`
        };
      }
    }

    return {
      isWindowsVuln: false,
      message: null
    };
  }
}


