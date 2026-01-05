/**
 * Vulhub Template Manager
 * Manages Vulhub templates and adapts them for CTF challenges
 * Adjusts flags, configurations, and ensures Guacamole compatibility
 */

import { Logger } from '../core/logger.js';
import { vulhubFetcher } from './vulhub-fetcher.js';
import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

export class VulhubTemplateManager {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Get and adapt a Vulhub template for a challenge
   * @param {Object} requirements - Challenge requirements
   * @param {string} serviceType - Service type (ftp, samba, etc.)
   * @param {string} vulnerability - Optional vulnerability name
   * @returns {Object} Adapted template with Dockerfile, docker-compose, and configs
   */
  async getAdaptedTemplate(requirements, serviceType, vulnerability = null) {
    try {
      this.logger.info('VulhubTemplateManager', 'Fetching Vulhub template', { serviceType, vulnerability });

      // Fetch Vulhub example
      const vulhubExample = await vulhubFetcher.getBestExample(serviceType, vulnerability);

      if (!vulhubExample) {
        this.logger.warn('VulhubTemplateManager', 'No Vulhub example found, using AI generation', { serviceType });
        return null;
      }

      this.logger.success('VulhubTemplateManager', 'Found Vulhub example', { name: vulhubExample.name });

      // Adapt template using AI
      const adapted = await this.adaptTemplate(vulhubExample, requirements, serviceType);

      return adapted;

    } catch (error) {
      this.logger.error('VulhubTemplateManager', 'Failed to get adapted template', error.stack);
      return null;
    }
  }

  /**
   * Adapt Vulhub template for CTF challenge
   * AI adjusts flags, configurations, and ensures compatibility
   */
  async adaptTemplate(vulhubExample, requirements, serviceType) {
    try {
      const prompt = this.buildAdaptationPrompt(vulhubExample, requirements, serviceType);

      const response = await anthropic.messages.create({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
        max_tokens: 4000,
        temperature: 0.7,
        messages: [{
          role: 'user',
          content: prompt
        }]
      });

      const content = response.content[0].text;
      
      // Parse JSON response
      const jsonMatch = content.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
      const jsonString = jsonMatch ? jsonMatch[1] : content;
      const jsonObjectMatch = jsonString.match(/\{[\s\S]*\}/);
      
      if (jsonObjectMatch) {
        const adapted = JSON.parse(jsonObjectMatch[0]);
        
        // Merge with original Vulhub files
        return {
          ...adapted,
          originalVulhub: {
            name: vulhubExample.name,
            path: vulhubExample.path
          }
        };
      }

      throw new Error('Failed to parse adapted template');

    } catch (error) {
      this.logger.error('VulhubTemplateManager', 'Failed to adapt template', error.stack);
      // Fallback: return original with minimal modifications
      return this.fallbackAdaptation(vulhubExample, requirements);
    }
  }

  /**
   * Build prompt for AI adaptation
   */
  buildAdaptationPrompt(vulhubExample, requirements, serviceType) {
    let prompt = `You are adapting a Vulhub vulnerable environment template for a CTF challenge.

VULHUB TEMPLATE:
Name: ${vulhubExample.name}
Path: ${vulhubExample.path}

ORIGINAL DOCKERFILE:
\`\`\`
${vulhubExample.dockerfile || 'Not available'}
\`\`\`

ORIGINAL DOCKER-COMPOSE.YML:
\`\`\`
${vulhubExample.dockerCompose || 'Not available'}
\`\`\`

CONFIG FILES:
${vulhubExample.configFiles.map(f => `\n${f.name}:\n\`\`\`\n${f.content}\n\`\`\``).join('\n')}

CHALLENGE REQUIREMENTS:
${JSON.stringify(requirements, null, 2)}

SERVICE TYPE: ${serviceType}

TASK:
1. **Keep the working Vulhub configuration** - Don't break what works!
2. **Add CTF-specific elements**:
   - Generate a unique flag: CTF{descriptive_flag_name_here}
   - Place flag in appropriate location (based on service type)
   - Ensure flag is accessible through the vulnerability
3. **Adjust configurations**:
   - Keep all working service configurations
   - Add any user-specified requirements
   - Ensure services start correctly
4. **Ensure Guacamole compatibility**:
   - Attacker container must have SSH enabled (port 22)
   - SSH user: kali, password: kali
   - Container must stay running
5. **Maintain Linux-only**:
   - All containers must use Linux base images
   - No Windows-specific configurations

CRITICAL RULES:
- ✅ KEEP all working Vulhub configurations
- ✅ ADD flag placement and access
- ✅ ENSURE services start properly
- ✅ MAINTAIN Dockerfile and docker-compose structure
- ❌ DON'T remove working configurations
- ❌ DON'T break service startup commands
- ❌ DON'T use Windows images

Return JSON with:
{
  "dockerfile": "adapted Dockerfile content",
  "dockerCompose": "adapted docker-compose.yml content",
  "configFiles": [
    {
      "name": "config-file-name",
      "content": "config content",
      "path": "relative/path/to/file"
    }
  ],
  "flag": "CTF{descriptive_flag_name}",
  "flagLocation": "/path/to/flag",
  "setup": "commands to start services and place flag",
  "notes": "any important notes about the adaptation"
}`;

    return prompt;
  }

  /**
   * Fallback adaptation if AI fails
   */
  fallbackAdaptation(vulhubExample, requirements) {
    // Generate a simple flag
    const flag = `CTF{${vulhubExample.name.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}}`;

    // Minimal modifications to original
    let dockerfile = vulhubExample.dockerfile || '';
    let dockerCompose = vulhubExample.dockerCompose || '';

    // Add flag placement to Dockerfile if not present
    if (dockerfile && !dockerfile.includes('flag')) {
      const flagLocation = this.getDefaultFlagLocation(requirements.serviceType || 'network');
      dockerfile += `\n\n# CTF Flag\nRUN echo "${flag}" > ${flagLocation}\n`;
    }

    return {
      dockerfile,
      dockerCompose,
      configFiles: vulhubExample.configFiles,
      flag,
      flagLocation: this.getDefaultFlagLocation(requirements.serviceType || 'network'),
      setup: this.getDefaultSetup(requirements.serviceType || 'network'),
      notes: 'Minimal adaptation - using original Vulhub configuration'
    };
  }

  /**
   * Get default flag location based on service type
   */
  getDefaultFlagLocation(serviceType) {
    const locations = {
      'ftp': '/var/ftp/data/flag.txt',
      'samba': '/tmp/share/flag.txt',
      'smb': '/tmp/share/flag.txt',
      'http': '/var/www/html/flag.txt',
      'web': '/var/www/html/flag.txt',
      'ssh': '/root/flag.txt'
    };

    return locations[serviceType.toLowerCase()] || '/root/flag.txt';
  }

  /**
   * Get default setup commands
   */
  getDefaultSetup(serviceType) {
    const setups = {
      'ftp': 'service vsftpd start || /usr/sbin/vsftpd /etc/vsftpd.conf &',
      'samba': '/usr/sbin/smbd -D & /usr/sbin/nmbd -D &',
      'smb': '/usr/sbin/smbd -D & /usr/sbin/nmbd -D &',
      'http': 'service apache2 start || /usr/sbin/apache2ctl -D FOREGROUND &',
      'web': 'service apache2 start || /usr/sbin/apache2ctl -D FOREGROUND &',
      'ssh': '/usr/sbin/sshd -D &'
    };

    return setups[serviceType.toLowerCase()] || 'echo "Service started"';
  }
}

export const vulhubTemplateManager = new VulhubTemplateManager();

