/**
 * OS Detection Agent - AI-powered detection of Windows vs Linux vulnerabilities
 * 
 * Uses AI to intelligently determine if a vulnerability is Windows-specific,
 * Linux-specific, or platform-agnostic. This replaces static pattern matching
 * to handle any vulnerability, not just hardcoded ones.
 */

import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';
import { Logger } from '../core/logger.js';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const OS_DETECTION_SYSTEM_PROMPT = `You are an expert cybersecurity vulnerability analyst specializing in operating system-specific vulnerabilities.

Your task is to analyze a user's CTF challenge request and determine if the vulnerability they're requesting is:
1. **Windows-specific** - Only affects Windows operating systems
2. **Linux-specific** - Only affects Linux/Unix operating systems  
3. **Platform-agnostic** - Works on both or is OS-independent

**CRITICAL RULES:**
- Windows vulnerabilities include: BlueKeep (CVE-2019-0708), PrintNightmare, Zerologon, MS08-067, Windows SMB exploits, RDP vulnerabilities, Active Directory exploits, PowerShell exploits, Windows-specific buffer overflows
- Linux vulnerabilities include: Linux kernel exploits, Samba (Linux SMB), Linux-specific privilege escalation, Linux service exploits
- Platform-agnostic: SQL injection, XSS, general web vulnerabilities, network protocols (FTP, SSH, Telnet), cryptography challenges

**IMPORTANT:**
- If a vulnerability is Windows-specific, return "windows" and provide a clear explanation
- If a vulnerability is Linux-specific or platform-agnostic, return "linux" or "agnostic"
- Be thorough - consider CVE numbers, service names, protocol details, and exploit techniques
- If uncertain, err on the side of caution and provide detailed reasoning

**OUTPUT FORMAT (JSON):**
{
  "os": "windows" | "linux" | "agnostic" | "unknown",
  "confidence": 0.0-1.0,
  "reasoning": "Detailed explanation of why this vulnerability is Windows/Linux/agnostic",
  "vulnerability": "Name of the vulnerability if identified",
  "cve": "CVE number if mentioned",
  "services": ["service1", "service2"],
  "alternative": "Suggested Linux alternative if Windows" | null
}

**EXAMPLES:**

User: "create bluekeep vulnerability challenge"
Response:
{
  "os": "windows",
  "confidence": 0.98,
  "reasoning": "BlueKeep (CVE-2019-0708) is a critical Windows RDP vulnerability that specifically affects Windows 7, Windows Server 2008 R2, and other Windows versions. It does not affect Linux systems.",
  "vulnerability": "BlueKeep",
  "cve": "CVE-2019-0708",
  "services": ["rdp"],
  "alternative": "EternalBlue (Samba on Linux) or other Linux SMB vulnerabilities"
}

User: "create eternal blue vulnerability challenge"
Response:
{
  "os": "linux",
  "confidence": 0.95,
  "reasoning": "EternalBlue (MS17-010) can refer to Windows SMB exploit, but in CTF context on Linux platforms, this typically means Samba (Linux SMB) vulnerabilities. The platform only supports Linux, so this should be implemented as a Samba challenge.",
  "vulnerability": "EternalBlue",
  "cve": "CVE-2017-0144",
  "services": ["samba", "smb"],
  "alternative": null
}

User: "create sql injection challenge"
Response:
{
  "os": "agnostic",
  "confidence": 0.99,
  "reasoning": "SQL injection is a web application vulnerability that is platform-agnostic. It works regardless of the underlying operating system (Windows, Linux, etc.).",
  "vulnerability": "SQL Injection",
  "cve": null,
  "services": ["http", "database"],
  "alternative": null
}

User: "create ftp challenge"
Response:
{
  "os": "agnostic",
  "confidence": 0.90,
  "reasoning": "FTP (File Transfer Protocol) is a network protocol that works on both Windows and Linux. FTP vulnerabilities like anonymous access or weak credentials are platform-agnostic.",
  "vulnerability": null,
  "cve": null,
  "services": ["ftp"],
  "alternative": null
}`;

export class OSDetectionAgent {
  constructor() {
    this.logger = new Logger();
    this.model = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514';
  }

  /**
   * Detect if a vulnerability is Windows-specific using AI
   * @param {string} message - User's request message
   * @param {Array} conversationHistory - Conversation history for context
   * @returns {Promise<object>} Detection result with OS type and reasoning
   */
  async detectOS(message, conversationHistory = []) {
    try {
      // Build context from conversation history
      let contextText = '';
      if (conversationHistory && conversationHistory.length > 0) {
        const recentHistory = conversationHistory.slice(-5);
        contextText = recentHistory.map(msg => {
          const role = msg.role === 'user' ? 'User' : 'Assistant';
          const content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
          return `${role}: ${content}`;
        }).join('\n');
      }

      const prompt = `Analyze this CTF challenge request and determine if the vulnerability is Windows-specific, Linux-specific, or platform-agnostic:

User Request: "${message}"

${contextText ? `\nConversation Context:\n${contextText}` : ''}

Determine the operating system requirement for this vulnerability. Return JSON only.`;

      const response = await anthropic.messages.create({
        model: this.model,
        max_tokens: 500,
        temperature: 0.1, // Low temperature for consistent detection
        system: OS_DETECTION_SYSTEM_PROMPT,
        messages: [
          {
            role: 'user',
            content: prompt
          }
        ]
      });

      const content = response.content[0];
      if (content.type === 'text') {
        const text = content.text.trim();
        
        // Extract JSON from response
        let jsonText = text;
        const jsonMatch = text.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
        if (jsonMatch) {
          jsonText = jsonMatch[1];
        } else {
          const braceMatch = text.match(/\{[\s\S]*\}/);
          if (braceMatch) {
            jsonText = braceMatch[0];
          }
        }

        const result = JSON.parse(jsonText);
        
        // Normalize OS value
        const os = result.os?.toLowerCase();
        if (os === 'windows') {
          return {
            isWindows: true,
            os: 'windows',
            confidence: result.confidence || 0.8,
            reasoning: result.reasoning || 'AI detected Windows-specific vulnerability',
            vulnerability: result.vulnerability || null,
            cve: result.cve || null,
            services: result.services || [],
            alternative: result.alternative || null,
            message: this.buildRejectionMessage(result)
          };
        } else {
          return {
            isWindows: false,
            os: os || 'agnostic',
            confidence: result.confidence || 0.8,
            reasoning: result.reasoning || 'AI determined this is not Windows-specific',
            vulnerability: result.vulnerability || null,
            cve: result.cve || null,
            services: result.services || []
          };
        }
      }

      // Fallback
      return {
        isWindows: false,
        os: 'unknown',
        confidence: 0.3,
        reasoning: 'Failed to parse AI response',
        message: null
      };

    } catch (error) {
      this.logger.error('OSDetectionAgent', 'AI detection failed', error.stack);
      
      // Fallback to static check if AI fails
      return {
        isWindows: false,
        os: 'unknown',
        confidence: 0.3,
        reasoning: `AI detection failed: ${error.message}. Using fallback.`,
        message: null
      };
    }
  }

  /**
   * Build user-friendly rejection message
   */
  buildRejectionMessage(detection) {
    const vulnName = detection.vulnerability || 'this vulnerability';
    const cve = detection.cve ? ` (${detection.cve})` : '';
    const services = detection.services && detection.services.length > 0 
      ? ` affecting ${detection.services.join(', ')}` 
      : '';
    
    let message = `❌ Windows challenges are not supported\n\n`;
    message += `The vulnerability "${vulnName}"${cve} is a Windows-specific vulnerability${services}.\n\n`;
    message += `**This platform only supports Linux-based challenges.**\n\n`;
    
    if (detection.alternative) {
      message += `**Alternative suggestion:**\n`;
      message += `• ${detection.alternative}\n\n`;
    } else {
      message += `**Alternative suggestions:**\n`;
      message += `• For SMB vulnerabilities: Try "EternalBlue" or "Samba" challenges (Linux SMB)\n`;
      message += `• For network challenges: Try FTP, SSH, or other Linux services\n`;
      message += `• For web challenges: Try Linux-based web servers (Apache, Nginx)\n\n`;
    }
    
    message += `Would you like to create a Linux-based challenge instead?`;
    
    return message;
  }
}

export const osDetectionAgent = new OSDetectionAgent();

