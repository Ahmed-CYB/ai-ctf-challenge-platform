/**
 * Deployment Error Fixer - AI-powered error analysis and fixing
 * 
 * Analyzes Docker deployment errors and attempts to fix them automatically
 */

import Anthropic from '@anthropic-ai/sdk';
import { execSync } from 'child_process';
import { Logger } from '../core/logger.js';
import dotenv from 'dotenv';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const logger = new Logger();

const SYSTEM_PROMPT = `You are a Docker deployment error analysis and fixing agent. Your job is to analyze Docker deployment errors and provide specific fixes.

**ERROR ANALYSIS:**
1. Read the error message carefully
2. Identify the root cause (network overlap, port conflict, missing file, etc.)
3. Determine if it's fixable automatically
4. Provide specific commands or configuration changes to fix it

**COMMON ERRORS AND FIXES:**

1. **Network Subnet Overlap:**
   Error: "Pool overlaps with other one on this address space"
   Fix: 
   - Remove the conflicting network: docker network rm <network-name>
   - Or allocate a different subnet that doesn't overlap
   - Check for existing networks: docker network ls

2. **Network Already Exists:**
   Error: "network with name X already exists"
   Fix:
   - Remove existing network: docker network rm <network-name>
   - Or use a different network name

3. **Port Already in Use:**
   Error: "port is already allocated" or "bind: address already in use"
   Fix:
   - Find process using port: netstat -ano | findstr :<port> (Windows) or lsof -i :<port> (Linux)
   - Stop the process or change the port in docker-compose.yml

4. **Missing Dockerfile:**
   Error: "failed to solve: failed to read dockerfile"
   Fix:
   - Check if Dockerfile exists in the service directory
   - Verify the build context path in docker-compose.yml

5. **Invalid YAML:**
   Error: "yaml: invalid" or "yaml: line X"
   Fix:
   - Check YAML syntax (indentation, quotes, etc.)
   - Validate with a YAML parser

**OUTPUT FORMAT:**
Return JSON:
{
  "fixable": true|false,
  "errorType": "network_overlap" | "port_conflict" | "missing_file" | "yaml_error" | "unknown",
  "fixes": [
    {
      "action": "remove_network" | "change_subnet" | "remove_port" | "fix_yaml" | "custom",
      "description": "What this fix does",
      "command": "exact command to run (if applicable)",
      "file": "file to modify (if applicable)",
      "change": "what to change in the file (if applicable)"
    }
  ],
  "confidence": 0.0-1.0,
  "reasoning": "Why this error occurred and how the fix will resolve it"
}

**IMPORTANT:**
- Only suggest fixes that are safe and reversible
- Always check if resources exist before removing them
- Prefer fixing configuration over removing resources when possible
- Be specific with commands and file paths`;

export class DeploymentErrorFixer {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Analyze error and suggest fixes
   */
  async analyzeAndFix(error, challengeName, challengePath) {
    try {
      this.logger.info('DeploymentErrorFixer', 'Analyzing deployment error', {
        error: error.message?.substring(0, 200),
        challengeName
      });

      // Extract error details
      const errorMessage = error.message || error.toString();
      const stdout = error.stdout || '';
      const stderr = error.stderr || '';

      // Build context for AI
      const context = {
        errorMessage,
        stdout: stdout.substring(0, 1000),
        stderr: stderr.substring(0, 1000),
        challengeName,
        challengePath
      };

      // Ask AI to analyze and suggest fixes
      const response = await anthropic.messages.create({
        model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514',
        max_tokens: 2000,
        temperature: 0.3,
        system: SYSTEM_PROMPT,
        messages: [{
          role: 'user',
          content: `Analyze this Docker deployment error and suggest fixes:

Error: ${errorMessage}
Stdout: ${context.stdout}
Stderr: ${context.stderr}
Challenge: ${challengeName}
Path: ${challengePath}

Provide fixes in JSON format as specified.`
        }]
      });

      const analysisText = response.content[0].text.trim();
      
      // Parse JSON from response (might be wrapped in markdown)
      let analysis;
      try {
        // Try to extract JSON from markdown code blocks
        const jsonMatch = analysisText.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
        if (jsonMatch) {
          analysis = JSON.parse(jsonMatch[1]);
        } else {
          // Try parsing the whole response as JSON
          analysis = JSON.parse(analysisText);
        }
      } catch (parseError) {
        this.logger.warn('DeploymentErrorFixer', 'Failed to parse AI response as JSON', {
          response: analysisText.substring(0, 200),
          error: parseError.message
        });
        // Fallback: try to extract key information from text
        analysis = this.extractFixesFromText(analysisText, errorMessage);
      }

      if (!analysis.fixable) {
        return {
          fixed: false,
          reason: analysis.reasoning || 'Error not automatically fixable'
        };
      }

      // Apply fixes
      const fixResults = await this.applyFixes(analysis.fixes, challengeName, challengePath);

      return {
        fixed: fixResults.every(r => r.success),
        fixes: fixResults,
        analysis
      };

    } catch (error) {
      this.logger.error('DeploymentErrorFixer', 'Error analysis failed', error.stack);
      return {
        fixed: false,
        reason: 'Error analysis failed: ' + error.message
      };
    }
  }

  /**
   * Apply suggested fixes
   */
  async applyFixes(fixes, challengeName, challengePath) {
    const results = [];

    for (const fix of fixes) {
      try {
        switch (fix.action) {
          case 'remove_network':
            if (fix.command) {
              try {
                execSync(fix.command, { stdio: 'ignore' });
                this.logger.info('DeploymentErrorFixer', 'Removed network', { command: fix.command });
                results.push({ success: true, action: fix.action, description: fix.description });
              } catch (cmdError) {
                // Network might not exist, that's okay
                this.logger.debug('DeploymentErrorFixer', 'Network removal command failed (may not exist)', {
                  command: fix.command,
                  error: cmdError.message
                });
                results.push({ success: true, action: fix.action, description: 'Network already removed or doesn\'t exist' });
              }
            }
            break;

          case 'change_subnet':
            // This is handled by revalidateIPAllocation, so we just log it
            this.logger.info('DeploymentErrorFixer', 'Subnet change needed', { description: fix.description });
            results.push({ success: true, action: fix.action, description: fix.description });
            break;

          case 'fix_yaml':
            // Would need to modify docker-compose.yml, but this is complex
            // For now, just log it
            this.logger.warn('DeploymentErrorFixer', 'YAML fix needed but not implemented', { file: fix.file });
            results.push({ success: false, action: fix.action, description: 'YAML fixes require manual intervention' });
            break;

          case 'remove_orphaned_containers':
            try {
              // Find and remove containers that are stopped/exited
              const containers = execSync('docker ps -a --format "{{.Names}} {{.Status}}"', { encoding: 'utf8' });
              const containerList = containers.trim().split('\n').filter(line => {
                const parts = line.split(' ');
                const name = parts[0];
                const status = line.substring(name.length + 1);
                return name.includes(challengeName) && (status.includes('Exited') || status.includes('Dead'));
              });
              
              for (const line of containerList) {
                const containerName = line.split(' ')[0];
                try {
                  execSync(`docker rm -f ${containerName}`, { stdio: 'ignore' });
                  this.logger.info('DeploymentErrorFixer', 'Removed orphaned container', { containerName });
                } catch (rmError) {
                  // Continue with others
                }
              }
              results.push({ success: true, action: fix.action, description: `Removed ${containerList.length} orphaned containers` });
            } catch (error) {
              this.logger.warn('DeploymentErrorFixer', 'Failed to remove orphaned containers', { error: error.message });
              results.push({ success: false, action: fix.action, error: error.message });
            }
            break;

          case 'force_remove_containers':
            try {
              // Force remove all containers for this challenge
              const containers = execSync(`docker ps -a --filter "name=${challengeName}" --format "{{.Names}}"`, { encoding: 'utf8' });
              const containerList = containers.trim().split('\n').filter(n => n);
              
              for (const containerName of containerList) {
                try {
                  execSync(`docker rm -f ${containerName}`, { stdio: 'ignore' });
                  this.logger.info('DeploymentErrorFixer', 'Force removed container', { containerName });
                } catch (rmError) {
                  // Continue with others
                }
              }
              results.push({ success: true, action: fix.action, description: `Force removed ${containerList.length} containers` });
            } catch (error) {
              this.logger.warn('DeploymentErrorFixer', 'Failed to force remove containers', { error: error.message });
              results.push({ success: false, action: fix.action, error: error.message });
            }
            break;

          case 'remove_networks':
            try {
              // Remove all networks for this challenge
              const networks = execSync('docker network ls --format "{{.Name}}"', { encoding: 'utf8' });
              const networkList = networks.trim().split('\n').filter(n => n && n.includes(challengeName));
              
              for (const networkName of networkList) {
                try {
                  execSync(`docker network rm ${networkName}`, { stdio: 'ignore' });
                  this.logger.info('DeploymentErrorFixer', 'Removed network', { networkName });
                } catch (rmError) {
                  // Continue with others
                }
              }
              results.push({ success: true, action: fix.action, description: `Removed ${networkList.length} networks` });
            } catch (error) {
              this.logger.warn('DeploymentErrorFixer', 'Failed to remove networks', { error: error.message });
              results.push({ success: false, action: fix.action, error: error.message });
            }
            break;

          case 'clean_system':
            try {
              // Clean up Docker system (prune)
              execSync('docker system prune -f', { stdio: 'ignore' });
              this.logger.info('DeploymentErrorFixer', 'Cleaned Docker system');
              results.push({ success: true, action: fix.action, description: 'Cleaned Docker system' });
            } catch (error) {
              this.logger.warn('DeploymentErrorFixer', 'Failed to clean Docker system', { error: error.message });
              results.push({ success: false, action: fix.action, error: error.message });
            }
            break;

          case 'restart_deployment':
            // This is handled by the deployer retry logic, just log it
            this.logger.info('DeploymentErrorFixer', 'Restart deployment requested', { description: fix.description });
            results.push({ success: true, action: fix.action, description: fix.description });
            break;

          case 'custom':
            if (fix.command) {
              try {
                execSync(fix.command, { stdio: 'ignore', cwd: challengePath });
                this.logger.info('DeploymentErrorFixer', 'Executed custom fix', { command: fix.command });
                results.push({ success: true, action: fix.action, description: fix.description });
              } catch (cmdError) {
                this.logger.warn('DeploymentErrorFixer', 'Custom fix command failed', {
                  command: fix.command,
                  error: cmdError.message
                });
                results.push({ success: false, action: fix.action, description: fix.description, error: cmdError.message });
              }
            }
            break;

          default:
            this.logger.warn('DeploymentErrorFixer', 'Unknown fix action', { action: fix.action });
            results.push({ success: false, action: fix.action, description: 'Unknown action type' });
        }
      } catch (error) {
        this.logger.error('DeploymentErrorFixer', 'Error applying fix', {
          fix: fix.action,
          error: error.message
        });
        results.push({ success: false, action: fix.action, error: error.message });
      }
    }

    return results;
  }

  /**
   * Extract fixes from text response (fallback)
   */
  extractFixesFromText(text, errorMessage) {
    const fixes = [];
    
    // Check for common error patterns
    if (errorMessage.includes('Pool overlaps') || errorMessage.includes('overlaps with other')) {
      fixes.push({
        action: 'remove_network',
        description: 'Remove conflicting network',
        command: null // Will be determined by challenge name
      });
    }

    return {
      fixable: fixes.length > 0,
      errorType: 'network_overlap',
      fixes,
      confidence: 0.7,
      reasoning: 'Detected network overlap error'
    };
  }
}

export const deploymentErrorFixer = new DeploymentErrorFixer();

