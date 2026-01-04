/**
 * Pre-Deployment Validator - Validates configurations before deployment
 * 
 * Responsibilities:
 * - Validate all files before deployment
 * - Check syntax correctness
 * - Verify completeness
 * - Auto-fix common issues
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import yaml from 'js-yaml';
import { Logger } from '../core/logger.js';
import { FixEngine } from './fix-engine.js';

// Get project root directory (3 levels up from this file: src/validation/ -> src/ -> packages/ctf-automation/ -> packages/ -> project root)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

export class PreDeployValidator {
  constructor() {
    this.logger = new Logger();
    this.fixEngine = new FixEngine();
  }

  /**
   * Validate challenge before deployment
   */
  async validateChallenge(challengeName) {
    try {
      this.logger.info('PreDeployValidator', 'Validating challenge', { challengeName });

      const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
      
      // Check if challenge exists
      try {
        await fs.access(challengePath);
      } catch {
        return {
          success: false,
          error: 'Challenge not found',
          details: `Challenge directory does not exist: ${challengePath}`
        };
      }

      // Validate docker-compose.yml
      const composeValidation = await this.validateCompose(challengePath);
      if (!composeValidation.valid) {
        return {
          success: false,
          error: 'docker-compose.yml validation failed',
          details: composeValidation.errors
        };
      }

      // Validate Dockerfiles
      const dockerfileValidation = await this.validateDockerfiles(challengePath);
      if (!dockerfileValidation.valid) {
        return {
          success: false,
          error: 'Dockerfile validation failed',
          details: dockerfileValidation.errors
        };
      }

      this.logger.success('PreDeployValidator', 'Challenge validated successfully', { challengeName });

      return {
        success: true
      };

    } catch (error) {
      this.logger.error('PreDeployValidator', 'Validation failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Validate structure data
   */
  async validate(structure) {
    try {
      this.logger.info('PreDeployValidator', 'Validating structure');

      const errors = [];

      // Validate structure completeness
      if (!structure.name) errors.push('Missing challenge name');
      if (!structure.subnet) errors.push('Missing subnet');
      if (!structure.machines || structure.machines.length === 0) {
        errors.push('No machines defined');
      }

      // Validate each machine
      for (const machine of structure.machines || []) {
        if (!machine.name) errors.push(`Machine missing name`);
        if (!machine.ip) errors.push(`Machine ${machine.name} missing IP`);
        if (!machine.os) errors.push(`Machine ${machine.name} missing OS`);
        if (machine.role === 'victim' && (!machine.services || machine.services.length === 0)) {
          errors.push(`Victim machine ${machine.name} has no services`);
        }
      }

      if (errors.length > 0) {
        return {
          success: false,
          errors
        };
      }

      return {
        success: true
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Validate docker-compose.yml
   */
  async validateCompose(challengePath) {
    const composePath = path.join(challengePath, 'docker-compose.yml');
    
    try {
      const content = await fs.readFile(composePath, 'utf8');
      
      // Parse YAML
      try {
        const compose = yaml.load(content);
        
        // Validate structure
        if (!compose.services) {
          return { valid: false, errors: ['No services defined'] };
        }

        if (!compose.networks) {
          return { valid: false, errors: ['No networks defined'] };
        }

        return { valid: true };

      } catch (yamlError) {
        return {
          valid: false,
          errors: [`YAML syntax error: ${yamlError.message}`]
        };
      }

    } catch (error) {
      return {
        valid: false,
        errors: [`Failed to read docker-compose.yml: ${error.message}`]
      };
    }
  }

  /**
   * Validate Dockerfiles
   */
  async validateDockerfiles(challengePath) {
    const errors = [];

    try {
      const entries = await fs.readdir(challengePath, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isDirectory()) {
          const dockerfilePath = path.join(challengePath, entry.name, 'Dockerfile');
          
          try {
            await fs.access(dockerfilePath);
            const content = await fs.readFile(dockerfilePath, 'utf8');
            
            // Basic validation
            if (!content.includes('FROM')) {
              errors.push(`Dockerfile in ${entry.name} missing FROM instruction`);
            }

            if (!content.includes('CMD') && !content.includes('ENTRYPOINT')) {
              errors.push(`Dockerfile in ${entry.name} missing CMD or ENTRYPOINT`);
            }

          } catch {
            // Dockerfile doesn't exist - that's OK if it's not a machine directory
            continue;
          }
        }
      }

      return {
        valid: errors.length === 0,
        errors
      };

    } catch (error) {
      return {
        valid: false,
        errors: [`Failed to validate Dockerfiles: ${error.message}`]
      };
    }
  }

  /**
   * Auto-fix issues
   */
  async autoFix(errors) {
    try {
      this.logger.info('PreDeployValidator', 'Auto-fixing issues', { errorCount: errors.length });

      const fixes = [];

      for (const error of errors) {
        const fix = await this.fixEngine.fix(error);
        if (fix.fixed) {
          fixes.push(fix);
        }
      }

      return {
        success: fixes.length > 0,
        fixes
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}


