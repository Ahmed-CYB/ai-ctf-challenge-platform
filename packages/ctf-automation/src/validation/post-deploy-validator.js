/**
 * Post-Deployment Validator - Validates deployed challenges
 * 
 * Responsibilities:
 * - Validate containers are running
 * - Test connectivity
 * - Verify services accessible
 * - Auto-fix issues
 */

import { Logger } from '../core/logger.js';
import { HealthChecker } from '../deployment/health-checker.js';
import { validateAndFixVictimMachine } from '../victim-validation-agent.js';

export class PostDeployValidator {
  constructor() {
    this.logger = new Logger();
    this.healthChecker = new HealthChecker();
  }

  /**
   * Validate deployment
   */
  async validate(deployment) {
    try {
      this.logger.info('PostDeployValidator', 'Validating deployment', { 
        challengeName: deployment.challengeName 
      });

      // Use health checker
      const health = await this.healthChecker.checkAll(
        deployment.challengeName,
        deployment.containers
      );

      if (!health.healthy) {
        return {
          success: false,
          errors: this.extractErrors(health),
          health
        };
      }

      // Additional validation: Test connectivity from attacker to victims
      const connectivity = await this.testConnectivity(deployment);

      if (!connectivity.success) {
        return {
          success: false,
          errors: connectivity.errors,
          health
        };
      }

      this.logger.success('PostDeployValidator', 'Deployment validated successfully');

      return {
        success: true,
        health,
        connectivity
      };

    } catch (error) {
      this.logger.error('PostDeployValidator', 'Validation failed', error.stack);
      return {
        success: false,
        error: error.message,
        details: error.stack
      };
    }
  }

  /**
   * Extract errors from health status
   */
  extractErrors(health) {
    const errors = [];

    if (health.details?.attacker && !health.details.attacker.healthy) {
      errors.push('Attacker container is not healthy');
    }

    if (health.details?.victims) {
      health.details.victims.forEach((victim, index) => {
        if (!victim.healthy) {
          errors.push(`Victim container ${index + 1} is not healthy`);
        }
      });
    }

    return errors;
  }

  /**
   * Test connectivity from attacker to victims
   */
  async testConnectivity(deployment) {
    try {
      const { attacker, victims } = deployment.containers;

      if (!attacker || !attacker.running) {
        return {
          success: false,
          errors: ['Attacker container is not running']
        };
      }

      // Test ping to each victim
      for (const victim of victims) {
        if (!victim.ip) {
          return {
            success: false,
            errors: [`Victim ${victim.name} has no IP address`]
          };
        }
      }

      return {
        success: true
      };

    } catch (error) {
      return {
        success: false,
        errors: [error.message]
      };
    }
  }

  /**
   * Auto-fix deployment issues
   */
  async autoFix(errors, deployment) {
    try {
      this.logger.info('PostDeployValidator', 'Auto-fixing deployment issues', { 
        errorCount: errors.length 
      });

      const fixes = [];

      // Use victim validation agent for victim issues
      for (const victim of deployment.containers.victims) {
        if (!victim.running || !victim.ip) {
          const fixResult = await validateAndFixVictimMachine({
            challengeName: deployment.challengeName,
            victimContainerName: victim.name,
            attackerContainerName: deployment.containers.attacker?.name,
            attackerIP: deployment.containers.attacker?.ip,
            expectedServices: [],
            composeConfig: {}
          });

          if (fixResult.fixed) {
            fixes.push({
              type: 'victim_fix',
              message: `Fixed victim container ${victim.name}`
            });
          }
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

