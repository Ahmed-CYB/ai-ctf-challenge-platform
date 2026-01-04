/**
 * Health Checker - Validates container health
 * 
 * Responsibilities:
 * - Check container status
 * - Verify services running
 * - Test connectivity
 * - Validate IP assignment
 */

import Docker from 'dockerode';
import { Logger } from '../core/logger.js';

export class HealthChecker {
  constructor() {
    this.docker = new Docker();
    this.logger = new Logger();
  }

  /**
   * Check all containers for a challenge
   */
  async checkAll(challengeName, containers) {
    try {
      this.logger.info('HealthChecker', 'Checking container health', { challengeName });

      const health = {
        attacker: await this.checkContainer(containers.attacker),
        victims: []
      };

      for (const victim of containers.victims) {
        health.victims.push(await this.checkContainer(victim));
      }

      const allHealthy = health.attacker.healthy && 
        health.victims.every(v => v.healthy);

      return {
        healthy: allHealthy,
        details: health
      };

    } catch (error) {
      this.logger.error('HealthChecker', 'Health check failed', error.stack);
      return {
        healthy: false,
        error: error.message
      };
    }
  }

  /**
   * Check a single container
   */
  async checkContainer(containerInfo) {
    if (!containerInfo) {
      return { healthy: false, error: 'Container info not provided' };
    }

    try {
      const container = this.docker.getContainer(containerInfo.id);
      const inspect = await container.inspect();

      const checks = {
        running: inspect.State.Running,
        hasIP: !!containerInfo.ip,
        servicesRunning: false
      };

      // Check if services are running (for victims)
      if (containerInfo.name.includes('victim') || !containerInfo.name.includes('attacker')) {
        checks.servicesRunning = await this.checkServices(container);
      } else {
        checks.servicesRunning = true; // Attacker always has SSH
      }

      const healthy = checks.running && checks.hasIP && checks.servicesRunning;

      return {
        healthy,
        checks
      };

    } catch (error) {
      return {
        healthy: false,
        error: error.message
      };
    }
  }

  /**
   * Check if services are running in container
   */
  async checkServices(container) {
    try {
      const exec = await container.exec({
        Cmd: ['sh', '-c', 'netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "no_netstat"'],
        AttachStdout: true,
        AttachStderr: true
      });

      const stream = await exec.start({ hijack: true, stdin: false });
      let output = '';

      return new Promise((resolve) => {
        stream.on('data', (chunk) => {
          output += chunk.toString();
        });

        stream.on('end', () => {
          // Check for common service ports
          const commonPorts = [21, 22, 80, 443, 445];
          const hasListeningPorts = commonPorts.some(port => 
            output.includes(`:${port}`) || output.includes(`0.0.0.0:${port}`)
          );
          resolve(hasListeningPorts);
        });

        setTimeout(() => resolve(false), 3000);
      });

    } catch (error) {
      return false;
    }
  }
}


