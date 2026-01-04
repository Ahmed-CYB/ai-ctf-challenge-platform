/**
 * Linux-Only Validator - Ensures all challenges are Linux-based only
 * 
 * Validates at multiple stages:
 * - Design validation (OS field in machines)
 * - Structure validation (OS in structure)
 * - Dockerfile validation (base images)
 * - Docker-compose validation (service images)
 * - Pre-deploy validation (final check)
 */

import { Logger } from './logger.js';

export class LinuxOnlyValidator {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Windows OS patterns to detect
   */
  getWindowsPatterns() {
    return {
      // Windows base images
      images: [
        /mcr\.microsoft\.com/i,
        /microsoft\/windows/i,
        /windows/i,
        /win32/i,
        /win64/i,
        /windowsservercore/i,
        /nanoserver/i,
        /windowsserver/i,
        /microsoft-windows/i
      ],
      // Windows OS strings
      osStrings: [
        /windows/i,
        /win32/i,
        /win64/i,
        /microsoft windows/i,
        /windows server/i,
        /windows 10/i,
        /windows 11/i,
        /windows 7/i,
        /windows 8/i,
        /windows xp/i
      ],
      // Windows-specific services/features
      services: [
        /rdp/i,
        /remote desktop/i,
        /active directory/i,
        /powershell/i,
        /iis/i,
        /internet information services/i,
        /windows smb/i,
        /windows rdp/i
      ]
    };
  }

  /**
   * Check if an OS string/image is Windows
   */
  isWindowsOS(osString) {
    if (!osString || typeof osString !== 'string') {
      return false;
    }

    const osLower = osString.toLowerCase();
    const patterns = this.getWindowsPatterns();

    // Check OS strings
    for (const pattern of patterns.osStrings) {
      if (pattern.test(osLower)) {
        return true;
      }
    }

    // Check image patterns
    for (const pattern of patterns.images) {
      if (pattern.test(osLower)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a Dockerfile contains Windows base images
   */
  validateDockerfile(dockerfileContent) {
    const errors = [];
    const warnings = [];

    if (!dockerfileContent || typeof dockerfileContent !== 'string') {
      return { valid: false, errors: ['Dockerfile content is missing or invalid'] };
    }

    const lines = dockerfileContent.split('\n');
    const patterns = this.getWindowsPatterns();

    lines.forEach((line, index) => {
      const lineLower = line.toLowerCase();
      const lineNumber = index + 1;

      // Check for Windows base images
      if (lineLower.includes('from')) {
        for (const pattern of patterns.images) {
          if (pattern.test(line)) {
            errors.push(`Line ${lineNumber}: Windows base image detected: "${line.trim()}"`);
          }
        }
      }

      // Check for Windows-specific commands
      if (lineLower.includes('powershell') || lineLower.includes('cmd.exe')) {
        errors.push(`Line ${lineNumber}: Windows-specific command detected: "${line.trim()}"`);
      }

      // Check for Windows paths
      if (lineLower.includes('c:\\') || lineLower.includes('c:/')) {
        errors.push(`Line ${lineNumber}: Windows path detected: "${line.trim()}"`);
      }
    });

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate design machines for Linux-only OS
   */
  validateDesignMachines(machines) {
    const errors = [];
    const warnings = [];

    if (!machines || !Array.isArray(machines)) {
      return { valid: false, errors: ['Machines array is missing or invalid'] };
    }

    machines.forEach((machine, index) => {
      if (!machine.os) {
        errors.push(`Machine ${index} (${machine.name || 'unnamed'}): Missing OS field`);
        return;
      }

      if (this.isWindowsOS(machine.os)) {
        errors.push(
          `Machine ${index} (${machine.name || 'unnamed'}): Windows OS detected: "${machine.os}". ` +
          `Only Linux-based OS are supported (e.g., ubuntu:22.04, rockylinux:9, alpine:latest, kalilinux/kali-rolling:latest)`
        );
      }

      // Check for Linux base images
      const osLower = machine.os.toLowerCase();
      const validLinuxPatterns = [
        /ubuntu/i,
        /debian/i,
        /alpine/i,
        /rocky/i,
        /centos/i,
        /fedora/i,
        /kali/i,
        /linux/i
      ];

      const isValidLinux = validLinuxPatterns.some(pattern => pattern.test(osLower));
      if (!isValidLinux && !this.isWindowsOS(machine.os)) {
        warnings.push(
          `Machine ${index} (${machine.name || 'unnamed'}): OS "${machine.os}" may not be a standard Linux distribution. ` +
          `Recommended: ubuntu:22.04, rockylinux:9, alpine:latest, or kalilinux/kali-rolling:latest`
        );
      }
    });

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Validate docker-compose.yml for Windows images
   */
  async validateDockerCompose(composeContent) {
    const errors = [];
    const warnings = [];

    if (!composeContent) {
      return { valid: false, errors: ['Docker-compose content is missing'] };
    }

    try {
      const yaml = require('js-yaml');
      const compose = typeof composeContent === 'string' 
        ? yaml.load(composeContent) 
        : composeContent;

      if (!compose.services) {
        return { valid: true, errors: [], warnings: [] };
      }

      const patterns = this.getWindowsPatterns();

      Object.entries(compose.services).forEach(([serviceName, service]) => {
        // Check image field
        if (service.image) {
          for (const pattern of patterns.images) {
            if (pattern.test(service.image)) {
              errors.push(
                `Service "${serviceName}": Windows image detected: "${service.image}". ` +
                `Only Linux-based images are supported`
              );
            }
          }
        }

        // Check build context for Dockerfile
        if (service.build && service.build.dockerfile) {
          // Dockerfile will be validated separately
        }
      });

    } catch (error) {
      // If YAML parsing fails, check raw content
      const contentStr = typeof composeContent === 'string' 
        ? composeContent 
        : JSON.stringify(composeContent);

      const patterns = this.getWindowsPatterns();
      for (const pattern of patterns.images) {
        if (pattern.test(contentStr)) {
          errors.push(`Docker-compose contains Windows image reference`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Comprehensive validation of challenge configuration
   */
  validateChallengeConfig(design, structure, dockerfiles, compose) {
    const allErrors = [];
    const allWarnings = [];

    // 1. Validate design machines
    if (design && design.machines) {
      const designValidation = this.validateDesignMachines(design.machines);
      allErrors.push(...designValidation.errors);
      allWarnings.push(...designValidation.warnings);
    }

    // 2. Validate structure machines
    if (structure && structure.machines) {
      const structureValidation = this.validateDesignMachines(structure.machines);
      allErrors.push(...structureValidation.errors);
      allWarnings.push(...structureValidation.warnings);
    }

    // 3. Validate Dockerfiles
    if (dockerfiles && Array.isArray(dockerfiles)) {
      dockerfiles.forEach((df, index) => {
        if (df.dockerfile || df.content) {
          const dockerfileValidation = this.validateDockerfile(df.dockerfile || df.content);
          dockerfileValidation.errors.forEach(err => {
            allErrors.push(`Dockerfile ${index} (${df.machineName || 'unnamed'}): ${err}`);
          });
          dockerfileValidation.warnings.forEach(warn => {
            allWarnings.push(`Dockerfile ${index} (${df.machineName || 'unnamed'}): ${warn}`);
          });
        }
      });
    }

    // 4. Validate docker-compose
    if (compose) {
      const composeValidation = this.validateDockerCompose(
        compose.content || compose.data || compose
      );
      allErrors.push(...composeValidation.errors);
      allWarnings.push(...composeValidation.warnings);
    }

    return {
      valid: allErrors.length === 0,
      errors: allErrors,
      warnings: allWarnings
    };
  }
}

export const linuxOnlyValidator = new LinuxOnlyValidator();

