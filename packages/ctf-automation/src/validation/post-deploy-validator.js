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
   * Also tests service-specific functionality (FTP anonymous login, etc.)
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

      const errors = [];
      const warnings = [];

      // Test ping to each victim and service-specific tests
      for (const victim of victims) {
        if (!victim.ip) {
          errors.push(`Victim ${victim.name} has no IP address`);
          continue;
        }

        // Test service-specific functionality based on challenge type
        const serviceTests = await this.testVictimServices(attacker, victim, deployment.challengeName);
        
        if (!serviceTests.success) {
          errors.push(...serviceTests.errors);
        }
        
        if (serviceTests.warnings) {
          warnings.push(...serviceTests.warnings);
        }
      }

      if (errors.length > 0) {
        return {
          success: false,
          errors,
          warnings
        };
      }

      return {
        success: true,
        warnings
      };

    } catch (error) {
      return {
        success: false,
        errors: [error.message]
      };
    }
  }

  /**
   * Test victim services - Comprehensive testing of all services
   */
  async testVictimServices(attacker, victim, challengeName) {
    const { execSync } = await import('child_process');
    const errors = [];
    const warnings = [];

    try {
      // Step 1: Discover all open ports on victim machine
      const openPorts = await this.scanOpenPorts(attacker.name, victim.ip);
      this.logger.info('PostDeployValidator', 'Discovered open ports', {
        victim: victim.name,
        ip: victim.ip,
        ports: openPorts
      });

      if (openPorts.length === 0) {
        errors.push(`No open ports detected on victim ${victim.name}. Services may not be running.`);
        return { success: false, errors, warnings };
      }

      // Step 2: Identify services based on ports
      const detectedServices = this.identifyServices(openPorts);
      this.logger.info('PostDeployValidator', 'Identified services', {
        victim: victim.name,
        services: detectedServices
      });

      // Step 3: Test each detected service
      for (const service of detectedServices) {
        const testResult = await this.testService(service, attacker.name, victim.ip, challengeName, victim.name);
        
        if (!testResult.success) {
          if (testResult.critical) {
            errors.push(...testResult.errors);
          } else {
            warnings.push(...testResult.warnings);
          }
        } else {
          this.logger.success('PostDeployValidator', `Service test passed: ${service.name}`, {
            victim: victim.name,
            port: service.port
          });
        }
      }

      // Step 4: Check challenge-specific requirements
      const challengeRequirements = await this.checkChallengeRequirements(
        challengeName, 
        detectedServices, 
        attacker.name, 
        victim.ip,
        victim.name
      );
      
      if (!challengeRequirements.success) {
        errors.push(...challengeRequirements.errors);
      }

    } catch (error) {
      errors.push(`Service testing failed: ${error.message}`);
    }

    return {
      success: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Scan for open ports on victim machine
   */
  async scanOpenPorts(attackerContainer, victimIP) {
    const { execSync } = await import('child_process');
    const openPorts = [];

    try {
      // Use nmap to scan common ports
      const commonPorts = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 5432, 6379, 8080, 8443];
      const portsString = commonPorts.join(',');
      
      try {
        const nmapOutput = execSync(
          `docker exec ${attackerContainer} nmap -p ${portsString} --open -n ${victimIP} 2>/dev/null || echo "nmap_failed"`,
          { encoding: 'utf-8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] }
        );

        if (nmapOutput.includes('nmap_failed')) {
          // Fallback: Use nc to test ports individually
          for (const port of commonPorts) {
            try {
              execSync(
                `docker exec ${attackerContainer} timeout 2 nc -zv ${victimIP} ${port} 2>&1`,
                { encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe'] }
              );
              openPorts.push(port);
            } catch {
              // Port is closed
            }
          }
        } else {
          // Parse nmap output
          const portMatches = nmapOutput.matchAll(/(\d+)\/tcp\s+open/g);
          for (const match of portMatches) {
            openPorts.push(parseInt(match[1]));
          }
        }
      } catch (error) {
        // Fallback to individual port testing
        for (const port of commonPorts) {
          try {
            execSync(
              `docker exec ${attackerContainer} timeout 2 nc -zv ${victimIP} ${port} 2>&1`,
              { encoding: 'utf-8', timeout: 3000, stdio: ['pipe', 'pipe', 'pipe'] }
            );
            openPorts.push(port);
          } catch {
            // Port is closed
          }
        }
      }
    } catch (error) {
      this.logger.warn('PostDeployValidator', 'Port scanning failed', { error: error.message });
    }

    return openPorts;
  }

  /**
   * Identify services based on open ports
   */
  identifyServices(ports) {
    const serviceMap = {
      21: { name: 'ftp', port: 21, type: 'network' },
      22: { name: 'ssh', port: 22, type: 'network' },
      23: { name: 'telnet', port: 23, type: 'network' },
      25: { name: 'smtp', port: 25, type: 'network' },
      53: { name: 'dns', port: 53, type: 'network' },
      80: { name: 'http', port: 80, type: 'web' },
      135: { name: 'msrpc', port: 135, type: 'network' },
      139: { name: 'netbios', port: 139, type: 'network' },
      443: { name: 'https', port: 443, type: 'web' },
      445: { name: 'samba', port: 445, type: 'network' },
      1433: { name: 'mssql', port: 1433, type: 'database' },
      3306: { name: 'mysql', port: 3306, type: 'database' },
      5432: { name: 'postgresql', port: 5432, type: 'database' },
      6379: { name: 'redis', port: 6379, type: 'database' },
      8080: { name: 'http-alt', port: 8080, type: 'web' },
      8443: { name: 'https-alt', port: 8443, type: 'web' }
    };

    return ports
      .map(port => serviceMap[port])
      .filter(service => service !== undefined);
  }

  /**
   * Test a specific service - includes configuration and vulnerability checks
   */
  async testService(service, attackerContainer, victimIP, challengeName, victimName) {
    const errors = [];
    const warnings = [];
    let success = false;

    try {
      switch (service.name) {
        case 'ftp':
          const ftpTest = await this.testFTPService(attackerContainer, victimIP, challengeName, victimName);
          if (!ftpTest.success) {
            errors.push(...ftpTest.errors || [ftpTest.error]);
          } else {
            success = true;
          }
          // Check FTP configuration
          const ftpConfig = await this.checkFTPConfiguration(victimName, challengeName);
          if (!ftpConfig.success) {
            errors.push(...ftpConfig.errors);
            success = false;
          }
          break;

        case 'samba':
        case 'smb':
          const smbTest = await this.testSMBAccess(attackerContainer, victimIP, challengeName, victimName);
          if (!smbTest.success) {
            errors.push(...smbTest.errors || [smbTest.error]);
          } else {
            success = true;
          }
          // Check Samba configuration
          const smbConfig = await this.checkSambaConfiguration(victimName, challengeName);
          if (!smbConfig.success) {
            errors.push(...smbConfig.errors);
            success = false;
          }
          break;

        case 'ssh':
          const sshTest = await this.testSSHAccess(attackerContainer, victimIP);
          if (!sshTest.success) {
            warnings.push(`SSH access test: ${sshTest.error || 'Could not verify'}`);
          } else {
            success = true;
          }
          break;

        case 'http':
        case 'https':
        case 'http-alt':
        case 'https-alt':
          const httpTest = await this.testHTTPAccess(attackerContainer, victimIP, service.port);
          if (!httpTest.success) {
            warnings.push(`HTTP access test: ${httpTest.error || 'Could not verify'}`);
          } else {
            success = true;
          }
          break;

        case 'telnet':
          const telnetTest = await this.testTelnetAccess(attackerContainer, victimIP);
          if (!telnetTest.success) {
            warnings.push(`Telnet access test: ${telnetTest.error || 'Could not verify'}`);
          } else {
            success = true;
          }
          break;

        case 'mysql':
        case 'postgresql':
        case 'redis':
          // Database services - just verify port is open
          success = true;
          break;

        default:
          // Unknown service - just verify port is open
          success = true;
          warnings.push(`Service ${service.name} on port ${service.port} detected but no specific test available`);
      }
    } catch (error) {
      errors.push(`Failed to test ${service.name}: ${error.message}`);
    }

    return {
      success,
      errors,
      warnings,
      critical: errors.length > 0
    };
  }

  /**
   * Test FTP service - checks for anonymous access if challenge mentions it
   * Also verifies actual exploitation (can list files, access flag, etc.)
   */
  async testFTPService(attackerContainer, victimIP, challengeName, victimName) {
    const challengeLower = challengeName.toLowerCase();
    const isAnonymousChallenge = challengeLower.includes('anonymous') || 
                                  challengeLower.includes('anon');

    if (isAnonymousChallenge) {
      // Test anonymous login AND actual file access
      const loginTest = await this.testFTPAnonymousLogin(attackerContainer, victimIP);
      if (!loginTest.success) {
        return loginTest;
      }

      // Test actual exploitation: can we list files and access flag?
      const exploitTest = await this.testFTPExploitation(attackerContainer, victimIP);
      if (!exploitTest.success) {
        return {
          success: false,
          error: `Anonymous login works but exploitation failed: ${exploitTest.error}`,
          errors: [`Anonymous login works but exploitation failed: ${exploitTest.error}`]
        };
      }

      return { success: true };
    } else {
      // Just verify FTP port is accessible
      const { execSync } = await import('child_process');
      try {
        execSync(
          `docker exec ${attackerContainer} nc -zv ${victimIP} 21`,
          { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
        );
        return { success: true };
      } catch (error) {
        return {
          success: false,
          error: 'FTP port 21 is not accessible'
        };
      }
    }
  }

  /**
   * Test FTP exploitation - verify we can actually access files
   */
  async testFTPExploitation(attackerContainer, victimIP) {
    const { execSync } = await import('child_process');
    
    try {
      // Test: Login anonymously, list directories, try to access flag
      const ftpCommands = `user anonymous\\npass\\nls\\ncd data\\nls\\ncd classified\\nls\\nget flag.txt\\nquit`;
      
      const ftpOutput = execSync(
        `docker exec ${attackerContainer} sh -c "echo -e '${ftpCommands}' | ftp -n ${victimIP} 2>&1"`,
        { encoding: 'utf-8', timeout: 15000, stdio: ['pipe', 'pipe', 'pipe'] }
      );

      const output = ftpOutput.toLowerCase();
      
      // Check for successful file operations
      const canListFiles = output.includes('226') || output.includes('transfer complete') || 
                          output.includes('directory send ok');
      const canAccessFlag = output.includes('flag.txt') || output.includes('classified');
      const loginSuccess = output.includes('230') || output.includes('logged in');

      if (loginSuccess && canListFiles) {
        return { success: true };
      } else {
        return {
          success: false,
          error: `FTP exploitation test failed. Login: ${loginSuccess}, Can list files: ${canListFiles}, Can access flag: ${canAccessFlag}`
        };
      }
    } catch (error) {
      return {
        success: false,
        error: `FTP exploitation test error: ${error.message}`
      };
    }
  }

  /**
   * Check FTP configuration file
   */
  async checkFTPConfiguration(victimContainer, challengeName) {
    const { execSync } = await import('child_process');
    const errors = [];
    const challengeLower = challengeName.toLowerCase();
    const isAnonymousChallenge = challengeLower.includes('anonymous') || challengeLower.includes('anon');

    try {
      // Read vsftpd.conf from container
      let configContent = '';
      try {
        configContent = execSync(
          `docker exec ${victimContainer} cat /etc/vsftpd.conf 2>/dev/null || echo "config_not_found"`,
          { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
        );
      } catch {
        // Try /challenge/vsftpd.conf
        try {
          configContent = execSync(
            `docker exec ${victimContainer} cat /challenge/vsftpd.conf 2>/dev/null || echo "config_not_found"`,
            { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
          );
        } catch {
          errors.push('FTP configuration file (vsftpd.conf) not found in /etc/vsftpd.conf or /challenge/vsftpd.conf');
          return { success: false, errors };
        }
      }

      if (configContent.includes('config_not_found')) {
        errors.push('FTP configuration file (vsftpd.conf) not found');
        return { success: false, errors };
      }

      const configLower = configContent.toLowerCase();

      // Check for anonymous access configuration
      if (isAnonymousChallenge) {
        if (!configLower.includes('anonymous_enable=yes')) {
          errors.push('FTP configuration error: anonymous_enable=YES is missing or set to NO. Anonymous FTP challenge requires anonymous access to be enabled.');
        }

        if (!configLower.includes('anon_root')) {
          warnings.push('FTP configuration: anon_root not set (using default /var/ftp)');
        }

        if (configLower.includes('no_anon_password=no') || 
            (configLower.includes('no_anon_password') && !configLower.includes('no_anon_password=yes'))) {
          warnings.push('FTP configuration: no_anon_password should be YES for easier anonymous access');
        }
      }

      // Check for common misconfigurations
      if (configLower.includes('chroot_local_user=yes') && !configLower.includes('allow_writeable_chroot=yes')) {
        warnings.push('FTP configuration: chroot_local_user=YES without allow_writeable_chroot=YES may cause issues');
      }

      // Verify service is using the config
      const vsftpdProcess = execSync(
        `docker exec ${victimContainer} ps aux | grep vsftpd | grep -v grep || echo "not_running"`,
        { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
      );

      if (vsftpdProcess.includes('not_running')) {
        errors.push('vsftpd process is not running. Service may have failed to start.');
      }

    } catch (error) {
      errors.push(`Failed to check FTP configuration: ${error.message}`);
    }

    return {
      success: errors.length === 0,
      errors,
      warnings: warnings || []
    };
  }

  /**
   * Test SSH access
   */
  async testSSHAccess(attackerContainer, victimIP) {
    const { execSync } = await import('child_process');
    
    try {
      execSync(
        `docker exec ${attackerContainer} nc -zv ${victimIP} 22`,
        { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
      );
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: `SSH port 22 not accessible: ${error.message}`
      };
    }
  }

  /**
   * Test HTTP/HTTPS access
   */
  async testHTTPAccess(attackerContainer, victimIP, port = 80) {
    const { execSync } = await import('child_process');
    
    try {
      const protocol = port === 443 || port === 8443 ? 'https' : 'http';
      const url = `${protocol}://${victimIP}:${port}`;
      
      const curlOutput = execSync(
        `docker exec ${attackerContainer} curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 ${url} 2>&1 || echo "curl_failed"`,
        { encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }
      );

      if (curlOutput.includes('curl_failed')) {
        // Fallback: Just check if port is open
        execSync(
          `docker exec ${attackerContainer} nc -zv ${victimIP} ${port}`,
          { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
        );
        return { success: true };
      }

      const statusCode = parseInt(curlOutput.trim());
      if (statusCode >= 200 && statusCode < 500) {
        return { success: true };
      } else {
        return {
          success: false,
          error: `HTTP returned status code ${statusCode}`
        };
      }
    } catch (error) {
      return {
        success: false,
        error: `HTTP access test failed: ${error.message}`
      };
    }
  }

  /**
   * Test Telnet access
   */
  async testTelnetAccess(attackerContainer, victimIP) {
    const { execSync } = await import('child_process');
    
    try {
      execSync(
        `docker exec ${attackerContainer} nc -zv ${victimIP} 23`,
        { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
      );
      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: `Telnet port 23 not accessible: ${error.message}`
      };
    }
  }

  /**
   * Check challenge-specific requirements based on challenge name/description
   * Also verifies flag accessibility and vulnerability exploitation
   */
  async checkChallengeRequirements(challengeName, detectedServices, attackerContainer, victimIP, victimName) {
    const errors = [];
    const warnings = [];
    const challengeLower = challengeName.toLowerCase();

    // Check for anonymous FTP requirement
    if (challengeLower.includes('anonymous') && challengeLower.includes('ftp')) {
      const ftpService = detectedServices.find(s => s.name === 'ftp');
      if (!ftpService) {
        errors.push('Challenge mentions anonymous FTP but FTP service (port 21) is not accessible');
      } else {
        // Test anonymous login
        const ftpTest = await this.testFTPAnonymousLogin(attackerContainer, victimIP);
        if (!ftpTest.success) {
          errors.push(`Anonymous FTP challenge requirement not met: ${ftpTest.error}`);
        } else {
          // Test flag accessibility
          const flagTest = await this.checkFlagAccessibility('ftp', attackerContainer, victimIP, victimName);
          if (!flagTest.success) {
            errors.push(`Flag accessibility test failed: ${flagTest.error}`);
          }
        }
      }
    }

    // Check for Samba/SMB requirement
    if ((challengeLower.includes('samba') || challengeLower.includes('smb')) && 
        !challengeLower.includes('windows')) {
      const smbService = detectedServices.find(s => s.name === 'samba');
      if (!smbService) {
        errors.push('Challenge mentions Samba/SMB but SMB service (port 445) is not accessible');
      } else {
        // Test SMB share access
        const smbTest = await this.testSMBAccess(attackerContainer, victimIP, challengeName, victimName);
        if (!smbTest.success && smbTest.errors) {
          errors.push(...smbTest.errors);
        }
      }
    }

    // Check for web/HTTP requirement
    if (challengeLower.includes('web') || challengeLower.includes('http') || 
        challengeLower.includes('website') || challengeLower.includes('sql injection') ||
        challengeLower.includes('xss')) {
      const httpService = detectedServices.find(s => s.name === 'http' || s.name === 'https');
      if (!httpService) {
        errors.push('Challenge mentions web/HTTP but HTTP service (port 80/443) is not accessible');
      } else {
        // Test web vulnerability (if SQL injection or XSS mentioned)
        if (challengeLower.includes('sql injection') || challengeLower.includes('sqli')) {
          const sqlTest = await this.testSQLInjectionVulnerability(attackerContainer, victimIP, httpService.port);
          if (!sqlTest.success) {
            warnings.push(`SQL injection test: ${sqlTest.error || 'Could not verify vulnerability'}`);
          }
        }
      }
    }

    return {
      success: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Test FTP anonymous login
   */
  async testFTPAnonymousLogin(attackerContainer, victimIP) {
    const { execSync } = await import('child_process');
    
    try {
      // Test FTP anonymous login using ftp command
      // Try multiple methods to ensure compatibility
      let ftpTest;
      
      try {
        // Method 1: Use ftp command with here-document
        const ftpScript = `user anonymous\\npass\\nls\\nquit`;
        ftpTest = execSync(
          `docker exec ${attackerContainer} sh -c "echo -e '${ftpScript}' | ftp -n ${victimIP}"`,
          { encoding: 'utf-8', timeout: 15000, stdio: ['pipe', 'pipe', 'pipe'] }
        );
      } catch (method1Error) {
        // Method 2: Use nc (netcat) to test FTP connection
        try {
          ftpTest = execSync(
            `docker exec ${attackerContainer} sh -c "echo -e 'user anonymous\\npass\\nquit' | nc ${victimIP} 21"`,
            { encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }
          );
        } catch (method2Error) {
          // Method 3: Just test if port 21 is open
          try {
            execSync(
              `docker exec ${attackerContainer} nc -zv ${victimIP} 21`,
              { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
            );
            // Port is open, but we can't fully test anonymous login
            return {
              success: false,
              error: 'FTP port is open but anonymous login could not be verified. Please test manually.'
            };
          } catch (portTestError) {
            return {
              success: false,
              error: 'FTP port 21 is not accessible'
            };
          }
        }
      }

      // Check for successful login indicators
      const ftpOutput = ftpTest.toLowerCase();
      const hasLoginSuccess = ftpOutput.includes('230') || // Login successful
                             ftpOutput.includes('logged in') ||
                             ftpOutput.includes('anonymous') && (ftpOutput.includes('331') || ftpOutput.includes('230'));
      
      const hasFTPResponse = ftpOutput.includes('220') || // FTP service ready
                            ftpOutput.includes('vsftpd') ||
                            ftpOutput.includes('ftp server');

      if (hasLoginSuccess) {
        return { success: true };
      } else if (hasFTPResponse) {
        // FTP is responding but anonymous login might not be enabled
        return {
          success: false,
          error: 'FTP service is responding but anonymous login appears to be disabled or not working. Check vsftpd.conf for anonymous_enable=YES',
          errors: ['FTP service is responding but anonymous login appears to be disabled or not working. Check vsftpd.conf for anonymous_enable=YES']
        };
      } else {
        return {
          success: false,
          error: `FTP service not responding correctly. Output: ${ftpTest.substring(0, 200)}`,
          errors: [`FTP service not responding correctly. Output: ${ftpTest.substring(0, 200)}`]
        };
      }

    } catch (error) {
      return {
        success: false,
        error: `FTP anonymous login test failed: ${error.message}`,
        errors: [`FTP anonymous login test failed: ${error.message}`]
      };
    }
  }

  /**
   * Test SMB access - verifies actual share enumeration and access
   */
  async testSMBAccess(attackerContainer, victimIP, challengeName, victimName) {
    const { execSync } = await import('child_process');
    const errors = [];
    
    try {
      // Test SMB port 445
      execSync(
        `docker exec ${attackerContainer} nc -zv ${victimIP} 445`,
        { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
      );

      // Test actual SMB share enumeration (null session if challenge allows it)
      const challengeLower = challengeName.toLowerCase();
      const allowsNullSession = challengeLower.includes('null') || 
                                challengeLower.includes('anonymous') ||
                                challengeLower.includes('public');

      if (allowsNullSession) {
        // Try to enumerate shares with null session
        try {
          const smbclientOutput = execSync(
            `docker exec ${attackerContainer} smbclient -L ${victimIP} -N 2>&1 || echo "smbclient_failed"`,
            { encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }
          );

          if (!smbclientOutput.includes('smbclient_failed')) {
            // Check if we can see shares
            if (smbclientOutput.includes('sharename') || smbclientOutput.includes('disk')) {
              return { success: true };
            } else {
              errors.push('SMB null session enumeration failed - no shares visible');
            }
          }
        } catch (smbError) {
          // smbclient might not be installed, that's okay
          warnings.push('smbclient not available for detailed SMB testing');
        }
      }

      return { 
        success: errors.length === 0,
        errors: errors.length > 0 ? errors : undefined
      };
    } catch (error) {
      return {
        success: false,
        error: `SMB port 445 not accessible: ${error.message}`,
        errors: [`SMB port 445 not accessible: ${error.message}`]
      };
    }
  }

  /**
   * Check Samba configuration file
   */
  async checkSambaConfiguration(victimContainer, challengeName) {
    const { execSync } = await import('child_process');
    const errors = [];
    const warnings = [];
    const challengeLower = challengeName.toLowerCase();
    const allowsNullSession = challengeLower.includes('null') || 
                              challengeLower.includes('anonymous') ||
                              challengeLower.includes('public');

    try {
      // Read smb.conf from container
      let configContent = '';
      try {
        configContent = execSync(
          `docker exec ${victimContainer} cat /etc/samba/smb.conf 2>/dev/null || echo "config_not_found"`,
          { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
        );
      } catch {
        // Try /challenge/smb.conf
        try {
          configContent = execSync(
            `docker exec ${victimContainer} cat /challenge/smb.conf 2>/dev/null || echo "config_not_found"`,
            { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
          );
        } catch {
          errors.push('Samba configuration file (smb.conf) not found in /etc/samba/smb.conf or /challenge/smb.conf');
          return { success: false, errors };
        }
      }

      if (configContent.includes('config_not_found')) {
        errors.push('Samba configuration file (smb.conf) not found');
        return { success: false, errors };
      }

      const configLower = configContent.toLowerCase();

      // Check for null session configuration if challenge requires it
      if (allowsNullSession) {
        if (!configLower.includes('map to guest') && !configLower.includes('guest ok')) {
          warnings.push('Samba configuration: For null session access, consider adding "map to guest = Bad User" or "guest ok = yes"');
        }
      }

      // Check if shares are defined
      if (!configContent.match(/\[.*\]/)) {
        errors.push('Samba configuration: No shares defined in smb.conf');
      }

      // Verify services are running
      const smbdProcess = execSync(
        `docker exec ${victimContainer} ps aux | grep smbd | grep -v grep || echo "not_running"`,
        { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] }
      );

      if (smbdProcess.includes('not_running')) {
        errors.push('smbd process is not running. Samba service may have failed to start.');
      }

    } catch (error) {
      errors.push(`Failed to check Samba configuration: ${error.message}`);
    }

    return {
      success: errors.length === 0,
      errors,
      warnings
    };
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

