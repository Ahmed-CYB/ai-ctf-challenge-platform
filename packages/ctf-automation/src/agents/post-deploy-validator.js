/**
 * Post-Deployment Challenge Validator
 * 
 * Validates that deployed CTF challenges are working correctly before releasing to users.
 * Tests services, connections, and challenge objectives.
 */

import { execSync } from 'child_process';
import OpenAI from 'openai';
import Docker from 'dockerode';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const docker = new Docker();

/**
 * Find attacker container (handles suffixes like -workstation)
 */
async function findAttackerContainer(challengeName) {
  const basePattern = `ctf-${challengeName}-attacker`;
  const containers = await docker.listContainers();
  
  const attackerContainer = containers.find(c => 
    c.Names.some(name => name.includes(basePattern))
  );
  
  if (!attackerContainer) {
    throw new Error(`Could not find attacker container with pattern: ${basePattern}`);
  }
  
  // Return the full container name (without leading /)
  return attackerContainer.Names[0].replace(/^\//, '');
}

/**
 * Validate deployed challenge functionality
 */
export async function validateChallenge(challengeName, deployment, progressCallback) {
  console.log(`\n🧪 Running post-deployment validation for: ${challengeName}`);
  
  const results = {
    success: true,
    tests: [],
    errors: [],
    warnings: []
  };

  try {
    // 1. Container Health Checks
    progressCallback?.({ step: 'validation-containers', message: '🔍 Checking container health...' });
    const containerCheck = await checkContainers(challengeName);
    results.tests.push(containerCheck);
    if (!containerCheck.passed) results.success = false;

    // 2. Network Connectivity Tests
    progressCallback?.({ step: 'validation-network', message: '🌐 Testing network connectivity...' });
    const networkCheck = await checkNetwork(challengeName, deployment);
    results.tests.push(networkCheck);
    if (!networkCheck.passed) results.success = false;

    // 3. Service Port Tests
    progressCallback?.({ step: 'validation-services', message: '🔌 Verifying service ports...' });
    const serviceCheck = await checkServices(challengeName, deployment);
    results.tests.push(serviceCheck);
    if (!serviceCheck.passed) results.success = false;

    // 4. Challenge-Specific Validation
    progressCallback?.({ step: 'validation-challenge', message: '🎯 Testing challenge objectives...' });
    const challengeCheck = await validateChallengeObjectives(challengeName, deployment);
    results.tests.push(challengeCheck);
    if (!challengeCheck.passed) results.success = false;

    // 5. Generate validation report
    const report = generateValidationReport(results);
    console.log(report);

    return results;

  } catch (error) {
    console.error('❌ Validation error:', error.message);
    results.success = false;
    results.errors.push(error.message);
    return results;
  }
}

/**
 * Check container status
 */
async function checkContainers(challengeName) {
  const result = {
    name: 'Container Health',
    passed: true,
    details: []
  };

  try {
    // Get all containers for this challenge
    const containers = execSync(
      `docker ps --filter "name=ctf-${challengeName}" --format "{{.Names}}|{{.Status}}"`,
      { encoding: 'utf-8' }
    ).trim().split('\n').filter(Boolean);

    if (containers.length === 0) {
      result.passed = false;
      result.details.push('❌ No containers found for challenge');
      return result;
    }

    containers.forEach(containerInfo => {
      const [name, status] = containerInfo.split('|');
      const isHealthy = status.includes('Up');
      
      result.details.push(
        isHealthy 
          ? `✅ ${name}: ${status}`
          : `❌ ${name}: ${status}`
      );

      if (!isHealthy) result.passed = false;
    });

  } catch (error) {
    result.passed = false;
    result.details.push(`❌ Error checking containers: ${error.message}`);
  }

  return result;
}

/**
 * Check network connectivity
 */
async function checkNetwork(challengeName, deployment) {
  const result = {
    name: 'Network Connectivity',
    passed: true,
    details: []
  };

  try {
    // Test if attacker can reach victim
    const attackerContainer = await findAttackerContainer(challengeName);
    const victimIP = deployment.victimIP;

    if (!victimIP) {
      result.details.push('⚠️ No victim IP provided, skipping network test');
      return result;
    }

    try {
      const pingTest = execSync(
        `docker exec ${attackerContainer} ping -c 1 -W 2 ${victimIP}`,
        { encoding: 'utf-8', timeout: 5000 }
      );

      result.details.push(`✅ Attacker can reach victim at ${victimIP}`);
    } catch (pingError) {
      result.passed = false;
      result.details.push(`❌ Network connectivity failed: Attacker cannot reach ${victimIP}`);
    }

  } catch (error) {
    result.passed = false;
    result.details.push(`❌ Network test error: ${error.message}`);
  }

  return result;
}

/**
 * Check services are listening on expected ports
 */
async function checkServices(challengeName, deployment) {
  const result = {
    name: 'Service Port Checks',
    passed: true,
    details: []
  };

  try {
    const attackerContainer = await findAttackerContainer(challengeName);
    const victimIP = deployment.victimIP;

    if (!victimIP) {
      result.details.push('⚠️ No victim IP provided, skipping service checks');
      return result;
    }

    // Common ports to check based on challenge type
    const portsToCheck = detectPortsFromChallenge(challengeName);

    for (const port of portsToCheck) {
      try {
        const nmapScan = execSync(
          `docker exec ${attackerContainer} timeout 5 nmap -p ${port} --open ${victimIP}`,
          { encoding: 'utf-8', timeout: 10000 }
        );

        const isOpen = nmapScan.includes(`${port}/tcp open`);
        
        if (isOpen) {
          result.details.push(`✅ Port ${port} is open and accessible`);
        } else {
          result.passed = false;
          result.details.push(`❌ Port ${port} is not accessible`);
        }
      } catch (scanError) {
        result.passed = false;
        result.details.push(`❌ Port ${port} scan failed`);
      }
    }

  } catch (error) {
    result.passed = false;
    result.details.push(`❌ Service check error: ${error.message}`);
  }

  return result;
}

/**
 * Validate challenge objectives can be completed
 */
async function validateChallengeObjectives(challengeName, deployment) {
  const result = {
    name: 'Challenge Objectives',
    passed: true,
    details: []
  };

  try {
    const attackerContainer = await findAttackerContainer(challengeName);
    const victimIP = deployment.victimIP;

    // Test FTP access if FTP challenge
    if (challengeName.toLowerCase().includes('ftp')) {
      const ftpTest = await testFTPAccess(attackerContainer, victimIP);
      result.details.push(...ftpTest.details);
      if (!ftpTest.passed) result.passed = false;
    }

    // Test SMB access if SMB challenge
    if (challengeName.toLowerCase().includes('smb') || challengeName.toLowerCase().includes('samba')) {
      const smbTest = await testSMBAccess(attackerContainer, victimIP);
      result.details.push(...smbTest.details);
      if (!smbTest.passed) result.passed = false;
    }

    // Test SSH access if SSH challenge
    if (challengeName.toLowerCase().includes('ssh')) {
      const sshTest = await testSSHAccess(attackerContainer, victimIP);
      result.details.push(...sshTest.details);
      if (!sshTest.passed) result.passed = false;
    }

    // Test web access if web challenge
    if (challengeName.toLowerCase().includes('web') || challengeName.toLowerCase().includes('sql') || challengeName.toLowerCase().includes('xss')) {
      const webTest = await testWebAccess(attackerContainer, victimIP);
      result.details.push(...webTest.details);
      if (!webTest.passed) result.passed = false;
    }

  } catch (error) {
    result.passed = false;
    result.details.push(`❌ Challenge validation error: ${error.message}`);
  }

  return result;
}

/**
 * Test FTP service functionality
 */
async function testFTPAccess(container, victimIP) {
  const result = { passed: false, details: [] };

  try {
    // Test FTP connection
    const ftpTest = execSync(
      `docker exec ${container} timeout 5 bash -c "echo -e 'user anonymous\\npass anonymous\\nls\\nquit' | nc ${victimIP} 21"`,
      { encoding: 'utf-8', timeout: 10000 }
    );

    if (ftpTest.includes('220') || ftpTest.includes('230') || ftpTest.includes('331')) {
      result.passed = true;
      result.details.push('✅ FTP service is responding');
    } else {
      result.details.push('❌ FTP service not responding correctly');
      result.details.push(`   Response: ${ftpTest.substring(0, 200)}`);
    }
  } catch (error) {
    result.details.push('❌ FTP connection failed');
    result.details.push(`   Error: ${error.message.substring(0, 200)}`);
  }

  return result;
}

/**
 * Test SMB service functionality
 */
async function testSMBAccess(container, victimIP) {
  const result = { passed: false, details: [] };

  try {
    // Test SMB connection
    const smbTest = execSync(
      `docker exec ${container} timeout 10 smbclient -L //${victimIP} -N`,
      { encoding: 'utf-8', timeout: 15000 }
    );

    if (smbTest.includes('Sharename') || smbTest.includes('IPC$')) {
      result.passed = true;
      result.details.push('✅ SMB service is responding');
    } else {
      result.details.push('⚠️ SMB service responding but no shares found');
      result.passed = true; // Still consider it passed if service responds
    }
  } catch (error) {
    // Check if error output contains expected SMB responses
    const errorOutput = error.stdout?.toString() || error.stderr?.toString() || '';
    if (errorOutput.includes('Sharename') || errorOutput.includes('session setup failed')) {
      result.passed = true;
      result.details.push('✅ SMB service is running (authentication required)');
    } else {
      result.details.push('❌ SMB connection failed');
      result.details.push(`   Error: ${error.message.substring(0, 200)}`);
    }
  }

  return result;
}

/**
 * Test SSH service functionality
 */
async function testSSHAccess(container, victimIP) {
  const result = { passed: false, details: [] };

  try {
    const sshTest = execSync(
      `docker exec ${container} timeout 5 nc -zv ${victimIP} 22`,
      { encoding: 'utf-8', timeout: 10000 }
    );

    if (sshTest.includes('open') || sshTest.includes('succeeded')) {
      result.passed = true;
      result.details.push('✅ SSH service is accessible');
    } else {
      result.details.push('❌ SSH service not accessible');
    }
  } catch (error) {
    const errorOutput = error.stderr?.toString() || '';
    if (errorOutput.includes('open') || errorOutput.includes('succeeded')) {
      result.passed = true;
      result.details.push('✅ SSH service is accessible');
    } else {
      result.details.push('❌ SSH connection failed');
    }
  }

  return result;
}

/**
 * Test web service functionality
 */
async function testWebAccess(container, victimIP) {
  const result = { passed: false, details: [] };

  try {
    // Try port 80
    const webTest = execSync(
      `docker exec ${container} timeout 5 curl -s -o /dev/null -w "%{http_code}" http://${victimIP}`,
      { encoding: 'utf-8', timeout: 10000 }
    ).trim();

    const statusCode = parseInt(webTest);
    if (statusCode >= 200 && statusCode < 500) {
      result.passed = true;
      result.details.push(`✅ Web service is responding (HTTP ${statusCode})`);
    } else {
      result.details.push(`⚠️ Web service returned HTTP ${statusCode}`);
    }
  } catch (error) {
    result.details.push('❌ Web service not accessible on port 80');
  }

  return result;
}

/**
 * Detect which ports to check based on challenge name
 */
function detectPortsFromChallenge(challengeName) {
  const name = challengeName.toLowerCase();
  const ports = [];

  if (name.includes('ftp')) ports.push(21);
  if (name.includes('ssh')) ports.push(22);
  if (name.includes('web') || name.includes('sql') || name.includes('xss')) ports.push(80, 443);
  if (name.includes('smb') || name.includes('samba') || name.includes('eternal')) ports.push(445, 139);
  if (name.includes('mysql')) ports.push(3306);
  if (name.includes('postgres')) ports.push(5432);
  if (name.includes('redis')) ports.push(6379);
  if (name.includes('mongo')) ports.push(27017);

  // Default to common ports if none detected
  if (ports.length === 0) {
    ports.push(80, 22, 21);
  }

  return [...new Set(ports)]; // Remove duplicates
}

/**
 * Generate human-readable validation report
 */
function generateValidationReport(results) {
  let report = '\n' + '='.repeat(60) + '\n';
  report += '🧪 CHALLENGE VALIDATION REPORT\n';
  report += '='.repeat(60) + '\n\n';

  if (results.success) {
    report += '✅ VALIDATION PASSED - Challenge is ready for users\n\n';
  } else {
    report += '❌ VALIDATION FAILED - Issues found, challenge not ready\n\n';
  }

  results.tests.forEach(test => {
    report += `\n📋 ${test.name}: ${test.passed ? '✅ PASS' : '❌ FAIL'}\n`;
    test.details.forEach(detail => {
      report += `   ${detail}\n`;
    });
  });

  if (results.errors.length > 0) {
    report += '\n\n⚠️ ERRORS:\n';
    results.errors.forEach(error => {
      report += `   - ${error}\n`;
    });
  }

  if (results.warnings.length > 0) {
    report += '\n\n⚠️ WARNINGS:\n';
    results.warnings.forEach(warning => {
      report += `   - ${warning}\n`;
    });
  }

  report += '\n' + '='.repeat(60) + '\n';

  return report;
}

export default { validateChallenge };
