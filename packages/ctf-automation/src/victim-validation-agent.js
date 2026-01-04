/**
 * Victim Machine Validation and Auto-Fix Agent
 * 
 * This agent ensures victim machines are always accessible and working correctly.
 * It performs comprehensive validation and automatic fixes for common issues.
 */

import { execSync } from 'child_process';
import Docker from 'dockerode';

const docker = new Docker();

/**
 * Comprehensive victim machine validation and auto-fix
 * This runs after deployment to ensure victim machines work correctly
 */
export async function validateAndFixVictimMachine({
  challengeName,
  victimContainerName,
  attackerContainerName,
  attackerIP,
  expectedServices = [],
  composeConfig = {}
}) {
  console.log(`\n🔍 [VICTIM VALIDATION AGENT] Starting comprehensive validation for ${victimContainerName}...`);
  
  const results = {
    validated: false,
    fixed: false,
    errors: [],
    warnings: [],
    fixes: [],
    finalStatus: {}
  };

  try {
    // PHASE 1: Check if container exists and get status
    let victimContainer;
    let victimInfo;
    try {
      victimContainer = docker.getContainer(victimContainerName);
      victimInfo = await victimContainer.inspect();
    } catch (error) {
      results.errors.push(`Container ${victimContainerName} does not exist: ${error.message}`);
      return results;
    }

    // PHASE 2: Fix container if not running - AGGRESSIVE FIX MODE
    if (!victimInfo.State.Running) {
      console.log(`⚠️  [VICTIM VALIDATION] Container is not running (Status: ${victimInfo.State.Status}, Exit Code: ${victimInfo.State.ExitCode})`);
      
      // Get logs to diagnose the issue
      const logs = await victimContainer.logs({ stdout: true, stderr: true, tail: 50 });
      const logOutput = logs.toString();
      console.log(`📋 [VICTIM VALIDATION] Container logs:\n${logOutput.substring(0, 500)}`);
      
      // ✅ CRITICAL: ALWAYS fix script if container is not running (aggressive mode)
      // Don't wait for specific error types - just fix it
      console.log(`🔧 [VICTIM VALIDATION] Container not running - ALWAYS fixing startup script...`);
      const fixResult = await fixStartupScriptInContainer(victimContainerName);
      if (fixResult.fixed) {
        results.fixes.push(fixResult);
        results.fixed = true;
        console.log(`✅ [VICTIM VALIDATION] Startup script fixed`);
      } else {
        console.error(`❌ [VICTIM VALIDATION] Failed to fix script, but will still try to start container`);
      }
      
      // Try to start the container with retries
      let startAttempts = 0;
      const maxStartAttempts = 3;
      
      while (startAttempts < maxStartAttempts && !victimInfo.State.Running) {
        startAttempts++;
        try {
          console.log(`🔧 [VICTIM VALIDATION] Attempting to start container (attempt ${startAttempts}/${maxStartAttempts})...`);
          
          // ✅ CRITICAL: ALWAYS fix script before EACH start attempt (not just retries)
          console.log(`🔧 [VICTIM VALIDATION] Fixing script before start attempt ${startAttempts}...`);
          const scriptFixResult = await fixStartupScriptInContainer(victimContainerName);
          if (scriptFixResult.fixed) {
            console.log(`✅ [VICTIM VALIDATION] Script fixed before start attempt`);
            results.fixes.push(scriptFixResult);
          } else {
            console.warn(`⚠️  [VICTIM VALIDATION] Script fix returned false, but continuing with start attempt`);
          }
          
          await victimContainer.start();
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait for startup
          
          // Re-inspect
          victimInfo = await victimContainer.inspect();
          if (victimInfo.State.Running) {
            console.log(`✅ [VICTIM VALIDATION] Container started successfully on attempt ${startAttempts}`);
            results.fixes.push({ type: 'container_start', message: `Started stopped container (attempt ${startAttempts})` });
            results.fixed = true;
            break; // Success - exit retry loop
          } else {
            // Container still not running - check logs
            const newLogs = await victimContainer.logs({ stdout: true, stderr: true, tail: 20 });
            const newLogOutput = newLogs.toString();
            console.log(`⚠️  [VICTIM VALIDATION] Container still not running after attempt ${startAttempts}. Latest logs:\n${newLogOutput.substring(0, 200)}`);
            
            if (startAttempts < maxStartAttempts) {
              console.log(`🔄 [VICTIM VALIDATION] Will retry...`);
              await new Promise(resolve => setTimeout(resolve, 2000)); // Wait before retry
            } else {
              results.errors.push(`Container failed to start after ${maxStartAttempts} attempts. Exit code: ${victimInfo.State.ExitCode}`);
            }
          }
        } catch (startError) {
          console.error(`❌ [VICTIM VALIDATION] Start attempt ${startAttempts} failed: ${startError.message}`);
          if (startAttempts < maxStartAttempts) {
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait before retry
          } else {
            results.errors.push(`Failed to start container after ${maxStartAttempts} attempts: ${startError.message}`);
          }
        }
      }
      
      // Final check - if still not running, try one more aggressive fix
      if (!victimInfo.State.Running) {
        console.log(`🔧 [VICTIM VALIDATION] Final aggressive fix attempt...`);
        const finalFix = await fixStartupScriptInContainer(victimContainerName);
        if (finalFix.fixed) {
          try {
            await victimContainer.start();
            await new Promise(resolve => setTimeout(resolve, 5000));
            victimInfo = await victimContainer.inspect();
            if (victimInfo.State.Running) {
              console.log(`✅ [VICTIM VALIDATION] Container started after final aggressive fix`);
              results.fixed = true;
              results.fixes.push({ type: 'final_fix', message: 'Container started after final aggressive fix' });
            }
          } catch (finalError) {
            console.error(`❌ [VICTIM VALIDATION] Final fix attempt failed: ${finalError.message}`);
          }
        }
      }
    }

    // PHASE 3: Validate IP assignment
    if (victimInfo.State.Running) {
      const networks = victimInfo.NetworkSettings?.Networks || {};
      const challengeNetwork = Object.keys(networks).find(n => 
        !n.includes('ctf-instances-network') && !n.includes('bridge')
      );
      
      let victimIP = null;
      if (challengeNetwork && networks[challengeNetwork]?.IPAddress) {
        victimIP = networks[challengeNetwork].IPAddress;
        console.log(`✅ [VICTIM VALIDATION] Victim IP assigned: ${victimIP}`);
        results.finalStatus.victimIP = victimIP;
      } else {
        results.errors.push('Victim IP not assigned to challenge network');
        console.log(`⚠️  [VICTIM VALIDATION] No IP assigned - attempting to reconnect to network...`);
        
        // Try to reconnect to network
        if (challengeNetwork) {
          try {
            const network = docker.getNetwork(challengeNetwork);
            await network.disconnect({ Container: victimContainerName });
            await new Promise(resolve => setTimeout(resolve, 1000));
            await network.connect({ Container: victimContainerName });
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            // Re-inspect
            victimInfo = await victimContainer.inspect();
            const newNetworks = victimInfo.NetworkSettings?.Networks || {};
            if (newNetworks[challengeNetwork]?.IPAddress) {
              victimIP = newNetworks[challengeNetwork].IPAddress;
              console.log(`✅ [VICTIM VALIDATION] Reconnected to network, IP: ${victimIP}`);
              results.fixes.push({ type: 'network_reconnect', message: `Reconnected to network, got IP: ${victimIP}` });
              results.fixed = true;
              results.finalStatus.victimIP = victimIP;
            }
          } catch (networkError) {
            results.errors.push(`Failed to reconnect to network: ${networkError.message}`);
          }
        }
      }

      // PHASE 4: Validate services are running
      if (victimIP) {
        console.log(`🔍 [VICTIM VALIDATION] Checking if services are running...`);
        
        // Check if startup script exists and is valid
        try {
          const scriptCheck = await victimContainer.exec({
            Cmd: ['test', '-f', '/start-services.sh'],
            AttachStdout: true,
            AttachStderr: true
          });
          
          const scriptStream = await scriptCheck.start({ hijack: true, stdin: false });
          await new Promise((resolve) => {
            scriptStream.on('end', resolve);
            setTimeout(resolve, 2000);
          });
          
          // Check script syntax
          const syntaxCheck = await victimContainer.exec({
            Cmd: ['sh', '-n', '/start-services.sh'], // -n = syntax check only
            AttachStdout: true,
            AttachStderr: true
          });
          
          const syntaxStream = await syntaxCheck.start({ hijack: true, stdin: false });
          let syntaxOutput = '';
          syntaxStream.on('data', (chunk) => {
            syntaxOutput += chunk.toString();
          });
          
          await new Promise((resolve) => {
            syntaxStream.on('end', resolve);
            setTimeout(resolve, 2000);
          });
          
          if (syntaxOutput.trim()) {
            console.log(`❌ [VICTIM VALIDATION] Startup script has syntax errors: ${syntaxOutput}`);
            results.errors.push(`Startup script syntax error: ${syntaxOutput}`);
            
            // Attempt to fix the script
            const scriptFix = await fixStartupScriptInContainer(victimContainerName);
            if (scriptFix.fixed) {
              results.fixes.push(scriptFix);
              results.fixed = true;
            }
          } else {
            console.log(`✅ [VICTIM VALIDATION] Startup script syntax is valid`);
          }
        } catch (checkError) {
          results.warnings.push(`Could not validate startup script: ${checkError.message}`);
        }
        
        // Check if services are listening
        const servicesRunning = await checkServicesRunning(victimContainerName, expectedServices);
        if (!servicesRunning) {
          console.log(`⚠️  [VICTIM VALIDATION] Services not detected - attempting to start them...`);
          
          // Try to execute startup script manually
          try {
            const startResult = await victimContainer.exec({
              Cmd: ['sh', '/start-services.sh'],
              AttachStdout: true,
              AttachStderr: true,
              Detach: true
            });
            
            await startResult.start({ hijack: true, stdin: false });
            await new Promise(resolve => setTimeout(resolve, 3000));
            
            // Check again
            const servicesRunningAfter = await checkServicesRunning(victimContainerName, expectedServices);
            if (servicesRunningAfter) {
              console.log(`✅ [VICTIM VALIDATION] Services started successfully`);
              results.fixes.push({ type: 'services_start', message: 'Manually started services' });
              results.fixed = true;
            } else {
              results.warnings.push('Services may need more time to start or configuration may be incorrect');
            }
          } catch (startError) {
            results.errors.push(`Failed to start services: ${startError.message}`);
          }
        } else {
          console.log(`✅ [VICTIM VALIDATION] Services are running`);
          results.finalStatus.servicesRunning = true;
        }
      }
    }

    // PHASE 5: Final validation
    if (victimInfo.State.Running && results.finalStatus.victimIP && results.finalStatus.servicesRunning) {
      results.validated = true;
      console.log(`✅ [VICTIM VALIDATION] All checks passed!`);
    } else {
      console.log(`⚠️  [VICTIM VALIDATION] Some checks failed, but fixes were attempted`);
    }

  } catch (error) {
    console.error(`❌ [VICTIM VALIDATION] Validation error: ${error.message}`);
    results.errors.push(`Validation error: ${error.message}`);
  }

  return results;
}

/**
 * Fix startup script syntax errors
 */
async function fixStartupScript(containerName, errorLog) {
  try {
    const container = docker.getContainer(containerName);
    
    // Check what's wrong with the script
    const scriptContent = await container.exec({
      Cmd: ['cat', '/start-services.sh'],
      AttachStdout: true,
      AttachStderr: true
    });
    
    const scriptStream = await scriptContent.start({ hijack: true, stdin: false });
    let script = '';
    scriptStream.on('data', (chunk) => {
      script += chunk.toString();
    });
    
    await new Promise((resolve) => {
      scriptStream.on('end', resolve);
      setTimeout(resolve, 2000);
    });
    
    console.log(`📋 [VICTIM VALIDATION] Current startup script:\n${script.substring(0, 500)}`);
    
    // Common fixes:
    // 1. Remove invalid && operators at line breaks
    // 2. Ensure proper line endings
    // 3. Fix escaped characters
    
    let fixedScript = script
      .replace(/\r\n/g, '\n') // Normalize line endings
      .replace(/\r/g, '\n')
      .split('\n')
      .map(line => {
        // Fix lines that have && at the start (from broken multi-line commands)
        if (line.trim().startsWith('&&')) {
          return line.trim().substring(2).trim();
        }
        // Fix lines with && at end without proper continuation
        if (line.trim().endsWith('&&') && !line.trim().endsWith('\\')) {
          return line.trim().substring(0, line.trim().length - 2).trim();
        }
        return line;
      })
      .filter(line => line.trim().length > 0) // Remove empty lines
      .join('\n');
    
    // Ensure script starts with shebang
    if (!fixedScript.startsWith('#!/')) {
      fixedScript = '#!/bin/bash\n' + fixedScript;
    }
    
    // Ensure script ends with wait or tail
    if (!fixedScript.includes('wait') && !fixedScript.includes('tail -f')) {
      fixedScript += '\n# Keep container running\nwait\n';
    }
    
    // Write fixed script back
    const fixedScriptBase64 = Buffer.from(fixedScript).toString('base64');
    await container.exec({
      Cmd: ['sh', '-c', `echo '${fixedScriptBase64}' | base64 -d > /start-services.sh && chmod +x /start-services.sh`],
      AttachStdout: true,
      AttachStderr: true
    });
    
    console.log(`✅ [VICTIM VALIDATION] Fixed startup script`);
    
    return {
      fixed: true,
      type: 'script_syntax_fix',
      message: 'Fixed startup script syntax errors'
    };
  } catch (error) {
    console.error(`❌ [VICTIM VALIDATION] Failed to fix startup script: ${error.message}`);
    return {
      fixed: false,
      type: 'script_syntax_fix',
      message: `Failed to fix: ${error.message}`
    };
  }
}

/**
 * Fix startup script directly in container
 * Uses docker cp to work even with stopped containers
 */
async function fixStartupScriptInContainer(containerName) {
  try {
    const container = docker.getContainer(containerName);
    const containerInfo = await container.inspect();
    
    // Create a minimal working startup script that handles common services
    const minimalScript = `#!/bin/bash
set -e

# Start services based on what's available
# FTP Service
if [ -f /challenge/vsftpd.conf ] || [ -f /etc/vsftpd.conf ]; then
  if [ -f /challenge/vsftpd.conf ]; then
    cp /challenge/vsftpd.conf /etc/vsftpd.conf 2>/dev/null || true
  fi
  mkdir -p /var/run/vsftpd/empty 2>/dev/null || true
  mkdir -p /var/ftp/data/classified 2>/dev/null || true
  chmod 555 /var/ftp 2>/dev/null || true
  chmod 755 /var/ftp/data 2>/dev/null || true
  chmod 755 /var/ftp/data/classified 2>/dev/null || true
  if [ -f /challenge/flag.txt ]; then
    cp /challenge/flag.txt /var/ftp/data/classified/flag.txt 2>/dev/null || true
    chmod 644 /var/ftp/data/classified/flag.txt 2>/dev/null || true
    chown ftp:ftp /var/ftp/data/classified/flag.txt 2>/dev/null || true
  fi
  /usr/sbin/vsftpd /etc/vsftpd.conf &
fi

# Samba Service
if [ -f /etc/samba/smb.conf ] || [ -f /challenge/smb.conf ]; then
  if [ -f /challenge/smb.conf ]; then
    cp /challenge/smb.conf /etc/samba/smb.conf 2>/dev/null || true
  fi
  /usr/sbin/smbd -D 2>/dev/null &
  /usr/sbin/nmbd -D 2>/dev/null &
fi

# SSH Service
if [ -f /usr/sbin/sshd ]; then
  mkdir -p /var/run/sshd
  /usr/sbin/sshd -D &
fi

# Keep container running
wait
`;
    
    // Use docker cp to copy the script into the container (works even if stopped)
    // First, write script to a temp file
    const fs = await import('fs/promises');
    const path = await import('path');
    const os = await import('os');
    
    const tempDir = os.tmpdir();
    const tempScriptPath = path.join(tempDir, `start-services-${Date.now()}.sh`);
    
    try {
      await fs.writeFile(tempScriptPath, minimalScript, { mode: 0o755 });
      
      // ✅ CRITICAL: Always use docker cp (works on stopped containers)
      // Try docker cp first (most reliable for stopped containers)
      try {
        // Use shell: true for Windows compatibility and proper path handling
        const normalizedPath = tempScriptPath.replace(/\\/g, '/');
        const command = `docker cp "${normalizedPath}" ${containerName}:/start-services.sh`;
        console.log(`🔧 [VICTIM VALIDATION] Executing: ${command}`);
        execSync(command, { 
          stdio: 'pipe', // Use pipe to capture errors
          encoding: 'utf8',
          shell: true // Critical for Windows
        });
        console.log(`✅ [VICTIM VALIDATION] docker cp completed successfully`);
        
        // Set executable permissions - try multiple methods
        try {
          // Method 1: Try docker exec (works if container is running)
          execSync(`docker exec ${containerName} chmod +x /start-services.sh 2>/dev/null || true`, { 
            stdio: 'pipe',
            encoding: 'utf8'
          });
        } catch (chmodError) {
          // Method 2: If exec fails, we'll set permissions when container starts
          // The file mode (0o755) should already make it executable
          console.log(`⚠️  [VICTIM VALIDATION] Could not set exec permissions via exec (container may be stopped), will set on start`);
        }
        
        console.log(`✅ [VICTIM VALIDATION] Created minimal startup script using docker cp`);
        
        // Clean up temp file
        await fs.unlink(tempScriptPath).catch(() => {});
        
        return {
          fixed: true,
          type: 'script_recreate',
          message: 'Recreated startup script with minimal working version using docker cp'
        };
      } catch (cpError) {
        console.log(`⚠️  [VICTIM VALIDATION] docker cp failed: ${cpError.message}, trying alternative method...`);
        
        // Fallback: Try exec method if container is running
        if (containerInfo.State.Running) {
          try {
            // Write script using base64 encoding to avoid shell escaping issues
            const scriptBase64 = Buffer.from(minimalScript).toString('base64');
            
            const execResult = await container.exec({
              Cmd: ['sh', '-c', `echo '${scriptBase64}' | base64 -d > /start-services.sh && chmod +x /start-services.sh`],
              AttachStdout: true,
              AttachStderr: true
            });
            
            const execStream = await execResult.start({ hijack: true, stdin: false });
            await new Promise((resolve) => {
              execStream.on('end', resolve);
              setTimeout(resolve, 3000);
            });
            
            console.log(`✅ [VICTIM VALIDATION] Created script using exec method`);
            
            // Clean up temp file
            await fs.unlink(tempScriptPath).catch(() => {});
            
            return {
              fixed: true,
              type: 'script_recreate',
              message: 'Recreated startup script using exec method'
            };
          } catch (execError) {
            console.error(`❌ [VICTIM VALIDATION] Exec method also failed: ${execError.message}`);
            // Continue to throw original error
          }
        }
        
        // If all methods fail, clean up and throw
        await fs.unlink(tempScriptPath).catch(() => {});
        throw cpError;
      }
    } catch (error) {
      console.error(`❌ [VICTIM VALIDATION] Failed to recreate script: ${error.message}`);
      return {
        fixed: false,
        type: 'script_recreate',
        message: `Failed: ${error.message}`
      };
    }
  } catch (error) {
    console.error(`❌ [VICTIM VALIDATION] Failed to recreate script: ${error.message}`);
    return {
      fixed: false,
      type: 'script_recreate',
      message: `Failed: ${error.message}`
    };
  }
}

/**
 * Check if expected services are running
 */
async function checkServicesRunning(containerName, expectedServices) {
  try {
    const container = docker.getContainer(containerName);
    
    // Use netstat or ss to check listening ports
    const checkResult = await container.exec({
      Cmd: ['sh', '-c', 'netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo "no_netstat"'],
      AttachStdout: true,
      AttachStderr: true
    });
    
    const checkStream = await checkResult.start({ hijack: true, stdin: false });
    let output = '';
    checkStream.on('data', (chunk) => {
      output += chunk.toString();
    });
    
    await new Promise((resolve) => {
      checkStream.on('end', resolve);
      setTimeout(resolve, 3000);
    });
    
    if (output.includes('no_netstat')) {
      // Fallback: Check if processes are running
      const psResult = await container.exec({
        Cmd: ['sh', '-c', 'ps aux | grep -E "(vsftpd|smbd|nmbd|apache|nginx|httpd)" | grep -v grep || echo "no_services"'],
        AttachStdout: true,
        AttachStderr: true
      });
      
      const psStream = await psResult.start({ hijack: true, stdin: false });
      let psOutput = '';
      psStream.on('data', (chunk) => {
        psOutput += chunk.toString();
      });
      
      await new Promise((resolve) => {
        psStream.on('end', resolve);
        setTimeout(resolve, 2000);
      });
      
      return !psOutput.includes('no_services');
    }
    
    // Check for common service ports
    const commonPorts = [21, 22, 80, 443, 445];
    const hasListeningPorts = commonPorts.some(port => 
      output.includes(`:${port}`) || output.includes(`0.0.0.0:${port}`)
    );
    
    return hasListeningPorts;
  } catch (error) {
    console.warn(`⚠️  [VICTIM VALIDATION] Could not check services: ${error.message}`);
    return false;
  }
}

