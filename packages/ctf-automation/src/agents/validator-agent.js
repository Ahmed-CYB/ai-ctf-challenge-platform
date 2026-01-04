import OpenAI from 'openai';
import Docker from 'dockerode';
import { DockerManager } from '../docker-manager.js';
import { gitManager } from '../git-manager.js';
import { troubleshootChallenge } from './troubleshoot-agent.js';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const dockerManager = new DockerManager();

const VALIDATOR_SYSTEM_PROMPT = `You are an expert CTF challenge validator. Your job is to test if a deployed CTF challenge is working correctly and ready for users.

You will receive:
1. Challenge metadata (name, description, category, difficulty)
2. Deployment information (victim IP, attacker IP, subnet)
3. Test results from automated checks
4. Flag verification results

Your task:
- Analyze the test results to determine if the challenge is functioning
- Check if containers are running
- Verify network connectivity between attacker and victim
- CRITICAL: Verify the flag is correctly placed and accessible
- Assess if the challenge appears exploitable

VALIDATION CRITERIA (Be reasonable and forgiving):

✅ MUST PASS (Critical):
- Victim container is running
- Attacker container is running
- FLAG IS FOUND and MATCHES expected value
- Containers are on the same network

⚠️ NICE TO HAVE (Not critical for PASS):
- HTTP service responding (some challenges may not use HTTP)
- Ping connectivity (some containers may have ICMP disabled)
- VNC service (usually takes time to start)

IMPORTANT: 
- If flag is found and matches, and containers are running → LIKELY PASS
- If flag is not found or doesn't match → FAIL (critical issue)
- If containers are running but network tests fail → Still PASS if flag is correct (network restrictions are normal)
- Focus on whether the challenge is FUNCTIONAL, not perfect

Response format (JSON):
{
  "status": "PASS" or "FAIL",
  "verdict": "Brief summary of why it passed or failed",
  "details": "Detailed explanation focusing on flag verification and container status",
  "recommendations": ["List of recommendations if failed, empty array if passed"],
  "readyForUser": true or false,
  "confidence": "high" or "medium" or "low"
}`;

export class ValidatorAgent {
  constructor() {
    this.docker = new Docker();
  }

  async validateChallenge(challengeName, conversationHistory = [], progressCallback = null) {
    try {
      console.log(`\n🔍 Starting validation for challenge: ${challengeName}`);
      if (progressCallback) progressCallback({ step: 'validation-start', message: '\n🔍 Starting automated validation...' });

      // Step 1: Get challenge metadata
      if (progressCallback) progressCallback({ step: 'metadata', message: '📋 Loading challenge metadata...' });
      const challengeMetadata = await gitManager.getChallengeMetadata(challengeName);
      if (!challengeMetadata) {
        return {
          status: 'FAIL',
          verdict: 'Challenge metadata not found',
          details: `Could not find metadata for challenge: ${challengeName}`,
          recommendations: ['Ensure challenge was created properly with metadata.json'],
          readyForUser: false
        };
      }

      console.log(`📋 Challenge metadata loaded: ${challengeMetadata.name}`);
      if (progressCallback) progressCallback({ step: 'metadata-loaded', message: `✅ Loaded metadata for "${challengeMetadata.title}"` });

      // Step 2: Deploy multi-container setup (victim + attacker)
      console.log(`🚀 Deploying multi-container environment...`);
      if (progressCallback) progressCallback({ step: 'deploy-start', message: '🐳 Deploying Docker containers (victim + Kali Linux)...' });
      
      // Use deployFromCompose with private IPs - userId 'validator' for validation tests
      const deployment = await dockerManager.deployFromCompose(challengeName, 'validator', progressCallback);
      
      if (!deployment || !deployment.victimContainerName || !deployment.attackerContainerName) {
        return {
          status: 'FAIL',
          verdict: 'Deployment failed',
          details: 'Could not deploy containers successfully',
          recommendations: ['Check Docker is running', 'Verify docker-compose.yml syntax', 'Check container logs'],
          readyForUser: false
        };
      }

      console.log(`✅ Containers deployed:`);
      console.log(`   Victim: ${deployment.victimUrl}`);
      console.log(`   Attacker: ${deployment.attackerContainerName}`);
      if (progressCallback) progressCallback({ step: 'deploy-complete', message: `✅ Containers deployed\n  🎯 Victim: ${deployment.victimContainerName}\n  🥷 Kali: ${deployment.attackerContainerName}` });

      // Step 3: Wait for services to start - give plenty of time
      console.log(`⏳ Waiting for services to initialize (30 seconds)...`);
      if (progressCallback) progressCallback({ step: 'waiting', message: '⏳ Waiting for services to initialize (30 seconds)...' });
      await this.sleep(30000); // Give containers 30 seconds to fully start

      // Step 4: Run automated tests
      console.log(`🧪 Running automated tests...`);
      if (progressCallback) progressCallback({ step: 'testing', message: '🧪 Running automated connectivity tests...' });
      const testResults = await this.runAutomatedTests(deployment, progressCallback);

      // Step 4.5: Verify flag location
      console.log(`🚩 Verifying flag location...`);
      if (progressCallback) progressCallback({ step: 'flag-check', message: '🚩 Verifying flag location...' });
      const flagCheck = await this.verifyFlagLocation(deployment, challengeMetadata, progressCallback);
      testResults.flagVerification = flagCheck;

      // Step 5: Use AI to analyze test results
      console.log(`🤖 Analyzing test results with AI...`);
      if (progressCallback) progressCallback({ step: 'ai-analyze', message: '🤖 AI analyzing test results...' });
      const messages = [
        { role: 'system', content: VALIDATOR_SYSTEM_PROMPT },
        { role: 'user', content: `Challenge Metadata:\n${JSON.stringify(challengeMetadata, null, 2)}\n\nDeployment Info:\n${JSON.stringify(deployment, null, 2)}\n\nTest Results:\n${JSON.stringify(testResults, null, 2)}\n\nBased on these results, determine if the challenge is ready for users.` }
      ];

      const completion = await openai.chat.completions.create({
        model: process.env.OPENAI_MODEL || 'gpt-4',
        messages: messages,
        temperature: 0.3,
        max_tokens: 1500
      });

      let aiResponse = completion.choices[0].message.content;
      
      // Remove markdown code blocks if present
      aiResponse = aiResponse.replace(/^```(?:json)?\s*\n?/gm, '').replace(/\n?```\s*$/gm, '');
      
      let validationResult;

      try {
        validationResult = JSON.parse(aiResponse);
      } catch (parseError) {
        console.error('Failed to parse AI response:', aiResponse);
        validationResult = {
          status: 'FAIL',
          verdict: 'Validation analysis failed',
          details: aiResponse,
          recommendations: ['AI response could not be parsed'],
          readyForUser: false
        };
      }

      // Add deployment info to result
      validationResult.deployment = deployment;
      validationResult.testResults = testResults;
      validationResult.challengeMetadata = challengeMetadata;

      console.log(`\n${validationResult.status === 'PASS' ? '✅' : '❌'} Validation ${validationResult.status}: ${validationResult.verdict}`);

      // If validation failed, cleanup containers
      if (validationResult.status === 'FAIL') {
        console.log(`🧹 Cleaning up failed deployment...`);
        await dockerManager.cleanupMultiContainer(challengeName);
      }

      return validationResult;

    } catch (error) {
      console.error('Validator error:', error);
      return {
        status: 'FAIL',
        verdict: 'Validation process encountered an error',
        details: error.message,
        recommendations: ['Check logs for detailed error information', 'Verify all services are running'],
        readyForUser: false,
        error: error.message
      };
    }
  }

  async runAutomatedTests(deployment, progressCallback = null) {
    const results = {
      victimAccessible: false,
      attackerAccessible: false,
      victimResponseTime: null,
      attackerResponseTime: null,
      networkConnectivity: false,
      victimToAttackerPing: false,
      attackerToVictimPing: false,
      errors: []
    };

    try {
      // Test 1: Check if victim container is running
      console.log(`  Testing victim container: ${deployment.victimContainerName}...`);
      if (progressCallback) progressCallback({ step: 'test-victim', message: '  🎯 Testing victim container...' });
      
      const victimContainer = this.docker.getContainer(deployment.victimContainerName);
      const victimInfo = await victimContainer.inspect();
      
      results.victimAccessible = victimInfo.State.Running;
      results.victimIP = deployment.victimIP;
      
      if (victimInfo.State.Running) {
        console.log(`    ✓ Victim container is running at ${deployment.victimIP}`);
        if (progressCallback) progressCallback({ step: 'test-victim-success', message: `    ✅ Victim running at ${deployment.victimIP}` });
        
        // Test if victim service is listening on port 8080
        try {
          const exec = await victimContainer.exec({
            Cmd: ['sh', '-c', 'netstat -tuln 2>/dev/null | grep :8080 || ss -tuln 2>/dev/null | grep :8080 || echo "no-netstat"'],
            AttachStdout: true,
            AttachStderr: true
          });
          const stream = await exec.start();
          let output = '';
          stream.on('data', chunk => output += chunk.toString());
          await new Promise(resolve => stream.on('end', resolve));
          
          if (output.includes(':8080') || output.includes('no-netstat')) {
            console.log(`    ✓ Service appears to be running (port 8080)`);
            results.victimServiceRunning = true;
          }
        } catch (err) {
          console.log(`    ⚠️  Could not verify service port: ${err.message}`);
        }
      } else {
        console.log(`    ✗ Victim container is not running`);
        results.errors.push('Victim container is not running');
        if (progressCallback) progressCallback({ step: 'test-victim-fail', message: `    ❌ Victim not running` });
      }
    } catch (error) {
      console.log(`    ✗ Victim container check failed: ${error.message}`);
      results.errors.push(`Victim container error: ${error.message}`);
      if (progressCallback) progressCallback({ step: 'test-victim-fail', message: `    ❌ Victim check failed` });
    }

    try {
      // Test 2: Check if attacker (Kali) container is running
      console.log(`  Testing attacker container: ${deployment.attackerContainerName}...`);
      if (progressCallback) progressCallback({ step: 'test-kali', message: '  🥷 Testing Kali container...' });
      
      const attackerContainer = this.docker.getContainer(deployment.attackerContainerName);
      const attackerInfo = await attackerContainer.inspect();
      
      results.attackerAccessible = attackerInfo.State.Running;
      results.attackerIP = deployment.attackerIP;
      
      if (attackerInfo.State.Running) {
        console.log(`    ✓ Attacker container is running at ${deployment.attackerIP}`);
        if (progressCallback) progressCallback({ step: 'test-kali-success', message: `    ✅ Kali running at ${deployment.attackerIP}` });
        
        // Test VNC service
        try {
          const exec = await attackerContainer.exec({
            Cmd: ['sh', '-c', 'ps aux | grep vnc | grep -v grep || echo "no-vnc"'],
            AttachStdout: true,
            AttachStderr: true
          });
          const stream = await exec.start();
          let output = '';
          stream.on('data', chunk => output += chunk.toString());
          await new Promise(resolve => stream.on('end', resolve));
          
          if (output.includes('vnc') || output.includes('Xvnc')) {
            console.log(`    ✓ VNC service is running`);
            results.vncServiceRunning = true;
          }
        } catch (err) {
          console.log(`    ⚠️  Could not verify VNC service: ${err.message}`);
        }
      } else {
        console.log(`    ✗ Attacker container is not running`);
        results.errors.push('Attacker container is not running');
        if (progressCallback) progressCallback({ step: 'test-kali-fail', message: `    ❌ Kali not running` });
      }
    } catch (error) {
      console.log(`    ✗ Attacker container check failed: ${error.message}`);
      results.errors.push(`Attacker container error: ${error.message}`);
      if (progressCallback) progressCallback({ step: 'test-kali-fail', message: `    ❌ Kali check failed` });
    }

    // Test 3: Check network connectivity (both containers in same network)
    try {
      console.log(`  Testing network connectivity...`);
      if (progressCallback) progressCallback({ step: 'test-network', message: '  🌐 Testing network connectivity...' });
      const networkInfo = await dockerManager.getNetworkInfo(deployment.networkName);
      if (networkInfo && networkInfo.containers && Object.keys(networkInfo.containers).length >= 2) {
        results.networkConnectivity = true;
        console.log(`    ✓ Containers are connected on network: ${deployment.networkName}`);
        if (progressCallback) progressCallback({ step: 'test-network-success', message: `    ✅ Network connected` });
      } else {
        console.log(`    ✗ Network connectivity issue`);
        results.errors.push('Containers not properly connected on shared network');
        if (progressCallback) progressCallback({ step: 'test-network-fail', message: `    ❌ Network issue` });
      }
    } catch (error) {
      console.log(`    ✗ Network check failed: ${error.message}`);
      results.errors.push(`Network check error: ${error.message}`);
      if (progressCallback) progressCallback({ step: 'test-network-fail', message: `    ❌ Network check failed` });
    }

    // Test 4: Realistic connectivity - ping from attacker to victim
    try {
      console.log(`  Testing attacker → victim connectivity...`);
      if (progressCallback) progressCallback({ step: 'test-ping', message: '  🔗 Testing attacker → victim ping...' });
      
      const attackerContainer = this.docker.getContainer(deployment.attackerContainerName);
      const exec = await attackerContainer.exec({
        Cmd: ['sh', '-c', `ping -c 3 -W 10 ${deployment.victimIP} 2>&1 || echo "PING_FAILED"`],
        AttachStdout: true,
        AttachStderr: true
      });
      
      const stream = await exec.start();
      let output = '';
      
      // Wait up to 60 seconds for ping to complete
      const timeoutPromise = new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Ping timeout')), 60000)
      );
      
      const dataPromise = new Promise(resolve => {
        stream.on('data', chunk => output += chunk.toString());
        stream.on('end', resolve);
      });
      
      await Promise.race([dataPromise, timeoutPromise]).catch(err => {
        console.log(`    ⚠️  Ping timeout: ${err.message}`);
      });
      
      output = output.replace(/[\x00-\x1F\x7F-\x9F]/g, '');
      
      if (output.includes('3 packets transmitted') && output.includes('3 received')) {
        results.attackerToVictimPing = true;
        console.log(`    ✓ Attacker can reach victim at ${deployment.victimIP}`);
        if (progressCallback) progressCallback({ step: 'test-ping-success', message: `    ✅ Attacker → Victim: Connected` });
      } else if (output.includes('received') || output.includes('bytes from')) {
        results.attackerToVictimPing = true;
        console.log(`    ✓ Attacker has partial connectivity to victim`);
        if (progressCallback) progressCallback({ step: 'test-ping-partial', message: `    ⚠️  Partial connectivity detected` });
      } else {
        console.log(`    ✗ Attacker cannot reach victim`);
        console.log(`    Debug: ${output.substring(0, 200)}`);
        results.errors.push(`Attacker cannot ping victim at ${deployment.victimIP}`);
        if (progressCallback) progressCallback({ step: 'test-ping-fail', message: `    ❌ No connectivity` });
      }
    } catch (error) {
      console.log(`    ⚠️  Ping test error: ${error.message}`);
      // Don't fail validation on ping errors - might be restricted
    }

    // Test 5: HTTP connectivity from attacker to victim
    if (results.attackerToVictimPing) {
      try {
        console.log(`  Testing HTTP connectivity from attacker to victim...`);
        if (progressCallback) progressCallback({ step: 'test-http', message: '  🌐 Testing HTTP access...' });
        
        const attackerContainer = this.docker.getContainer(deployment.attackerContainerName);
        const exec = await attackerContainer.exec({
          Cmd: ['sh', '-c', `curl -s -o /dev/null -w "%{http_code}" --max-time 30 http://${deployment.victimIP}:8080 2>&1 || echo "CURL_FAILED"`],
          AttachStdout: true,
          AttachStderr: true
        });
        
        const stream = await exec.start();
        let output = '';
        
        // Wait up to 60 seconds for curl
        const timeoutPromise = new Promise((_, reject) => 
          setTimeout(() => reject(new Error('Curl timeout')), 60000)
        );
        
        const dataPromise = new Promise(resolve => {
          stream.on('data', chunk => output += chunk.toString());
          stream.on('end', resolve);
        });
        
        await Promise.race([dataPromise, timeoutPromise]).catch(err => {
          console.log(`    ⚠️  Curl timeout: ${err.message}`);
        });
        
        output = output.replace(/[\x00-\x1F\x7F-\x9F]/g, '').trim();
        const statusCode = parseInt(output);
        
        if (statusCode >= 200 && statusCode < 600) {
          results.httpAccessible = true;
          results.httpStatusCode = statusCode;
          console.log(`    ✓ HTTP service responding with status ${statusCode}`);
          if (progressCallback) progressCallback({ step: 'test-http-success', message: `    ✅ HTTP accessible (${statusCode})` });
        } else {
          console.log(`    ⚠️  HTTP test returned: ${output}`);
          results.errors.push(`HTTP service not responding properly`);
        }
      } catch (error) {
        console.log(`    ⚠️  HTTP test error: ${error.message}`);
      }
    }

    if (progressCallback) progressCallback({ step: 'tests-complete', message: '✅ All tests completed' });
    return results;
  }

  async verifyFlagLocation(deployment, metadata, progressCallback) {
    try {
      const containerName = deployment.victimContainerName;
      const expectedFlag = metadata.flag;
      
      if (!containerName) {
        console.log(`  ⚠️  No victim container name provided`);
        return {
          found: false,
          error: 'No victim container name',
          message: 'Deployment did not provide victim container name'
        };
      }
      
      if (!expectedFlag) {
        console.log(`  ⚠️  No expected flag in metadata`);
        return {
          found: false,
          error: 'No expected flag',
          message: 'Challenge metadata does not contain flag'
        };
      }
      
      // Common flag locations based on challenge type
      const flagLocations = [
        '/flag.txt',
        '/root/flag.txt',
        '/home/flag.txt',
        '/home/ctf/flag.txt',
        '/home/ftp/flag.txt',
        '/srv/ftp/flag.txt',
        '/var/www/html/flag.txt',
        '/var/www/flag.txt',
        '/tmp/flag.txt',
        '/opt/flag.txt',
        '/app/flag.txt'
      ];
      
      console.log(`  🔍 Searching for flag in ${flagLocations.length} locations...`);
      console.log(`  Expected flag: ${expectedFlag}`);
      if (progressCallback) progressCallback({ step: 'flag-search', message: '  🔍 Searching common flag locations...' });
      
      const container = this.docker.getContainer(containerName);
      
      // First verify container exists and is running
      try {
        const containerInfo = await container.inspect();
        if (!containerInfo.State.Running) {
          console.log(`  ⚠️  Container is not running`);
          return {
            found: false,
            error: 'Container not running',
            message: 'Victim container is not running'
          };
        }
      } catch (err) {
        console.log(`  ⚠️  Container not found: ${err.message}`);
        return {
          found: false,
          error: 'Container not found',
          message: `Victim container ${containerName} not found`
        };
      }
      
      // Search all locations
      const searchResults = [];
      
      for (const location of flagLocations) {
        try {
          // Try to read flag from container
          const exec = await container.exec({
            Cmd: ['sh', '-c', `cat ${location} 2>/dev/null || echo "FILE_NOT_FOUND"`],
            AttachStdout: true,
            AttachStderr: true
          });
          
          const stream = await exec.start();
          let output = '';
          
          await new Promise((resolve, reject) => {
            stream.on('data', (chunk) => {
              output += chunk.toString();
            });
            stream.on('end', resolve);
            stream.on('error', reject);
          });
          
          // Clean output (remove Docker stream headers and control characters)
          output = output.replace(/[\x00-\x1F\x7F-\x9F]/g, '').trim();
          
          if (output && output !== 'FILE_NOT_FOUND' && output.length > 0) {
            console.log(`    📄 Found file at ${location}: "${output.substring(0, 100)}"`);
            searchResults.push({ location, content: output });
            
            // Check if flag matches
            if (output.includes(expectedFlag)) {
              console.log(`    ✅ Flag MATCH at ${location}`);
              if (progressCallback) progressCallback({ 
                step: 'flag-found', 
                message: `  ✅ Flag found at ${location}` 
              });
              return {
                found: true,
                location: location,
                content: output,
                matches: true,
                message: `Flag correctly placed at ${location}`
              };
            } else {
              console.log(`    ⚠️  Flag MISMATCH at ${location}`);
              console.log(`    Expected: "${expectedFlag}"`);
              console.log(`    Got: "${output}"`);
            }
          }
        } catch (err) {
          // File doesn't exist at this location, continue searching
          continue;
        }
      }
      
      // If we found files but none matched
      if (searchResults.length > 0) {
        console.log(`  ❌ Flag MISMATCH - Found ${searchResults.length} files but none matched expected flag`);
        if (progressCallback) progressCallback({ 
          step: 'flag-mismatch', 
          message: `  ❌ Flag content doesn't match (found ${searchResults.length} files)` 
        });
        return {
          found: true,
          location: searchResults[0].location,
          content: searchResults[0].content,
          matches: false,
          searchResults: searchResults,
          message: `Found ${searchResults.length} flag files but none matched expected flag "${expectedFlag}"`
        };
      }
      
      // No flag files found at all
      console.log(`  ❌ Flag NOT FOUND in any location`);
      if (progressCallback) progressCallback({ 
        step: 'flag-missing', 
        message: '  ❌ Flag not found in any common location' 
      });
      
      return {
        found: false,
        location: null,
        matches: false,
        searchedLocations: flagLocations,
        message: `Flag not found in any of the ${flagLocations.length} checked locations. Searched: ${flagLocations.slice(0, 5).join(', ')}...`
      };
      
    } catch (error) {
      if (progressCallback) progressCallback({ 
        step: 'flag-error', 
        message: `  ⚠️  Error checking flag: ${error.message}` 
      });
      return {
        found: false,
        error: error.message,
        message: `Error verifying flag location: ${error.message}`
      };
    }
  }

  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  formatValidationReport(validationResult) {
    const { status, verdict, details, recommendations, deployment, testResults, challengeMetadata } = validationResult;

    let report = `
╔════════════════════════════════════════════════════════════════╗
║           CTF CHALLENGE VALIDATION REPORT                      ║
╚════════════════════════════════════════════════════════════════╝

📦 Challenge: ${challengeMetadata?.name || 'Unknown'}
🏷️  Category: ${challengeMetadata?.category || 'Unknown'}
⭐ Difficulty: ${challengeMetadata?.difficulty || 'Unknown'}

═══════════════════════════════════════════════════════════════

${status === 'PASS' ? '✅ VALIDATION PASSED' : '❌ VALIDATION FAILED'}

${verdict}

${details}

═══════════════════════════════════════════════════════════════

🧪 TEST RESULTS:
`;

    if (testResults) {
      report += `
  🎯 Victim Service:
    - Accessible: ${testResults.victimAccessible ? '✓ YES' : '✗ NO'}
    - Response Time: ${testResults.victimResponseTime ? testResults.victimResponseTime + 'ms' : 'N/A'}
    - Status Code: ${testResults.victimStatusCode || 'N/A'}

  🥷 Attacker Machine (Kali Linux):
    - Accessible: ${testResults.attackerAccessible ? '✓ YES' : '✗ NO'}
    - Response Time: ${testResults.attackerResponseTime ? testResults.attackerResponseTime + 'ms' : 'N/A'}
    - Status Code: ${testResults.attackerStatusCode || 'N/A'}

  🌐 Network Connectivity:
    - Status: ${testResults.networkConnectivity ? '✓ CONNECTED' : '✗ DISCONNECTED'}
`;

      if (testResults.errors && testResults.errors.length > 0) {
        report += `\n  ⚠️  Errors Detected:\n`;
        testResults.errors.forEach(err => {
          report += `    - ${err}\n`;
        });
      }
    }

    if (deployment && status === 'PASS') {
      report += `
═══════════════════════════════════════════════════════════════

🚀 DEPLOYMENT INFORMATION:

  🎯 Victim (Challenge Target):
     URL: ${deployment.victimUrl}
     Container: ${deployment.victimContainerName}
     
  🥷 Attacker (Kali Linux GUI):
     Container: ${deployment.attackerContainerName || deployment.attackerContainer}
     
  🌐 Network: ${deployment.networkName}
  
  📝 Instructions:
     1. Connect to attacker container: docker exec -it ${deployment.attackerContainer} /bin/bash
     2. The victim service is accessible at: http://victim:8080
     3. Use Kali's tools to exploit the vulnerability
     4. Find the flag (format: CTF{...})
`;
    }

    if (recommendations && recommendations.length > 0) {
      report += `
═══════════════════════════════════════════════════════════════

💡 RECOMMENDATIONS:
`;
      recommendations.forEach((rec, index) => {
        report += `  ${index + 1}. ${rec}\n`;
      });
    }

    report += `
═══════════════════════════════════════════════════════════════

${status === 'PASS' ? '🎉 Challenge is ready for users!' : '⚠️  Challenge needs fixes before deployment'}
`;

    return report;
  }
}

export const validatorAgent = new ValidatorAgent();
