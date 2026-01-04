import { gitManager } from '../git-manager.js';
import { dockerManager } from '../docker-manager.js';
import GuacamolePostgreSQLManager from '../guacamole-postgresql-manager.js';
import { sessionGuacManager } from '../session-guacamole-manager.js';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

// Get project root directory (3 levels up from this file)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

export async function deployChallenge(userMessage, conversationHistory = [], sessionId = null) {
  try {
    console.log('Deploying challenge...');
    if (sessionId) {
      console.log(`Session ID: ${sessionId}`);
    }

    // Extract challenge name from message (check history for context if not explicit)
    let challengeName = extractChallengeName(userMessage);
    
    // IMPROVEMENT: Token-efficient context extraction - only check last 3 messages
    // If no challenge name found, try to find it in recent conversation history
    if (!challengeName && conversationHistory.length > 0) {
      console.log('No explicit challenge name found, searching conversation history (token-efficient: last 3 messages)...');
      
      // Use helper function for token-efficient extraction
      challengeName = extractChallengeNameFromHistory(conversationHistory, 3);
      
      if (challengeName) {
        console.log(`✅ Found challenge name in conversation history: ${challengeName}`);
      }
    }
    
    if (!challengeName) {
      // List available challenges
      const challenges = await gitManager.listChallenges();
      return {
        success: false,
        message: 'Please specify which challenge to deploy.',
        availableChallenges: challenges,
        example: `Try saying: "Deploy ${challenges[0] || 'challenge-name'}"`
      };
    }

    // Ensure repository is up to date
    await gitManager.ensureRepository();

    // Check if challenge exists
    const challengePath = path.join(CLONE_PATH, 'challenges', challengeName);
    const metadata = await gitManager.getChallengeMetadata(challengeName);

    if (!metadata) {
      const challenges = await gitManager.listChallenges();
      return {
        success: false,
        message: `Challenge "${challengeName}" not found.`,
        availableChallenges: challenges,
        suggestion: 'Make sure the challenge name is correct and try again.'
      };
    }

    console.log(`Found challenge: ${challengeName}`);
    console.log(`Challenge metadata:`, metadata);

    // IMPROVEMENT: Check if challenge is already deployed
    const deploymentStatus = await dockerManager.isChallengeDeployed(challengeName);
    if (deploymentStatus.isDeployed) {
      console.log(`⚠️  Challenge "${challengeName}" is already deployed`);
      console.log(`   Running containers: ${deploymentStatus.containers.map(c => c.name).join(', ')}`);
      
      // Check if user wants to force redeploy (from message)
      const forceRedeploy = userMessage.toLowerCase().includes('force') || 
                            userMessage.toLowerCase().includes('redeploy') ||
                            userMessage.toLowerCase().includes('restart');
      
      if (!forceRedeploy) {
        return {
          success: false,
          message: `Challenge "${challengeName}" is already deployed.`,
          deployedContainers: deploymentStatus.containers,
          suggestion: 'To redeploy, say "deploy [challenge] force" or "redeploy [challenge]"',
          alreadyDeployed: true
        };
      } else {
        console.log(`🔄 Force redeploy requested, cleaning up existing containers...`);
        try {
          await dockerManager.cleanupMultiContainer(challengeName);
          console.log(`✅ Existing containers cleaned up`);
        } catch (cleanupError) {
          console.warn(`⚠️  Cleanup warning: ${cleanupError.message}`);
          // Continue with deployment anyway
        }
      }
    }

    // Collect build progress
    const buildProgress = [];
    const onProgress = (output) => {
      // IMPROVEMENT: Properly serialize output objects to strings
      if (typeof output === 'string') {
        buildProgress.push(output);
      } else if (output && typeof output === 'object') {
        // Extract message or step information from object
        const message = output.message || output.step || JSON.stringify(output);
        buildProgress.push(message);
      } else {
        buildProgress.push(String(output));
      }
    };

    // Build Docker image with streaming output
    const imageName = `ctf-${challengeName}:latest`;
    console.log(`Building image: ${imageName}`);
    
    // IMPROVEMENT: Add error handling with subnet cleanup and automatic error fixing
    let deployResult;
    let guacamoleConnectionCreated = false;
    let guacamoleConnectionName = null;
    
    try {
      // Call deployFromCompose with progress callback
      deployResult = await dockerManager.deployFromCompose(
        challengeName,
        'default',
        onProgress
      );
    } catch (deployError) {
      console.error('❌ Docker deployment failed:', deployError.message);
      
      // ✅ IMPROVED: Use comprehensive auto-fix system with retry logic
      const errorOutput = deployError.dockerOutput?.fullOutput || deployError.message || '';
      
      if (errorOutput) {
        try {
          const { deployWithAutoFix } = await import('./auto-error-fixer.js');
          
          // Use auto-fix system with retry logic
          const fixResult = await deployWithAutoFix(
            challengeName,
            async () => {
              return await dockerManager.deployFromCompose(
                challengeName,
                'default',
                onProgress
              );
            },
            onProgress,
            3 // Max 3 retry attempts
          );
          
          if (fixResult.success) {
            console.log('✅ Deployment succeeded after automatic fixes!');
            deployResult = fixResult.result;
            // Continue with normal flow below - don't throw error
          } else {
            console.log('⚠️  Could not auto-fix deployment errors after all retries');
            deployResult = null;
          }
        } catch (fixError) {
          console.warn('⚠️  Auto-fix system error:', fixError.message);
          deployResult = null;
        }
      } else {
        deployResult = null;
      }
      
      // IMPROVEMENT: Cleanup Guacamole connection if it was created before deployment failed
      if (guacamoleConnectionCreated && guacamoleConnectionName) {
        try {
          const { guacamoleAgent } = await import('../agents/guacamole-agent.js');
          await guacamoleAgent.deleteConnection(guacamoleConnectionName);
          console.log(`🧹 Cleaned up Guacamole connection after deployment failure`);
        } catch (cleanupError) {
          console.warn(`⚠️  Failed to cleanup Guacamole connection: ${cleanupError.message}`);
        }
      }
      
      // If we successfully retried, don't throw error - continue with normal flow
      if (!deployResult) {
        // Note: Subnet cleanup is handled by the cleanup functions in docker-manager
        throw new Error(`Failed to deploy challenge: ${deployError.message}`);
      }
    }

    // Get container IPs for Guacamole connection
    console.log('\n🔍 Getting container information...');
    const attackerContainerName = deployResult.attackerContainerName || `ctf-${challengeName}-attacker`;
    
    let attackerIP = deployResult.attackerIP;
    if (!attackerIP) {
      try {
        attackerIP = await dockerManager.getContainerIP(attackerContainerName);
        console.log(`✅ Kali container IP: ${attackerIP}`);
      } catch (error) {
        console.warn('⚠️  Could not get Kali container IP:', error.message);
      }
    }

    // ✅ IMPROVED: Use challenge network IP (.3) directly
    // Guacd is now connected to challenge network, so it can reach .3 IP
    // Note: attackerIP is always the challenge network IP (.3) - no separate guacamoleAttackerIP needed
    let guacamoleIP = deployResult.attackerIP || attackerIP;
    console.log(`🔗 Guacamole will connect to: ${guacamoleIP} (challenge network - direct connection)`);

    // Create Guacamole access if we have attacker IP and session
    // IMPROVEMENT: Unified user creation system - removed duplicate logic
    let guacamoleAccess = null;
    let connectionCreated = false;
    let connectionResult = null;
    
    if (guacamoleIP && sessionId) {
      console.log('\n🔐 Creating Guacamole access...');
      try {
        // IMPROVEMENT: Validate IP address
        if (!guacamoleIP.match(/^\d+\.\d+\.\d+\.\d+$/)) {
          throw new Error(`Invalid IP address: ${guacamoleIP}`);
        }
        
        // IMPROVEMENT: Clean up old connections before creating new one
        const { guacamoleAgent } = await import('../agents/guacamole-agent.js');
        await guacamoleAgent.cleanupOldConnections(challengeName, sessionId);
        
        // IMPROVEMENT: Validate connection parameters
        guacamoleAgent.validateConnectionParameters({
          hostname: guacamoleIP,
          port: 22,
          username: 'kali',
          password: 'kali'
        });
        
        // Step 1: Get or create session-based Guacamole user (unified system)
        const userAccount = await sessionGuacManager.getOrCreateSessionUser(sessionId);
        
        // Security check: Prevent admin permissions
        await sessionGuacManager.preventAdminCreation(userAccount.entityId);
        
        // Step 2: Create Guacamole connection using guacamole-agent (unified system)
        connectionResult = await guacamoleAgent.createConnection({
          challengeName,
          attackerIP: guacamoleIP,
          username: 'kali',  // Kali user password is set in Dockerfile
          password: 'kali',
          guacUsername: null,  // Don't auto-grant
          sessionId  // IMPROVEMENT: For unique connection names
        });
        connectionCreated = true;
        guacamoleConnectionCreated = true;
        guacamoleConnectionName = connectionResult.connectionName;
        
        // Step 3: Grant access to session user
        await sessionGuacManager.grantConnectionAccess(sessionId, connectionResult.connectionId);
        
        // IMPROVEMENT: Generate session-specific access URL with correct base URL
        // Default to localhost:8081/guacamole/#/ (user's actual Guacamole instance)
        const guacamoleBaseUrl = process.env.GUACAMOLE_URL || process.env.GUACAMOLE_BASE_URL || 'http://localhost:8081/guacamole/#/';
        // Normalize URL: ensure /#/ is present and properly formatted
        let baseUrl = guacamoleBaseUrl.trim();
        // Remove trailing slashes but preserve /#/
        baseUrl = baseUrl.replace(/\/+$/, '');
        // Ensure /#/ is present (Guacamole requires this format)
        if (!baseUrl.includes('/#/')) {
          // If /#/ is not present, add it after /guacamole
          if (baseUrl.endsWith('/guacamole')) {
            baseUrl = baseUrl + '/#/';
          } else if (baseUrl.includes('/guacamole')) {
            baseUrl = baseUrl.replace(/\/guacamole.*$/, '/guacamole/#/');
          } else {
            baseUrl = baseUrl + '/#/';
          }
        } else {
          // If /#/ exists, ensure it's properly formatted
          baseUrl = baseUrl.replace(/#.*$/, '') + '/#/';
        }
        const sessionUrl = `${baseUrl}client/${connectionResult.connectionId}?username=${encodeURIComponent(userAccount.username)}`;
        
        guacamoleAccess = {
          url: sessionUrl,
          baseUrl: baseUrl,
          username: userAccount.username,
          password: userAccount.password,
          connectionId: connectionResult.connectionId,
          connectionName: connectionResult.connectionName,
          message: '🖥️  Click the link to access your Kali Linux desktop (session-specific)!',
          instructions: `Click the link above. Login with username: ${userAccount.username} and password: ${userAccount.password}. This link is unique to your session.`,
          sessionBased: true,
          sessionId: sessionId
        };
        
        console.log(`✅ Guacamole access created (session user: ${userAccount.username})`);
      } catch (error) {
        console.error('⚠️  Failed to create Guacamole access:', error.message);
        // IMPROVEMENT: Cleanup connection if created but grant failed
        if (connectionCreated && connectionResult) {
          try {
            await guacamoleAgent.deleteConnection(connectionResult.connectionName);
            console.log(`🧹 Cleaned up connection after grant failure`);
          } catch (cleanupError) {
            console.warn(`⚠️  Failed to cleanup connection: ${cleanupError.message}`);
          }
        }
        // Don't throw - deployment can continue without Guacamole
      }
    } else if (!sessionId) {
      console.log('⚠️  No session ID provided - skipping Guacamole setup');
    }

    console.log('\n✅ Challenge deployed successfully');
    
    // ✅ NEW: Add validation summary to instructions if validation failed
    let validationMessage = '';
    if (deployResult.validation) {
      const val = deployResult.validation;
      if (val.errors.length > 0) {
        validationMessage = `\n\n⚠️  VICTIM ACCESSIBILITY WARNING:\n`;
        validationMessage += `   ${val.errors.join('\n   ')}\n`;
        if (val.warnings.length > 0) {
          validationMessage += `\n   Additional warnings:\n   ${val.warnings.join('\n   ')}\n`;
        }
        validationMessage += `\n   The victim machine may not be accessible. Please check the container status.`;
      } else if (val.warnings.length > 0) {
        validationMessage = `\n\n⚠️  Note: ${val.warnings.join('; ')}`;
      }
    }

    return {
      success: true,
      message: `Challenge "${challengeName}" deployed successfully!`,
      challenge: {
        name: challengeName,
        title: metadata.title,
        description: metadata.description,
        difficulty: metadata.difficulty,
        category: metadata.category,
        // Flag removed - should not be shown to user
        hints: metadata.hints
      },
      deployment: {
        services: deployResult.services,
        attackerContainer: attackerContainerName,
        attackerIP: attackerIP || 'Could not determine IP',
        victimIP: deployResult.victimIP || null,
        validation: deployResult.validation || null, // Add validation results
      },
      guacamole: guacamoleAccess,
      buildOutput: buildProgress.join('\n'),
      instructions: guacamoleAccess 
        ? `🎯 Challenge is ready!\n\n${guacamoleAccess.message}\n🔗 ${guacamoleAccess.url}\n\n🔐 Guacamole Login Credentials:\n   👤 Username: ${guacamoleAccess.username}\n   🔑 Password: ${guacamoleAccess.password}\n\nUse the Kali Linux desktop to solve the challenge!${validationMessage}`
        : `The challenge is now running. Container: ${attackerContainerName}${validationMessage}`
    };

  } catch (error) {
    console.error('Error deploying challenge:', error);
    return {
      success: false,
      error: 'Failed to deploy challenge',
      details: error.message,
      suggestion: 'Make sure Docker is running and the challenge has a valid Dockerfile.'
    };
  }
}

/**
 * Extract challenge name from a single message
 * Token-efficient: Only looks for explicit deploy commands
 */
function extractChallengeName(message) {
  // Try to extract challenge name from various message formats
  const patterns = [
    /deploy\s+([a-z0-9\-]+)/i,
    /run\s+([a-z0-9\-]+)/i,
    /start\s+([a-z0-9\-]+)/i,
    /launch\s+([a-z0-9\-]+)/i,
    /spin\s+up\s+([a-z0-9\-]+)/i
  ];

  for (const pattern of patterns) {
    const match = message.match(pattern);
    if (match && match[1]) {
      const name = match[1].toLowerCase();
      // Filter out common words that aren't challenge names
      const excludeWords = ['the', 'a', 'an', 'this', 'that', 'please', 'can', 'you', 'it', 'create', 'make', 'generate', 'provide', 'give', 'me', 'for', 'with', 'practice', 'range', 'tool', 'challenge', 'ctf', 'y', 'yes'];
      if (!excludeWords.includes(name)) {
        return name;
      }
    }
  }
  
  // Don't use fallback pattern - only extract if explicitly mentioned with deploy/run/start/launch
  return null;
}

/**
 * Extract challenge name from conversation history (token-efficient)
 * Only checks last few messages to avoid token overload
 */
function extractChallengeNameFromHistory(conversationHistory, maxMessages = 5) {
  if (!conversationHistory || conversationHistory.length === 0) {
    return null;
  }
  
  // Token-efficient: Only check last N messages (most recent first)
  const recentMessages = conversationHistory.slice(-maxMessages).reverse();
  
  for (const msg of recentMessages) {
    if (msg.role === 'assistant' && msg.content) {
      // Look for challenge name in various formats (improved patterns)
      const patterns = [
        /\*\*Name:\*\*\s+([a-z0-9\-_]+)/i,  // **Name:** challenge-name (allows underscores)
        /Challenge\s+"([a-z0-9\-_]+)"\s+created\s+successfully/i,  // Challenge "name" created successfully
        /deploy\s+([a-z0-9\-_]+)/i,  // deploy challenge-name
        /"name"\s*:\s*"([a-z0-9\-_]+)"/i,  // "name": "challenge-name"
        /challengeName["\s:]+([a-z0-9\-_]+)/i,  // challengeName: challenge-name
        /Name.*?([a-z0-9\-_]+)/i  // Name: challenge-name (fallback, less specific)
      ];
      
      for (const pattern of patterns) {
        const match = msg.content.match(pattern);
        if (match && match[1]) {
          const name = match[1].toLowerCase().trim();
          // Validate it looks like a challenge name (not a single letter or common word)
          if (name.length > 3 && !['yes', 'y', 'no', 'the', 'this', 'that'].includes(name)) {
            return name;
          }
        }
      }
    }
  }
  
  return null;
}
