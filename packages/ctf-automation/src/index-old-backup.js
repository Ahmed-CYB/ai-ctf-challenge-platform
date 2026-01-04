import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { classify } from './classifier.js';
import { createUniversalChallenge } from './agents/universal-structure-agent.js';
import { deployChallenge } from './agents/deploy-agent.js';
import { getExistingChallenges } from './agents/retriever-agent.js';
import { getChallengeInfo } from './agents/info-agent.js';
import { answerQuestion } from './agents/questions-agent.js';
import { validatorAgent } from './agents/validator-agent.js';
import { troubleshootChallenge } from './agents/troubleshoot-agent.js';
import { dbManager } from './db-manager.js';
import { guacamoleAgent } from './agents/guacamole-agent.js';
import { sessionGuacManager } from './session-guacamole-manager.js';
import { initializeToolLearning, getCacheStats } from './tool-learning-service.js';
import { checkpointManager } from './checkpoint-manager.js';
import path from 'path';

dotenv.config();

const app = express();
const PORT = process.env.CTF_API_PORT || process.env.PORT || 4003; // New port, original 3003 kept for backup

// ✅ Use singleton Guacamole agent instance (specialized for connections)
// Agent imported from ./agents/guacamole-agent.js
// ✅ Session-based Guacamole user manager (creates users per session)

app.use(cors());
app.use(express.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'CTF Automation Service is running' });
});

// Cache statistics endpoint
app.get('/api/cache/stats', (req, res) => {
  try {
    const stats = getCacheStats();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// IMPROVEMENT: Tool test statistics endpoints
app.get('/api/tools/:toolName/stats', async (req, res) => {
  try {
    const { toolName } = req.params;
    const { getToolTestStats } = await import('./tool-learning-service.js');
    const stats = await getToolTestStats(toolName);
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tools/stats/overall', async (req, res) => {
  try {
    const { getOverallTestStats } = await import('./tool-learning-service.js');
    const stats = await getOverallTestStats();
    res.json({ success: true, stats });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/api/tools/stats/problematic', async (req, res) => {
  try {
    const { getProblematicTools } = await import('./tool-learning-service.js');
    const minTests = parseInt(req.query.minTests) || 3;
    const maxSuccessRate = parseInt(req.query.maxSuccessRate) || 50;
    const tools = await getProblematicTools(minTests, maxSuccessRate);
    res.json({ success: true, tools });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Main chat endpoint
app.post('/api/chat', async (req, res) => {
  try {
    const { message, sessionId } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }

    // ✅ FIX: Always require sessionId - don't auto-generate (security and consistency)
    if (!sessionId) {
      return res.status(400).json({ 
        error: 'Session ID is required. Please refresh the page to create a new session.',
        sessionRequired: true
      });
    }

    console.log(`\n[${new Date().toISOString()}] Received message:`, message);
    console.log(`Session ID: ${sessionId}`);

    // ✅ FIX: Always validate session before processing (no exceptions)
    const sessionData = await dbManager.validateSession(sessionId);
    if (!sessionData) {
      // Track validation failure
      try {
        await dbManager.trackSessionActivity(sessionId, 'validation', {
          action: 'validation_failed',
          reason: 'session_expired_or_invalid'
        });
      } catch (trackError) {
        // Silent fail - activity tracking is non-critical
      }
      return res.status(401).json({ 
        error: 'Session expired or invalid. Please refresh the page to create a new session.',
        sessionExpired: true
      });
    }
    
    // ✅ IMPROVEMENT: Extend session expiration on activity (sliding window)
    try {
      await dbManager.extendSessionExpiration(sessionId);
    } catch (extendError) {
      console.warn(`⚠️  Failed to extend session expiration: ${extendError.message}`);
      // Don't fail the request - continue processing
    }
    
    // Track activity (non-critical, don't fail if it errors)
    try {
      await dbManager.trackSessionActivity(sessionId, 'message', {
        action: 'chat_message',
        messageLength: message.length
      });
    } catch (trackError) {
      // Silent fail - activity tracking is non-critical
      console.debug(`Activity tracking failed: ${trackError.message}`);
    }

    // Get conversation history for this session (use sessionId, not sessionData)
    const conversationHistory = await dbManager.getConversationHistory(sessionId);
    console.log(`Retrieved ${conversationHistory.length} previous messages`);

    // Save user message (use sessionId, not sessionData)
    await dbManager.saveMessage(sessionId, 'user', message);

    // Step 1: Check for deployment confirmation OR challenge creation confirmation BEFORE classification
    // Handle "y", "yes", "deploy", "yes deploy", etc. as deployment confirmations
    // Handle "yes please create", "create that", "make that" as creation confirmations
    const normalizedMessage = message.toLowerCase().trim();
    const isDeploymentConfirmation = normalizedMessage === 'yes' || 
                                     normalizedMessage === 'y' ||
                                     normalizedMessage === 'deploy' ||
                                     normalizedMessage.startsWith('deploy ') ||
                                     normalizedMessage.includes('yes deploy') ||
                                     normalizedMessage.includes('y deploy') ||
                                     (normalizedMessage.length <= 20 && (normalizedMessage.includes('deploy') || normalizedMessage.includes('yes')));
    
    const isCreationConfirmation = normalizedMessage.includes('yes please create') ||
                                   normalizedMessage.includes('create that') ||
                                   normalizedMessage.includes('make that') ||
                                   normalizedMessage.includes('do that') ||
                                   (normalizedMessage.includes('yes') && normalizedMessage.includes('create'));
    
    let challengeNameFromHistory = null;
    let challengeContextFromHistory = null;
    
    // If it's a deployment confirmation, extract challenge name from history (token-efficient: last 3 messages)
    if (isDeploymentConfirmation && conversationHistory.length > 0) {
      console.log('🔍 Detected deployment confirmation, searching for challenge name in recent messages...');
      const recentMessages = conversationHistory.slice(-3).reverse();
      
      for (const msg of recentMessages) {
        if (msg.role === 'assistant' && msg.content) {
          // Check if this message contains challenge details (readyForDeployment)
          if (msg.content.includes('Challenge Created Successfully') || 
              msg.content.includes('Would you like to deploy') ||
              msg.content.includes('readyForDeployment')) {
            // Extract challenge name from the message (multiple pattern attempts, token-efficient)
            const patterns = [
              /\*\*Name:\*\*\s+([a-z0-9\-_]+)/i,  // **Name:** challenge-name (allows underscores)
              /deploy\s+([a-z0-9\-_]+)/i,  // deploy challenge-name
              /"name"\s*:\s*"([a-z0-9\-_]+)"/i,  // "name": "challenge-name"
              /Name.*?([a-z0-9\-_]+)/i  // Name: challenge-name (fallback)
            ];
            
            for (const pattern of patterns) {
              const challengeMatch = msg.content.match(pattern);
              if (challengeMatch && challengeMatch[1]) {
                const challengeName = challengeMatch[1].toLowerCase().trim();
                // Validate it looks like a challenge name (not a single letter or common word)
                if (challengeName.length > 3 && 
                    !['yes', 'y', 'no', 'the', 'this', 'that', 'create', 'deploy'].includes(challengeName)) {
                  challengeNameFromHistory = challengeName;
                  console.log(`✅ Found challenge name from history: ${challengeNameFromHistory}`);
                  break;
                }
              }
            }
            
            if (challengeNameFromHistory) break;
          }
        }
      }
    }
    
    // Step 1.5: If it's a creation confirmation, extract challenge context from history
    if (isCreationConfirmation && conversationHistory.length > 0) {
      console.log('🔍 Detected creation confirmation, searching for challenge context in recent messages...');
      const recentMessages = conversationHistory.slice(-5).reverse();
      
      for (const msg of recentMessages) {
        if (msg.role === 'user' && msg.content) {
          const contentLower = msg.content.toLowerCase();
          // Look for challenge creation requests
          if (contentLower.includes('create') || 
              contentLower.includes('make') || 
              contentLower.includes('generate') ||
              contentLower.includes('ftp') ||
              contentLower.includes('challenge')) {
            challengeContextFromHistory = msg.content;
            console.log(`✅ Found challenge context from history: ${challengeContextFromHistory.substring(0, 100)}...`);
            // Use the original request as the message for classification
            message = challengeContextFromHistory;
            break;
          }
        }
      }
    }
    
    // Step 2: Classify the request (skip if we already found a deployment confirmation with challenge name)
    let classification;
    if (challengeNameFromHistory && isDeploymentConfirmation) {
      // Skip classification, we already know it's a Deploy
      classification = { category: 'Deploy', challengeName: challengeNameFromHistory };
      console.log(`✅ Skipping classification, using deployment confirmation for: ${challengeNameFromHistory}`);
    } else {
      classification = await classify(message, conversationHistory);
    }
    
    // If we found a challenge name from history but classification didn't catch it, override
    if (challengeNameFromHistory && isDeploymentConfirmation && classification.category !== 'Deploy') {
      console.log(`✅ Overriding classification to Deploy for challenge: ${challengeNameFromHistory}`);
      classification.category = 'Deploy';
      classification.challengeName = challengeNameFromHistory;
    }
    
    // PLATFORM RESTRICTION: Validate challenge type before processing
    // Only allow: network, crypto, and simple web challenges
    if (classification.category === 'Create') {
      const SUPPORTED_TYPES = ['network', 'crypto', 'web'];
      const SUPPORTED_KEYWORDS = {
        'network': ['ftp', 'ssh', 'smb', 'samba', 'telnet', 'tcp', 'udp', 'network', 'networking'],
        'crypto': ['crypto', 'cryptography', 'encryption', 'encoding', 'hashing', 'cipher', 'rsa', 'aes'],
        'web': ['web', 'sql injection', 'xss', 'csrf', 'http', 'api', 'web security']
      };
      
      const detectedType = classification.challengeType?.toLowerCase();
      const detectedTypes = classification.challengeTypes?.map(t => t.toLowerCase()) || (detectedType ? [detectedType] : []);
      
      // Check if classification detected a supported type
      const isSupportedByClassification = detectedTypes.length > 0 && detectedTypes.some(type => {
        return SUPPORTED_TYPES.includes(type) ||
               Object.values(SUPPORTED_KEYWORDS).some(keywords => keywords.includes(type));
      });
      
      // Check if classification returned 'misc' or null (needs clarification)
      const needsClarification = detectedType === 'misc' || 
                                 detectedType === null || 
                                 (detectedTypes.length === 0 && !detectedType);
      
      // Also check if message contains supported keywords
      const messageLower = message.toLowerCase();
      const hasSupportedKeyword = Object.entries(SUPPORTED_KEYWORDS).some(([type, keywords]) =>
        keywords.some(keyword => messageLower.includes(keyword))
      );
      
      // Check for unsupported keywords
      const UNSUPPORTED_KEYWORDS = ['forensics', 'forensic', 'reverse engineering', 'reversing', 'pwn', 'pwnable', 'binary', 'exploitation'];
      const hasUnsupportedKeyword = UNSUPPORTED_KEYWORDS.some(keyword => messageLower.includes(keyword));
      
      // If classification correctly identified a supported type, always proceed
      if (isSupportedByClassification) {
        // Classification is correct, proceed to challenge creation
        console.log('✅ Supported challenge type detected by classification, proceeding...');
      } else if (hasSupportedKeyword) {
        // Message contains supported keywords, proceed
        console.log('✅ Supported keywords found in message, proceeding...');
      } else if (needsClarification && !hasUnsupportedKeyword) {
        // Ask for clarification if type is unclear but not unsupported
        const clarificationResponse = {
          success: true,
          needsUserInput: true,
          question: `❓ **I'd like to create the perfect challenge for you!**

To get started, could you tell me:

1. **What type of challenge are you interested in?**
   - **Network Security** (FTP, SSH, SMB, Telnet, network protocols)
   - **Cryptography** (encryption, encoding, hashing, ciphers)
   - **Simple Web CTFs** (SQL injection, XSS, basic web vulnerabilities)

2. **Any specific requirements?** (optional)
   - Difficulty level (Easy, Medium, Hard)
   - Specific vulnerability or technique
   - Real-life scenario preference

**Example:** "Create a medium difficulty network security challenge with FTP misconfiguration and real-life scenario"

Once you provide these details, I'll create a customized challenge for you! 🚀`,
          answer: `I need a bit more information to create your challenge. Please specify the challenge type and any requirements.`,
          message: `I need a bit more information to create your challenge. Please specify the challenge type and any requirements.`,
          sessionId: sessionId
        };
        
        await dbManager.saveMessage(sessionId, 'assistant', clarificationResponse.question);
        return res.json(clarificationResponse);
      } else if (hasUnsupportedKeyword) {
        // Only reject if message has unsupported keywords and no supported type/keywords detected
        const unsupportedResponse = {
          success: true,
          needsUserInput: true,
          question: `❌ **Challenge Type Not Supported**

I'm sorry, but this platform currently supports only the following challenge types:

✅ **Supported Types:**
1. **Network Security** - FTP, SSH, SMB, Telnet, and other network protocols
2. **Cryptography** - Encryption, encoding, hashing, ciphers
3. **Simple Web CTFs** - SQL injection, XSS, basic web vulnerabilities

❌ **Not Supported:**
- Forensics challenges
- Reverse engineering / Binary exploitation
- Pwnable challenges
- Complex multi-stage challenges

**What you can do:**
- Request a network security challenge (e.g., "FTP misconfiguration", "SSH brute force")
- Request a cryptography challenge (e.g., "Caesar cipher", "RSA encryption")
- Request a simple web challenge (e.g., "SQL injection", "XSS vulnerability")

**Example requests:**
- "Create a medium difficulty network security challenge with FTP"
- "Create a crypto challenge with base64 encoding"
- "Create a simple web challenge with SQL injection"

Would you like to create a challenge from one of the supported types? 🚀`,
          answer: `❌ **Challenge Type Not Supported**

This platform supports only Network Security, Cryptography, and Simple Web CTFs. Please choose one of these types.`,
          message: `❌ **Challenge Type Not Supported**

This platform supports only Network Security, Cryptography, and Simple Web CTFs. Please choose one of these types.`,
          sessionId: sessionId
        };
        
          await dbManager.saveMessage(sessionId, 'assistant', unsupportedResponse.question);
        return res.json(unsupportedResponse);
      }
      // If we reach here, the challenge type is supported - continue to routing
    }
    
    console.log('Classification:', classification);
    console.log(`  → Type: ${classification.challengeType || 'not specified'}`);
    console.log(`  → Tools: ${classification.requiredTools?.join(', ') || 'none'}`);

    // FALLBACK: If message contains "create" but was misclassified as Question, re-route to Create
    const messageLower = message.toLowerCase();
    const hasCreateKeywords = messageLower.includes('create') && 
                              (messageLower.includes('environment') || 
                               messageLower.includes('challenge') || 
                               messageLower.includes('practice') || 
                               messageLower.includes('for me'));
    
    if (classification.category === 'Question' && hasCreateKeywords) {
      console.log('⚠️  Message contains "create" keywords but was classified as Question. Re-routing to Create...');
      classification.category = 'Create';
      // Infer challenge type and tools from message
      if (messageLower.includes('nmap') || messageLower.includes('network') || messageLower.includes('port') || messageLower.includes('scan')) {
        classification.challengeType = 'network';
        classification.challengeTypes = ['network'];
        classification.requiredTools = ['nmap', 'wireshark', 'tcpdump', 'netcat', 'ssh', 'nc', 'net-tools', 'iputils-ping', 'python3', 'curl', 'wget'];
      } else if (messageLower.includes('crypto') || messageLower.includes('encrypt') || messageLower.includes('hash') || messageLower.includes('cipher')) {
        classification.challengeType = 'crypto';
        classification.challengeTypes = ['crypto'];
        classification.requiredTools = ['hashcat', 'john', 'openssl', 'python3', 'curl', 'wget'];
      } else if (messageLower.includes('web') || messageLower.includes('sql') || messageLower.includes('xss') || messageLower.includes('injection')) {
        classification.challengeType = 'web';
        classification.challengeTypes = ['web'];
        classification.requiredTools = ['burpsuite', 'sqlmap', 'nikto', 'gobuster', 'curl', 'wget', 'python3'];
      } else {
        // Default to network if unclear
        classification.challengeType = 'network';
        classification.challengeTypes = ['network'];
        classification.requiredTools = ['nmap', 'wireshark', 'tcpdump', 'netcat', 'ssh', 'nc', 'net-tools', 'iputils-ping', 'python3', 'curl', 'wget'];
      }
    }

    let response;

    // Step 2: Route to appropriate agent based on classification with conversation history
    switch (classification.category) {
      case 'Create':
        console.log('Routing to Universal Structure Agent...');
        
        // Collect progress steps
        const progressSteps = [];
        const progressCallback = (step) => {
          console.log(`[Progress] ${step.message}`);
          progressSteps.push(step);
        };
        
        // Use universal agent for all challenge creation
        console.log('  → Using Universal Structure Agent (Multi-Category Support)...');
        response = await createUniversalChallenge(message, conversationHistory, progressCallback, classification);
        
        // Check if user input is needed
        if (response.needsUserInput) {
          // Use the question directly (it's already formatted)
          const questionText = response.question || 'I need more information to proceed.';
          
          // Save AI message asking for clarification
          await dbManager.saveMessage(sessionId, 'assistant', questionText);
          
          return res.json({
            success: true,
            needsUserInput: true,
            question: questionText,
            answer: questionText, // For frontend compatibility
            message: questionText, // Also include as message
            sessionId: sessionId,
            progressSteps: progressSteps
          });
        }
        
        // Check if challenge is ready for deployment but needs user confirmation
        if (response.success && response.readyForDeployment && response.challenge && response.challenge.name) {
          // Format a user-friendly response with challenge details
          const machinesList = response.machines?.map(m => {
            const services = m.services?.length > 0 ? ` (${m.services.join(', ')})` : '';
            return `  • **${m.name}** (${m.type})${services}\n    ${m.role || 'No description'}`;
          }).join('\n\n') || '  • No machines specified';
          
          const challengeDetails = `✅ **Challenge Created Successfully!**

📋 **Challenge Details:**

**Name:** ${response.challenge.name}
**Type:** ${response.type || response.challenge.type || 'General'}
**Difficulty:** ${response.difficulty || response.challenge.difficulty || 'Medium'}
**Description:** ${response.description || response.challenge.description || 'A CTF challenge'}

**Machines:**
${machinesList}

**Status:** ✅ Challenge files created and committed to GitHub successfully!

---

**Would you like to deploy this challenge now?** 

Just reply with:
- "yes" or "y" 
- "deploy" 
- "deploy ${response.challenge.name}"

Or say "no" if you want to modify it first.`;

          // Save AI message with challenge details
          await dbManager.saveMessage(sessionId, 'assistant', challengeDetails);
          
          return res.json({
            success: true,
            readyForDeployment: true,
            message: challengeDetails,
            answer: challengeDetails, // For frontend compatibility
            challenge: response.challenge,
            sessionId: sessionId,
            progressSteps: progressSteps
          });
        }
        
        // IMPROVEMENT: Pre-deployment validation now happens in universal-structure-agent BEFORE GitHub push
        // This validation step is now redundant but kept for backward compatibility
        if (response.success && response.challenge && response.challenge.name && !response.readyForDeployment) {
          try {
            // Note: Pre-deployment validation already ran in universal-structure-agent before GitHub push
            console.log('\n✅ Pre-deployment validation already completed (ran before GitHub push)');
            
            console.log('\n🚀 Deploying with docker compose...');
            progressCallback({ step: 'deploy', message: '🚀 Deploying containers...' });
            
            // Deploy with docker compose
            const { DockerManager } = await import('./docker-manager.js');
            const dockerManager = new DockerManager();
            const deployment = await dockerManager.deployFromCompose(response.challenge.name, 'default', progressCallback);
            
            // Analyze Docker output with Claude
            console.log('\n🔍 Analyzing Docker deployment output...');
            progressCallback({ step: 'docker-analysis', message: '🔍 Verifying deployment success...' });
            
            const { analyzeDockerOutput } = await import('./agents/pre-deploy-validator-agent.js');
            let dockerAnalysis = await analyzeDockerOutput(
              response.challenge.name,
              deployment.dockerOutput?.fullOutput || 'No output captured',
              progressCallback
            );
            
            // Run post-deployment validation
            console.log('\n🧪 Running post-deployment validation...');
            progressCallback({ step: 'validation', message: '🧪 Testing challenge functionality...' });
            
            const { validateChallenge } = await import('./agents/post-deploy-validator.js');
            const validationResults = await validateChallenge(
              response.challenge.name,
              deployment,
              progressCallback
            );
            
            if (!validationResults.success) {
              console.warn('⚠️ Challenge validation failed, but deployment succeeded');
              console.warn('⚠️ Review validation report above before releasing to users');
            }
            
            // If fixes were applied, retry deployment once
            if (dockerAnalysis.fixesApplied && dockerAnalysis.shouldRetry) {
              console.log('\n🔄 Retrying deployment after fixes...');
              progressCallback({ step: 'retry-deploy', message: '🔄 Retrying deployment with fixes...' });
              
              try {
                const retryDeployment = await dockerManager.deployFromCompose(response.challenge.name, 'default', progressCallback);
                
                // Analyze retry output
                console.log('\n🔍 Analyzing retry deployment...');
                progressCallback({ step: 'retry-analysis', message: '🔍 Verifying retry success...' });
                
                dockerAnalysis = await analyzeDockerOutput(
                  response.challenge.name,
                  retryDeployment.dockerOutput?.fullOutput || 'No output captured',
                  progressCallback
                );
                
                // Use retry deployment if successful
                if (dockerAnalysis.deploymentSuccessful) {
                  deployment = retryDeployment;
                  console.log('✅ Retry deployment successful!');
                }
              } catch (retryError) {
                console.warn('⚠️ Retry deployment failed:', retryError.message);
                // Continue with original analysis
              }
            }
            
            // Check if Claude detected any issues
            if (dockerAnalysis.success && !dockerAnalysis.deploymentSuccessful) {
              console.warn('⚠️ Claude detected deployment issues');
              const issues = dockerAnalysis.analysis?.issues || [];
              const recommendations = dockerAnalysis.analysis?.recommendations || [];
              
              let issuesMessage = `Challenge "${response.challenge.name}" created but deployment has issues:\n\n` +
                `⚠️ Deployment Status: ${dockerAnalysis.analysis?.deploymentStatus || 'unknown'}\n\n` +
                `Issues detected:\n${issues.map(i => `  - [${i.severity}] ${i.service}: ${i.message}`).join('\n')}\n\n`;
              
              if (dockerAnalysis.fixesApplied) {
                issuesMessage += `\n🔧 Fixes attempted:\n${dockerAnalysis.fixes.map(f => `  - ${f.explanation}: ${f.success ? '✅' : '❌'}`).join('\n')}\n\n`;
              }
              
              if (recommendations.length > 0) {
                issuesMessage += `Recommendations:\n${recommendations.map(r => `  - ${r}`).join('\n')}`;
              }
              
              response.message = issuesMessage;
              response.success = false;
              response.dockerAnalysis = dockerAnalysis.analysis;
            } else {
              // Deployment successful - now create Guacamole user and connection
              let guacamoleInfo = null;
              try {
                console.log('\n🔗 Setting up Guacamole access...');
                if (progressCallback) progressCallback({ step: 'guacamole-setup', message: '🔗 Creating user account and SSH connection...' });
                
                // Step 1: Get or create session-based Guacamole user (reuses existing if present)
                const userAccount = await sessionGuacManager.getOrCreateSessionUser(sessionId);
                
                // Security check: Ensure no admin permissions
                await sessionGuacManager.preventAdminCreation(userAccount.entityId);
                
                // ✅ Use challenge network IP (.3) for Guacamole connection
                // Guacd is connected to challenge network, so it can reach attacker at .3
                const attackerIPForGuacamole = deployment.attackerIP;
                
                // IMPROVEMENT: Validate IP address before creating connection
                if (!attackerIPForGuacamole || !attackerIPForGuacamole.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                  throw new Error(`Invalid attacker IP address: ${attackerIPForGuacamole}. Cannot create Guacamole connection.`);
                }
                
                // Step 2: Create SSH connection in Guacamole
                // IMPROVEMENT: Pass sessionId for unique connection names
                const connectionResult = await guacamoleAgent.createConnection({
                  challengeName: response.challenge.name,
                  attackerIP: attackerIPForGuacamole,
                  username: 'kali',
                  password: 'kali',
                  guacUsername: null,  // Don't auto-grant in guacamole-agent
                  sessionId: sessionId   // IMPROVEMENT: For unique connection names
                });
                
                // Step 3: Grant READ access to session user for this connection
                await sessionGuacManager.grantConnectionAccess(sessionId, connectionResult.connectionId);
                
                // IMPROVEMENT: Generate session-specific Guacamole URL with correct base URL
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
                
                // Generate session-specific URL that includes username for easier access
                // The connection is already restricted to this session user via permissions
                const sessionUrl = `${baseUrl}client/${connectionResult.connectionId}?username=${encodeURIComponent(userAccount.username)}`;
                
                guacamoleInfo = {
                  connectionId: connectionResult.connectionId,
                  connectionName: connectionResult.connectionName,
                  hostname: connectionResult.hostname,
                  url: sessionUrl,
                  baseUrl: baseUrl,
                  username: userAccount.username,
                  password: userAccount.password,
                  sshUsername: 'kali',
                  sshPassword: 'kali',
                  instructions: `Click the link to access your challenge. Login with username: ${userAccount.username} and password: ${userAccount.password}`,
                  isNewUser: userAccount.isNew,
                  sessionBased: true,
                  sessionId: sessionId  // Include session ID for tracking
                };
                
                console.log('\n🎯 Guacamole Access Information:');
                console.log(`   URL: ${guacamoleInfo.url}`);
                console.log(`   Guacamole User: ${guacamoleInfo.username} (session-based)`);
                console.log(`   Guacamole Password: ${guacamoleInfo.password}`);
                console.log(`   Connection: ${connectionResult.connectionName}`);
                console.log(`   SSH Target: kali@${attackerIPForGuacamole}:22`);
                console.log(`   User Type: Regular user (no admin rights)`);
                
                if (progressCallback) progressCallback({ step: 'guacamole-ready', message: '✅ Session user account and SSH access configured' });
              } catch (guacError) {
                console.error('⚠️  Guacamole connection setup failed:', guacError.message);
                if (progressCallback) progressCallback({ step: 'guacamole-failed', message: '⚠️ SSH access setup failed (non-fatal)' });
              }
              
              // IMPROVEMENT: Pre-deployment validation result may not be available in this scope
              // Only include pre-deployment fixes if we have access to the validation result
              const preDeployFixes = ''; // Pre-deployment fixes are logged during challenge creation
              
              const postDeployFixes = dockerAnalysis.fixesApplied
                ? `\n🔧 Post-deployment fixes:\n${dockerAnalysis.fixes.filter(f => f.success).map(f => `  - ${f.explanation}`).join('\n')}\n`
                : '';
              
              const dockerSummary = dockerAnalysis.success 
                ? `\n✅ Claude verified deployment: ${dockerAnalysis.summary}\n`
                : '';
              
              const guacamoleAccess = guacamoleInfo
                ? `\n🌐 WEB ACCESS (Guacamole - Session-Specific):\n   🔗 Click to open: ${guacamoleInfo.url}\n   👤 Username: ${guacamoleInfo.username}\n   🔑 Password: ${guacamoleInfo.password}\n   🔒 This link is unique to your session and can only be accessed by you\n`
                : '';
              
              response.message = `Challenge "${response.challenge.name}" created and deployed successfully!\n\n` +
                `✅ Everything is working correctly\n` +
                `${preDeployFixes}${postDeployFixes}${dockerSummary}\n` +
                `🎯 VICTIM CHALLENGE:\n` +
                `   IP:PORT → ${deployment.victimIP}:8080\n` +
                `   URL → http://${deployment.victimIP}:8080\n` +
                `   Container → ${deployment.victimContainerName}\n\n` +
                `🥷 ATTACKER (Kali Linux):\n` +
                `   IP → ${deployment.attackerIP}\n` +
                `   Container → ${deployment.attackerContainerName}\n` +
                guacamoleAccess +
                `\n📡 HOW TO ACCESS:\n` +
                `   Option 1 (GUI): Click the Guacamole link above\n` +
                `   Option 2 (CLI): docker exec -it ${deployment.attackerContainerName} /bin/bash\n\n` +
                `🎮 Attack Commands:\n` +
                `   curl http://${deployment.victimIP}:8080\n` +
                `   nmap -sV ${deployment.victimIP}\n` +
                `   sqlmap -u "http://${deployment.victimIP}:8080"\n\n` +
                `💡 All pentesting tools pre-installed in attacker container`;
              response.deployment = deployment;
              response.guacamole = guacamoleInfo;
              response.validation = validationResults; // Use validationResults (plural) from line 170
              response.dockerAnalysis = dockerAnalysis.analysis;
              response.success = true;
            }
            
            response.progressSteps = progressSteps;
            
          } catch (deployError) {
            console.error('Deployment error:', deployError);
            
            // ✅ IMPROVED: Use comprehensive auto-fix system with retry logic
            const errorOutput = deployError.dockerOutput?.fullOutput || deployError.message || '';
            
            if (errorOutput) {
              try {
                const { deployWithAutoFix } = await import('./agents/auto-error-fixer.js');
                const { DockerManager } = await import('./docker-manager.js');
                const dockerManager = new DockerManager();
                
                // Use auto-fix system with retry logic
                const fixResult = await deployWithAutoFix(
                  response.challenge.name,
                  async () => {
                    return await dockerManager.deployFromCompose(
                      response.challenge.name,
                      'default',
                      progressCallback
                    );
                  },
                  progressCallback,
                  3 // Max 3 retry attempts
                );
                
                if (fixResult.success) {
                  console.log('✅ Deployment succeeded after automatic fixes!');
                  deployment = fixResult.result;
                  
                  // Continue with Guacamole setup
                  try {
                    const { DockerManager } = await import('./docker-manager.js');
                    const dockerManager = new DockerManager();
                    const retryDeployment = await dockerManager.deployFromCompose(response.challenge.name, 'default', progressCallback);
                    
                    // Success after fixes!
                    console.log('✅ Deployment succeeded after fixes!');
                    
                    const fixSummary = `\n🔧 Fixes applied after initial failure:\n${errorAnalysis.fixes.filter(f => f.success).map(f => `  - ${f.explanation}`).join('\n')}\n`;
                    
                    // Create Guacamole user and connection for retry success
                    // IMPROVEMENT: Use unified sessionGuacManager instead of guacamoleAgent.createUser
                    let guacamoleInfo = null;
                    try {
                      // IMPROVEMENT: Use unified user creation system
                      const userAccount = await sessionGuacManager.getOrCreateSessionUser(sessionId);
                      
                      // Security check
                      await sessionGuacManager.preventAdminCreation(userAccount.entityId);
                      
                      // ✅ Use challenge network IP (.3) for Guacamole connection
                      const attackerIPForGuacamole = retryDeployment.attackerIP;
                      if (!attackerIPForGuacamole || !attackerIPForGuacamole.match(/^\d+\.\d+\.\d+\.\d+$/)) {
                        throw new Error(`Invalid attacker IP address: ${attackerIPForGuacamole}`);
                      }
                      
                      const connectionResult = await guacamoleAgent.createConnection({
                        challengeName: response.challenge.name,
                        attackerIP: attackerIPForGuacamole,
                        username: 'kali',
                        password: 'kali',
                        guacUsername: null,
                        sessionId: sessionId  // IMPROVEMENT: For unique connection names
                      });
                      
                      // Grant access
                      await sessionGuacManager.grantConnectionAccess(sessionId, connectionResult.connectionId);
                      
                      // IMPROVEMENT: Generate session-specific URL with correct base URL
                      // Default to localhost:8081/guacamole/#/ (user's actual Guacamole instance)
                      const guacamoleBaseUrl = process.env.GUACAMOLE_URL || process.env.GUACAMOLE_BASE_URL || 'http://localhost:8081/guacamole/#/';
                      // Normalize URL: remove trailing slashes, ensure /#/ is present
                      let baseUrl = guacamoleBaseUrl.replace(/\/+$/, ''); // Remove trailing slashes
                      if (!baseUrl.includes('/#/')) {
                        // If /#/ is not present, add it
                        baseUrl = baseUrl.replace(/\/guacamole$/, '/guacamole/#/');
                      }
                      const sessionUrl = `${baseUrl}client/${connectionResult.connectionId}?username=${encodeURIComponent(userAccount.username)}`;
                      
                      guacamoleInfo = {
                        connectionId: connectionResult.connectionId,
                        url: sessionUrl,
                        baseUrl: baseUrl,
                        directUrl: sessionUrl,  // Same as url for consistency
                        username: userAccount.username,
                        password: userAccount.password,
                        sessionId: sessionId,
                        sessionBased: true
                      };
                      
                      console.log('✅ Guacamole user and connection created');
                      console.log(`   User: ${userAccount.username} / ${userAccount.password}`);
                      console.log(`   Session-specific URL: ${sessionUrl}`);
                    } catch (guacError) {
                      console.error('⚠️  Guacamole setup failed (non-fatal):', guacError.message);
                    }
                    
                    const guacamoleAccess = guacamoleInfo
                      ? `\n🌐 WEB ACCESS (Guacamole - Session-Specific):\n   🔗 Click to open: ${guacamoleInfo.url}\n   👤 Username: ${guacamoleInfo.username}\n   🔑 Password: ${guacamoleInfo.password}\n   🔒 This link is unique to your session and can only be accessed by you\n`
                      : '';
                    
                    response.message = `Challenge "${response.challenge.name}" created and deployed successfully!\n\n` +
                      `⚠️ Initial deployment failed but was automatically fixed\n` +
                      `${fixSummary}\n` +
                      `✅ Everything is working correctly now\n\n` +
                      `🎯 VICTIM CHALLENGE:\n` +
                      `   IP:PORT → ${retryDeployment.victimIP}:8080\n` +
                      `   URL → http://${retryDeployment.victimIP}:8080\n` +
                      `   Container → ${retryDeployment.victimContainerName}\n\n` +
                      `🥷 ATTACKER (Kali Linux):\n` +
                      `   IP → ${retryDeployment.attackerIP}\n` +
                      `   Container → ${retryDeployment.attackerContainerName}\n` +
                      guacamoleAccess +
                      `\n📡 HOW TO ACCESS:\n` +
                      `   Option 1 (GUI): Click the Guacamole link above\n` +
                      `   Option 2 (CLI): docker exec -it ${retryDeployment.attackerContainerName} /bin/bash\n\n` +
                      `🎮 Attack Commands:\n` +
                      `   curl http://${retryDeployment.victimIP}:8080\n` +
                      `   nmap -sV ${retryDeployment.victimIP}\n` +
                      `   sqlmap -u "http://${retryDeployment.victimIP}:8080"\n\n` +
                      `💡 All pentesting tools pre-installed`;
                    response.deployment = retryDeployment;
                    response.guacamole = guacamoleInfo;
                    response.dockerAnalysis = errorAnalysis.analysis;
                    response.success = true;
                    response.progressSteps = progressSteps;
                    return response;
                  } catch (retryError) {
                    console.error('Retry also failed:', retryError.message);
                    // Continue with error message below
                  }
                }
              } catch (analysisError) {
                console.warn('Could not analyze error output:', analysisError.message);
              }
            }
            
            let errorMessage = `Challenge created but deployment failed: ${deployError.message}`;
            
            if (errorAnalysis?.success && errorAnalysis.analysis) {
              const issues = errorAnalysis.analysis.issues || [];
              const recommendations = errorAnalysis.analysis.recommendations || [];
              
              errorMessage += `\n\n🤖 Claude's Analysis:\n${errorAnalysis.summary}\n\n`;
              
              if (errorAnalysis.fixesApplied) {
                errorMessage += `\n🔧 Fixes attempted:\n${errorAnalysis.fixes.map(f => `  - ${f.explanation}: ${f.success ? '✅' : '❌'}`).join('\n')}\n\n`;
              }
              
              if (issues.length > 0) {
                errorMessage += `Issues:\n${issues.map(i => `  - [${i.severity}] ${i.service}: ${i.message}`).join('\n')}\n\n`;
              }
              
              if (recommendations.length > 0) {
                errorMessage += `Recommendations:\n${recommendations.map(r => `  - ${r}`).join('\n')}`;
              }
              
              response.dockerAnalysis = errorAnalysis.analysis;
            }
            
            response.message = errorMessage;
            response.success = false;
            response.progressSteps = progressSteps;
          }
          
          return response;
        }
        
        /* ORIGINAL VALIDATION CODE - DISABLED FOR TESTING
        if (response.success && response.challenge && response.challenge.name) {
          try {
            console.log('\n🔍 Automatically validating challenge...');
            progressCallback({ step: 'validation-start', message: '🔍 Validating deployed challenge...' });
            
            const validationResult = await validatorAgent.validateChallenge(response.challenge.name, conversationHistory, progressCallback);
            
            if (validationResult.status === 'PASS') {
              // Success on first try
              const validationReport = validatorAgent.formatValidationReport(validationResult);
              response.message = `Challenge "${response.challenge.name}" created and validated successfully!\n\n` +
                `🎯 Victim Container: ${validationResult.deployment.victimContainer}\n` +
                `🥷 Attacker Container: ${validationResult.deployment.attackerContainer}\n\n` +
                `Connect to attacker: docker exec -it ${validationResult.deployment.attackerContainer} /bin/bash\n\n${validationReport}`;
              response.deployment = validationResult.deployment;
              response.validation = validationResult;
              response.success = true;
            } else {
              // Validation failed - silently troubleshoot (don't show user yet)
              console.log('\n🔧 Validation failed, attempting silent auto-fix...');
              progressCallback({ step: 'troubleshoot-silent', message: '🔧 Optimizing deployment...' });
              
              // Get project root directory
              const projectRoot = path.resolve(process.cwd());
              const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');
              const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;
              const challengePath = path.join(CLONE_PATH, 'challenges', response.challenge.name);
              
              let fixedSuccessfully = false;
              let finalValidationResult = validationResult;
              
              // Try up to 5 troubleshooting attempts (increased from 2)
              for (let attempt = 1; attempt <= 5; attempt++) {
                try {
                  console.log(`🔧 Troubleshooting attempt ${attempt}/5...`);
                  
                  // CRITICAL: Stop and remove existing containers before troubleshooting
                  // This prevents container name conflicts when redeploying after fixes
                  console.log(`🧹 Cleaning up existing containers for ${response.challenge.name}...`);
                  try {
                    const { DockerManager } = await import('./docker-manager.js');
                    const dockerManager = new DockerManager();
                    await dockerManager.cleanupMultiContainer(response.challenge.name);
                    console.log(`✅ Containers cleaned up successfully`);
                  } catch (cleanupError) {
                    console.warn(`⚠️  Container cleanup warning: ${cleanupError.message}`);
                  }
                  
                  const troubleshootResult = await troubleshootChallenge(challengePath, {
                    maxAttempts: 1,
                    autoFix: true
                  });
                  
                  if (troubleshootResult.success) {
                    console.log(`✅ Troubleshooting attempt ${attempt} applied fixes, re-validating...`);
                    progressCallback({ step: 'revalidation', message: `🔄 Re-validating (attempt ${attempt})...` });
                    
                    // Re-run validation
                    const revalidationResult = await validatorAgent.validateChallenge(response.challenge.name, conversationHistory, progressCallback);
                    finalValidationResult = revalidationResult;
                    
                    if (revalidationResult.status === 'PASS') {
                      // Success after troubleshooting!
                      fixedSuccessfully = true;
                      console.log(`✅ Challenge fixed and validated on attempt ${attempt}!`);
                      break;
                    } else {
                      console.log(`⚠️ Attempt ${attempt} didn't fully fix the issue, trying again...`);
                    }
                  } else {
                    console.log(`⚠️ Troubleshooting attempt ${attempt} unsuccessful: ${troubleshootResult.message}`);
                  }
                } catch (troubleshootError) {
                  console.error(`Troubleshooting attempt ${attempt} error:`, troubleshootError.message);
                }
              }
              
              // After all attempts, return result to user
              if (fixedSuccessfully && finalValidationResult.status === 'PASS') {
                const validationReport = validatorAgent.formatValidationReport(finalValidationResult);
                response.message = `Challenge "${response.challenge.name}" created and validated successfully!\n\n` +
                  `🎯 Victim Container: ${finalValidationResult.deployment.victimContainer}\n` +
                  `🥷 Attacker Container: ${finalValidationResult.deployment.attackerContainer}\n\n` +
                  `Connect to attacker: docker exec -it ${finalValidationResult.deployment.attackerContainer} /bin/bash\n\n${validationReport}\n\n` +
                  `✨ Note: Challenge was automatically optimized during deployment.`;
                response.deployment = finalValidationResult.deployment;
                response.validation = finalValidationResult;
                response.success = true;
                response.troubleshootApplied = true;
              } else {
                // Failed after all attempts - return error
                const validationReport = validatorAgent.formatValidationReport(finalValidationResult);
                response.message = `Challenge "${response.challenge.name}" was created but could not be fully validated after multiple optimization attempts.\n\n${validationReport}\n\n` +
                  `🔧 The challenge files have been created in GitHub. You may need to manually review the configuration.\n\n` +
                  `Common issues:\n` +
                  `- Service startup may require more time\n` +
                  `- Flag file permissions\n` +
                  `- Network connectivity between containers`;
                response.success = false;
                response.troubleshootAttempted = true;
                response.validation = finalValidationResult;
              }
            }
          } catch (validationError) {
            console.error('Validation error:', validationError);
            response.message = `Challenge "${response.challenge.name}" was created but validation encountered an error: ${validationError.message}\n\n` +
              `The challenge files have been committed to GitHub. You can try deploying it manually or ask me to troubleshoot.`;
            response.success = false;
            response.validationError = validationError.message;
          }
        }
        */
        
        // Add progress steps to response
        response.progressSteps = progressSteps;
        break;

      case 'Deploy':
        console.log('Routing to Deploy Agent...');
        
        // IMPROVEMENT: Validate that this is actually a deploy request
        // If message contains "provide", "give me", "practice range", etc., it's likely a Create request
        const messageLower = message.toLowerCase();
        const createKeywords = ['provide', 'give me', 'practice range', 'practice environment', 'setup', 'set up', 'create', 'make', 'generate'];
        const hasCreateKeywords = createKeywords.some(keyword => messageLower.includes(keyword));
        
        // Check if a specific challenge name is mentioned (required for deploy)
        // IMPROVEMENT: Also check classification.challengeName (from context extraction)
        const hasChallengeName = /(?:deploy|run|start|launch|spin up)\s+([a-z0-9\-]+)/i.test(message) || 
                                 !!classification.challengeName;
        
        if (hasCreateKeywords && !hasChallengeName) {
          // This looks like a Create request, not Deploy - re-route to Create
          console.log('⚠️  Message contains create keywords but was classified as Deploy. Re-routing to Create...');
          classification.category = 'Create';
          // Don't break - fall through to Create case below
        } else {
          const deployProgressSteps = [];
          const deployProgressCallback = (step) => {
            console.log(`[Progress] ${step.message}`);
            deployProgressSteps.push(step);
          };
          
          // IMPROVEMENT: Pass challenge name from classification if available (from context extraction)
          const deployMessage = classification.challengeName 
            ? `deploy ${classification.challengeName}` 
            : message;
          
          console.log(`🚀 Deploying challenge: ${classification.challengeName || 'extracting from message...'}`);
          response = await deployChallenge(deployMessage, conversationHistory, sessionId);
        
          // After deployment, run validation to ensure it's working
          if (response.success && response.challengeName) {
            console.log('\n🔍 Validating deployed challenge...');
            const validationResult = await validatorAgent.validateChallenge(response.challengeName, conversationHistory, deployProgressCallback);
            
            const validationReport = validatorAgent.formatValidationReport(validationResult);
            
            response.validation = validationResult;
            response.validationReport = validationReport;
            
            if (validationResult.status === 'PASS') {
              response.message = `Challenge "${response.challengeName}" deployed and validated successfully!\n\n` +
                `🎯 Challenge URL: ${validationResult.deployment.victimUrl}\n` +
                `🥷 Kali Linux GUI: ${validationResult.deployment.attackerUrl}\n` +
                `(Username: kasm_user, Password: password)\n\n${validationReport}`;
              response.deployment = validationResult.deployment;
              response.attackerUrl = validationResult.deployment.attackerUrl;
              response.victimUrl = validationResult.deployment.victimUrl;
            } else {
              response.message = `Challenge "${response.challengeName}" was deployed but failed validation.\n\n${validationReport}`;
              response.success = false;
            }
          }
          
          // Ensure deployment info is available for exact command generation
          if (response.success && response.deployment) {
            // Make sure all deployment fields are populated
            if (!response.deployment.attackerIP && response.deployment.attackerContainer) {
              // Try to get IP from container name
              try {
                const { exec } = await import('child_process');
                const { promisify } = await import('util');
                const execAsync = promisify(exec);
                const result = await execAsync(`docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ${response.deployment.attackerContainer}`);
                response.deployment.attackerIP = result.stdout.trim();
              } catch (e) {
                console.warn('Could not get attacker IP:', e.message);
              }
            }
          }
          
          response.progressSteps = deployProgressSteps;
          break; // Only break if we actually deployed
        }
        
        // If we re-routed to Create, fall through to Create case (no break above)
        // Note: If classification.category is 'Create', we'll continue to the Create case below
        // If it's still 'Deploy', we break here
        if (classification.category !== 'Create') {
          break;
        }
        // Fall through to Create case if re-routed

      case 'Create':
        console.log('Routing to Info Agent...');
        response = await getChallengeInfo(message, conversationHistory);
        break;

      case 'Question':
        console.log('Routing to Questions Agent...');
        // Pass deployment info from recent deployment if available
        const recentDeployment = conversationHistory
          .slice(-10)
          .reverse()
          .find(msg => msg.role === 'assistant' && msg.metadata?.deployment);
        
        if (recentDeployment && recentDeployment.metadata.deployment) {
          // Enhance conversation history with deployment context
          const enhancedHistory = [...conversationHistory];
          if (enhancedHistory.length > 0) {
            enhancedHistory[enhancedHistory.length - 1] = {
              ...enhancedHistory[enhancedHistory.length - 1],
              metadata: {
                ...enhancedHistory[enhancedHistory.length - 1].metadata,
                deployment: recentDeployment.metadata.deployment
              }
            };
          }
          response = await answerQuestion(message, enhancedHistory);
        } else {
          response = await answerQuestion(message, conversationHistory);
        }
        break;

      default:
        response = {
          success: false,
          message: `Unknown category: ${classification.category}. Please try rephrasing your request.`
        };
    }

    // Save assistant response with deployment info if available
    const responseText = response.answer || response.message || JSON.stringify(response);
    const messageMetadata = {
      category: classification.category,
      success: response.success
    };
    
    // Include deployment info if available (for exact command generation)
    if (response.deployment) {
      messageMetadata.deployment = {
        challengeName: response.challengeName || response.challenge?.name,
        attackerIP: response.deployment.attackerIP,
        victimIP: response.deployment.victimIP || response.deployment.victimIP,
        attackerContainerName: response.deployment.attackerContainerName || response.deployment.attackerContainer,
        victimContainerName: response.deployment.victimContainerName || response.deployment.victimContainer,
        subnet: response.deployment.subnet,
        services: response.deployment.services
      };
    }
    
    await dbManager.saveMessage(sessionId, 'assistant', responseText, messageMetadata);

    console.log('Response:', response);
    res.json(response);

  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Guacamole User Management Endpoints
app.post('/api/guacamole/create-user', async (req, res) => {
  try {
    const { username, password, email, fullName } = req.body;

    if (!username || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username and password are required' 
      });
    }

    // Use GuacamolePostgreSQLManager for creating users
    const { GuacamolePostgreSQLManager } = await import('./guacamole-postgresql-manager.js');
    const guacManager = new GuacamolePostgreSQLManager();

    // Generate random alphabetic username
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    let guacUsername = 'ctf';
    for (let i = 0; i < 10; i++) {
      guacUsername += letters.charAt(Math.floor(Math.random() * letters.length));
    }

    // Hash password using Guacamole's format
    const salt = crypto.randomBytes(32);
    const saltHex = salt.toString('hex');
    const hash = crypto.createHash('sha256')
      .update(password)
      .update(saltHex)
      .digest('hex');

    // Create entity
    const createEntitySql = `INSERT INTO guacamole_entity (name, type) VALUES ('${guacUsername}', 'USER')`;
    await guacManager.execMySQLQuery(createEntitySql);

    // Get entity ID
    const getEntityIdSql = `SELECT entity_id FROM guacamole_entity WHERE name = '${guacUsername}' AND type = 'USER'`;
    const entityRows = await guacManager.queryMySQL(getEntityIdSql);
    const entityId = entityRows[0][0];

    // Create user with hashed password
    const createUserSql = `INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, email_address, full_name) 
      VALUES (${entityId}, UNHEX('${hash}'), UNHEX('${saltHex}'), NOW(), '${email || guacUsername + '@ctf.local'}', '${fullName || guacUsername}')`;
    await guacManager.execMySQLQuery(createUserSql);

    // Get user ID
    const getUserIdSql = `SELECT user_id FROM guacamole_user WHERE entity_id = ${entityId}`;
    const userRows = await guacManager.queryMySQL(getUserIdSql);
    const userId = userRows[0][0];

    await guacManager.close();

    console.log(`✅ Created Guacamole user: ${guacUsername} (entity_id: ${entityId}, user_id: ${userId})`);

    res.json({
      success: true,
      message: 'User created successfully',
      user: {
        username: guacUsername,
        userId: parseInt(userId),
        entityId: parseInt(entityId)
      },
      loginInfo: {
        url: 'http://localhost:8080/guacamole',
        username: guacUsername,
        password: password
      }
    });

  } catch (error) {
    console.error('Error creating Guacamole user:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to create user'
    });
  }
});

app.post('/api/guacamole/add-connection', async (req, res) => {
  try {
    const { 
      username, 
      connectionName, 
      protocol, 
      hostname, 
      port, 
      connectionUsername, 
      connectionPassword,
      parameters 
    } = req.body;

    if (!username || !connectionName || !protocol || !hostname) {
      return res.status(400).json({ 
        success: false, 
        error: 'Username, connectionName, protocol, and hostname are required' 
      });
    }

    const { GuacamolePostgreSQLManager } = await import('./guacamole-postgresql-manager.js');
    const guacManager = new GuacamolePostgreSQLManager();

    // Get entity ID for username
    const getEntitySql = `SELECT entity_id FROM guacamole_entity WHERE name = '${username}' AND type = 'USER'`;
    const entityRows = await guacManager.queryMySQL(getEntitySql);
    
    if (entityRows.length === 0) {
      await guacManager.close();
      return res.status(404).json({
        success: false,
        error: `User '${username}' not found`
      });
    }

    const entityId = entityRows[0][0];

    // Create connection
    const createConnSql = `INSERT INTO guacamole_connection (connection_name, protocol, max_connections) 
      VALUES ('${connectionName}', '${protocol}', 5)`;
    await guacManager.execMySQLQuery(createConnSql);

    // Get connection ID
    const getConnIdSql = `SELECT connection_id FROM guacamole_connection ORDER BY connection_id DESC LIMIT 1`;
    const connRows = await guacManager.queryMySQL(getConnIdSql);
    const connectionId = connRows[0][0];

    // Add connection parameters
    const params = [
      ['hostname', hostname],
      ['port', port || (protocol === 'ssh' ? '22' : '3389')],
      ['username', connectionUsername || 'root'],
      ['password', connectionPassword || 'kali']
    ];

    // Add additional parameters if provided
    if (parameters) {
      for (const [key, value] of Object.entries(parameters)) {
        params.push([key, value]);
      }
    }

    const paramValues = params.map(([name, value]) => 
      `(${connectionId}, '${name}', '${value}')`
    ).join(', ');

    const createParamsSql = `INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES ${paramValues}`;
    await guacManager.execMySQLQuery(createParamsSql);

    // Grant READ permission to user
    const grantUserPermSql = `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) 
      VALUES (${entityId}, ${connectionId}, 'READ')`;
    await guacManager.execMySQLQuery(grantUserPermSql);

    // Also grant to guacadmin for admin access
    const grantAdminPermSql = `INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission) 
      VALUES (1, ${connectionId}, 'READ')`;
    await guacManager.execMySQLQuery(grantAdminPermSql);

    await guacManager.close();

    console.log(`✅ Created connection: ${connectionName} (ID: ${connectionId}) for user ${username}`);

    res.json({
      success: true,
      message: 'Connection created successfully',
      connection: {
        connectionId: parseInt(connectionId),
        connectionName,
        protocol,
        hostname,
        port: port || (protocol === 'ssh' ? '22' : '3389')
      },
      access: {
        url: 'http://localhost:8080/guacamole',
        username,
        note: 'Login and select the connection from the dashboard'
      }
    });

  } catch (error) {
    console.error('Error adding connection:', error);
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to add connection'
    });
  }
});

// ===== SESSION MANAGEMENT API =====

// Delete session and cleanup Guacamole user
app.delete('/api/sessions/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    console.log(`\n🗑️  Cleaning up session: ${sessionId}`);
    
    // Delete Guacamole user for this session
    await sessionGuacManager.deleteSessionUser(sessionId);
    
    res.json({
      success: true,
      message: 'Session cleaned up successfully',
      sessionId
    });
  } catch (error) {
    console.error('Error cleaning up session:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// IMPROVEMENT: Add endpoint to cleanup specific challenge connection
app.delete('/api/challenges/:challengeName/guacamole', async (req, res) => {
  try {
    const { challengeName } = req.params;
    const { sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({
        success: false,
        error: 'Session ID is required in request body'
      });
    }
    
    console.log(`\n🗑️  Cleaning up Guacamole connection for challenge: ${challengeName}`);
    
    // Get connection name (with session ID suffix)
    const sessionPrefix = sessionId.substring(0, 8);
    const connectionName = `${challengeName}-${sessionPrefix}-ssh`;
    
    // Delete connection
    await guacamoleAgent.deleteConnection(connectionName);
    
    res.json({
      success: true,
      message: 'Connection deleted successfully',
      challengeName,
      connectionName
    });
  } catch (error) {
    console.error('Error deleting connection:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// IMPROVEMENT: Add endpoint to cleanup specific challenge connection
app.delete('/api/challenges/:challengeName/guacamole', async (req, res) => {
  try {
    const { challengeName } = req.params;
    const { sessionId } = req.body;
    
    if (!sessionId) {
      return res.status(400).json({
        success: false,
        error: 'Session ID is required in request body'
      });
    }
    
    console.log(`\n🗑️  Cleaning up Guacamole connection for challenge: ${challengeName}`);
    
    // Get connection name (with session ID suffix)
    const sessionPrefix = sessionId.substring(0, 8);
    const connectionName = `${challengeName}-${sessionPrefix}-ssh`;
    
    // Delete connection
    await guacamoleAgent.deleteConnection(connectionName);
    
    res.json({
      success: true,
      message: 'Connection deleted successfully',
      challengeName,
      connectionName
    });
  } catch (error) {
    console.error('Error deleting connection:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// IMPROVEMENT: Periodic cleanup of orphaned Guacamole connections
// Run cleanup every 6 hours
const CLEANUP_INTERVAL = 6 * 60 * 60 * 1000; // 6 hours

async function periodicGuacamoleCleanup() {
  try {
    console.log('\n🧹 Starting periodic Guacamole cleanup...');
    
    // Get list of valid challenges from GitHub
    const { gitManager } = await import('./git-manager.js');
    const challenges = await gitManager.listChallenges();
    
    // Clean up orphaned connections
    const { guacamoleAgent } = await import('./agents/guacamole-agent.js');
    const result = await guacamoleAgent.cleanupOrphanedConnections(challenges);
    
    console.log(`✅ Periodic cleanup complete: ${result.cleaned} orphaned connection(s) removed`);
  } catch (error) {
    console.error('❌ Periodic cleanup failed:', error.message);
  }
}

// Start periodic cleanup
setInterval(periodicGuacamoleCleanup, CLEANUP_INTERVAL);
console.log(`🕐 Periodic Guacamole cleanup scheduled (runs every 6 hours)`);

// Run initial cleanup after 1 minute (to allow service to start)
setTimeout(periodicGuacamoleCleanup, 60000);

// Get session user info
app.get('/api/sessions/:sessionId/guacamole', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const userInfo = sessionGuacManager.getSessionUser(sessionId);
    
    if (!userInfo) {
      return res.status(404).json({
        success: false,
        error: 'No Guacamole user for this session'
      });
    }
    
    res.json({
      success: true,
      user: {
        username: userInfo.username,
        entityId: userInfo.entityId,
        hasAccount: true
      }
    });
  } catch (error) {
    console.error('Error getting session user:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Security audit endpoint
app.post('/api/guacamole/audit', async (req, res) => {
  try {
    await sessionGuacManager.auditSessionUsers();
    
    res.json({
      success: true,
      message: 'Security audit completed'
    });
  } catch (error) {
    console.error('Error during audit:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Global error handlers
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

// Start server immediately, test connection in background
const server = app.listen(PORT, async () => {
  console.log(`\n🚀 CTF Automation Service started successfully`);
  console.log(`📡 Server running on port ${PORT}`);
  console.log(`🔗 API endpoint: http://localhost:${PORT}/api/chat`);
  console.log(`💚 Health check: http://localhost:${PORT}/health`);
  console.log(`📊 Cache stats: http://localhost:${PORT}/api/cache/stats\n`);
  console.log(`💡 MySQL connection will be tested on first challenge creation\n`);
  
  // IMPROVEMENT: Cleanup old checkpoints on startup
  checkpointManager.cleanupOld(7).catch(err => {
    console.warn('⚠️  Failed to cleanup old checkpoints:', err.message);
  });
  
  // IMPROVEMENT: Initialize content cache
  try {
    const { initializeContentCache, cleanupContentCache } = await import('./content-cache.js');
    await initializeContentCache();
    cleanupContentCache().catch(err => {
      console.warn('⚠️  Failed to cleanup content cache:', err.message);
    });
  } catch (cacheError) {
    console.warn('⚠️  Content cache initialization failed:', cacheError.message);
  }
  
  // Initialize tool learning system (build base image if needed)
  try {
    await initializeToolLearning();
  } catch (error) {
    console.warn('⚠️  Tool learning initialization failed:', error.message);
    console.warn('   Will use fallback mode without cached base image');
  }
});

server.on('error', (error) => {
  console.error('❌ Server error:', error);
  if (error.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Please kill the process or use a different port.`);
  }
  process.exit(1);
});
