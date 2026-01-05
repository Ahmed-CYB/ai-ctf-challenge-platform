/**
 * Core Orchestrator - Main orchestration system for CTF automation
 * 
 * This is the central coordinator that manages the entire workflow:
 * - Request validation
 * - Challenge creation
 * - Challenge deployment
 * - Error handling
 * - Result aggregation
 */

import { RequestValidator } from './request-validator.js';
import { ChallengeDesigner } from '../challenge/designer.js';
import { StructureBuilder } from '../challenge/structure-builder.js';
import { DockerfileGenerator } from '../challenge/dockerfile-generator.js';
import { ComposeGenerator } from '../challenge/compose-generator.js';
import { PreDeployValidator } from '../validation/pre-deploy-validator.js';
import { Deployer } from '../deployment/deployer.js';
import { PostDeployValidator } from '../validation/post-deploy-validator.js';
import { ErrorHandler } from './error-handler.js';
import { Logger } from './logger.js';
import { GitManager } from '../git-manager.js';
import { classifyConfirmation } from '../agents/confirmation-agent.js';
import { ContainerManager } from '../deployment/container-manager.js';

export class Orchestrator {
  constructor() {
    this.requestValidator = new RequestValidator();
    this.challengeDesigner = new ChallengeDesigner();
    this.structureBuilder = new StructureBuilder();
    this.dockerfileGenerator = new DockerfileGenerator();
    this.composeGenerator = new ComposeGenerator();
    this.preDeployValidator = new PreDeployValidator();
    this.deployer = new Deployer();
    this.postDeployValidator = new PostDeployValidator();
    this.errorHandler = new ErrorHandler();
    this.containerManager = new ContainerManager();
    this.logger = new Logger();
    this.gitManager = new GitManager();
  }

  /**
   * Main entry point for all requests
   */
  async processRequest(request) {
    // Validate request object
    if (!request || typeof request !== 'object') {
      return this.errorHandler.handleValidationError({
        valid: false,
        error: 'Invalid request object'
      });
    }
    
    const { message, sessionId, conversationHistory = [] } = request;
    
    // Validate message before processing
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return this.errorHandler.handleValidationError({
        valid: false,
        error: 'Message is required and must be a non-empty string'
      });
    }
    
    try {
      this.logger.info('Orchestrator', `Processing request: ${message.substring(0, 50)}...`);

      // Step 1: Validate request first to determine type
      const validationResult = await this.requestValidator.validate(message, conversationHistory);
      if (!validationResult || !validationResult.valid) {
        return this.errorHandler.handleValidationError(validationResult || { valid: false, error: 'Validation failed' });
      }

      const { type, category, requirements = {}, context = {} } = validationResult;

      // Check for pending deployment confirmation ONLY for deploy/run requests
      // This prevents greetings/questions from triggering confirmation checks
      if (type === 'deploy' || type === 'run') {
        const { dbManager } = await import('../db-manager.js');
        const pendingDeployment = await dbManager.getPendingDeployment(sessionId);
        
        if (pendingDeployment) {
          // User is responding to a confirmation request with a deploy command - handle it directly
          const { classifyConfirmation } = await import('../agents/confirmation-agent.js');
          const confirmation = await classifyConfirmation(message);
          
          if (confirmation.classification === 'CONFIRMATION') {
            // User confirmed - proceed with deployment
            return await this.handleChallengeDeployment(
              { challengeName: pendingDeployment.challenge_name },
              sessionId,
              {},
              message,
              pendingDeployment.existing_challenge_name
            );
          } else if (confirmation.classification === 'DENIAL') {
            // User denied - cancel deployment
            await dbManager.clearPendingDeployment(sessionId);
            return {
              success: false,
              error: 'Deployment cancelled',
              message: 'Deployment cancelled. The previous challenge will remain running.',
              cancelled: true
            };
          } else {
            // User said something else - ask again
            return {
              success: false,
              error: 'Confirmation required',
              message: `⚠️ **Confirmation Required**\n\nYou have a pending deployment request. The previous challenge "${pendingDeployment.existing_challenge_name}" will be terminated if you proceed.\n\nPlease confirm by saying "yes", "confirm", or "proceed" to continue, or "no" or "cancel" to cancel.`,
              requiresConfirmation: true,
              pendingDeployment: {
                newChallenge: pendingDeployment.challenge_name,
                existingChallenge: pendingDeployment.existing_challenge_name
              }
            };
          }
        }
      }
      
      // Also check for pending deployment if user says yes/confirm/no/cancel (even if not deploy command)
      // This allows users to confirm by just saying "yes" without repeating the deploy command
      // BUT only check if the message looks like a confirmation/denial, not a greeting
      const { dbManager } = await import('../db-manager.js');
      const pendingDeployment = await dbManager.getPendingDeployment(sessionId);
      if (pendingDeployment && (type === 'question' || type === 'unknown')) {
        // Only check confirmation if message is short and looks like yes/no/confirm/cancel
        // This prevents greetings like "hello" from triggering confirmation checks
        const messageLower = message.toLowerCase().trim();
        const looksLikeConfirmation = messageLower.length < 20 && (
          messageLower.match(/^(yes|y|confirm|proceed|go ahead|ok|okay|sure|yep|yeah|do it|deploy|continue)$/i) ||
          messageLower.match(/^(no|n|cancel|stop|don't|dont|abort|nevermind|never mind|nope|nah)$/i)
        );
        
        if (looksLikeConfirmation) {
          const { classifyConfirmation } = await import('../agents/confirmation-agent.js');
          const confirmation = await classifyConfirmation(message);
          
          if (confirmation.classification === 'CONFIRMATION') {
            // User confirmed - proceed with deployment
            return await this.handleChallengeDeployment(
              { challengeName: pendingDeployment.challenge_name },
              sessionId,
              {},
              message,
              pendingDeployment.existing_challenge_name
            );
          } else if (confirmation.classification === 'DENIAL') {
            // User denied - cancel deployment
            await dbManager.clearPendingDeployment(sessionId);
            return {
              success: false,
              error: 'Deployment cancelled',
              message: 'Deployment cancelled. The previous challenge will remain running.',
              cancelled: true
            };
          }
        }
        // If it doesn't look like a confirmation (like "hello"), continue with normal flow - don't block it
      }

      // Step 2: Route to appropriate handler
      switch (type) {
        case 'create':
          return await this.handleChallengeCreation(requirements, conversationHistory, sessionId);
        
        case 'deploy':
        case 'run':
          // 'run' is treated as 'deploy'
          // Pass the original message for confirmation handling
          return await this.handleChallengeDeployment(requirements, sessionId, context, message);
        
        case 'question':
          // Pass the original message directly, not from requirements
          return await this.handleQuestion(message, conversationHistory);
        
        default:
          return this.errorHandler.handleUnknownRequestType(type);
      }
    } catch (error) {
      return this.errorHandler.handleError(error, 'Orchestrator.processRequest');
    }
  }

  /**
   * Handle challenge creation workflow
   */
  async handleChallengeCreation(requirements, conversationHistory, sessionId) {
    // Validate inputs
    if (!requirements || typeof requirements !== 'object') {
      return this.errorHandler.handleValidationError({
        valid: false,
        error: 'Invalid requirements provided'
      });
    }
    
    if (!Array.isArray(conversationHistory)) {
      conversationHistory = [];
    }
    
    this.logger.info('Orchestrator', 'Starting challenge creation workflow');

    try {
      // Step 1: Design challenge (AI)
      this.logger.info('Orchestrator', 'Phase 1: Challenge Design');
      // Pass original message for better vulnerability extraction
      const design = await this.challengeDesigner.design(requirements, conversationHistory);
      
      if (!design || !design.success) {
        return this.errorHandler.handleDesignError(design || { success: false, error: 'Design failed' });
      }

      // Step 2: Build structure
      this.logger.info('Orchestrator', 'Phase 2: Structure Building');
      
      if (!design.data) {
        return this.errorHandler.handleDesignError({
          success: false,
          error: 'Design data is missing'
        });
      }
      
      const structure = await this.structureBuilder.build(design.data);
      
      if (!structure || !structure.success) {
        return this.errorHandler.handleStructureError(structure || { success: false, error: 'Structure building failed' });
      }

      // Step 3: Generate Dockerfiles
      this.logger.info('Orchestrator', 'Phase 3: Dockerfile Generation');
      
      if (!structure.data) {
        return this.errorHandler.handleStructureError({
          success: false,
          error: 'Structure data is missing'
        });
      }
      
      const dockerfiles = await this.dockerfileGenerator.generate(structure.data);
      
      if (!dockerfiles || !dockerfiles.success) {
        return this.errorHandler.handleDockerfileError(dockerfiles || { success: false, error: 'Dockerfile generation failed' });
      }

      // Step 4: Generate docker-compose.yml
      this.logger.info('Orchestrator', 'Phase 4: Compose Generation');
      
      if (!dockerfiles.data) {
        return this.errorHandler.handleDockerfileError({
          success: false,
          error: 'Dockerfile data is missing'
        });
      }
      
      const compose = await this.composeGenerator.generate(structure.data, dockerfiles.data);
      
      if (!compose || !compose.success) {
        return this.errorHandler.handleComposeError(compose || { success: false, error: 'Compose generation failed' });
      }

      // Step 5: Pre-deployment validation
      this.logger.info('Orchestrator', 'Phase 5: Pre-Deployment Validation');
      const validation = await this.preDeployValidator.validate(structure.data);
      
      if (!validation.success) {
        // Try to auto-fix
        const fixResult = await this.preDeployValidator.autoFix(validation.errors);
        if (!fixResult.success) {
          return this.errorHandler.handleValidationError(validation);
        }
      }

      // Step 6: Save to repository
      this.logger.info('Orchestrator', 'Phase 6: Saving to Repository');
      const saveResult = await this.structureBuilder.save(structure.data, dockerfiles.data, compose.data);
      
      if (!saveResult.success) {
        return this.errorHandler.handleSaveError(saveResult);
      }

      // Step 7: Optional test deployment (can be enabled via env var)
      // This validates that the challenge can actually be deployed
      if (process.env.TEST_DEPLOY_ON_CREATE === 'true') {
        this.logger.info('Orchestrator', 'Phase 7: Test Deployment (Validation)');
        try {
          const testDeployment = await this.deployer.deploy(structure.data.name, sessionId);
          if (!testDeployment.success) {
            this.logger.warn('Orchestrator', 'Test deployment failed, but challenge saved', {
              error: testDeployment.error
            });
            // Don't fail creation - just warn
          } else {
            this.logger.success('Orchestrator', 'Test deployment successful - challenge validated');
            // Clean up test deployment
            // Note: In production, you might want to keep it running or have a cleanup step
          }
        } catch (testError) {
          this.logger.warn('Orchestrator', 'Test deployment error (non-fatal)', {
            error: testError.message
          });
          // Don't fail creation - test deployment is optional
        }
      } else {
        this.logger.debug('Orchestrator', 'Test deployment skipped (set TEST_DEPLOY_ON_CREATE=true to enable)');
      }

      this.logger.success('Orchestrator', 'Challenge creation completed successfully');

      return {
        success: true,
        challenge: {
          name: structure.data.name,
          type: design.data.type,
          difficulty: design.data.difficulty,
          description: design.data.description,
          machines: structure.data.machines.map(m => ({
            name: m.name,
            role: m.role,
            services: m.services
          }))
        },
        readyForDeployment: true,
        message: `✅ Challenge "${structure.data.name}" created successfully!`
      };

    } catch (error) {
      return this.errorHandler.handleError(error, 'Orchestrator.handleChallengeCreation');
    }
  }

  /**
   * Handle challenge deployment workflow
   */
  async handleChallengeDeployment(requirements, sessionId, context = {}, userMessage = '', existingChallengeToTerminate = null) {
    // Validate inputs
    if (!requirements || typeof requirements !== 'object') {
      requirements = {};
    }
    
    if (!context || typeof context !== 'object') {
      context = {};
    }
    
    this.logger.info('Orchestrator', 'Starting challenge deployment workflow');

    try {
      let { challengeName } = requirements || {};

      // If challenge name is missing, try to get it from context
      if ((!challengeName || challengeName.trim().length === 0) && context?.challengeName) {
        challengeName = context.challengeName;
        this.logger.info('Orchestrator', `Using challenge name from context: ${challengeName}`);
      }

      // Validate challenge name is provided
      if (!challengeName || typeof challengeName !== 'string' || challengeName.trim().length === 0) {
        return {
          success: false,
          error: 'Challenge name required',
          message: context?.reasoning 
            ? `Could not determine which challenge to deploy. ${context.reasoning}`
            : 'Please specify the challenge name to deploy. Example: "deploy corporate-ftp-breach"',
          details: 'Challenge name was not provided or could not be extracted from conversation context',
          suggestion: 'Try: "deploy <challenge-name>" or create a challenge first, then say "deploy it"'
        };
      }

      // If existing challenge to terminate is provided (from confirmation), terminate it first
      if (existingChallengeToTerminate) {
        this.logger.info('Orchestrator', 'Terminating existing challenge before deployment', {
          existingChallenge: existingChallengeToTerminate,
          newChallenge: challengeName
        });
        
        try {
          const { dockerManager } = await import('../docker-manager.js');
          await dockerManager.cleanupMultiContainer(existingChallengeToTerminate);
          this.logger.success('Orchestrator', 'Old challenge terminated', {
            challengeName: existingChallengeToTerminate
          });
        } catch (cleanupError) {
          this.logger.warn('Orchestrator', 'Failed to terminate old challenge, continuing anyway', {
            error: cleanupError.message
          });
        }
      } else {
        // Check if there are other running challenges
        const runningChallenges = await this.containerManager.getRunningChallenges(challengeName);
        
        if (runningChallenges.length > 0) {
          // There are other challenges running - ask for confirmation
          const existingChallengeName = runningChallenges[0]; // Use first running challenge
          
          this.logger.info('Orchestrator', 'Found running challenge, requesting confirmation', {
            existingChallenge: existingChallengeName,
            newChallenge: challengeName
          });
          
          // Store pending deployment
          const { dbManager } = await import('../db-manager.js');
          await dbManager.storePendingDeployment(sessionId, challengeName, existingChallengeName);
          
          return {
            success: false,
            error: 'Confirmation required',
            message: `⚠️ **Confirmation Required**\n\nYou have a challenge "${existingChallengeName}" currently running. Deploying "${challengeName}" will terminate the previous challenge.\n\nPlease confirm by saying "yes", "confirm", or "proceed" to continue, or "no" or "cancel" to cancel.`,
            requiresConfirmation: true,
            pendingDeployment: {
              newChallenge: challengeName,
              existingChallenge: existingChallengeName
            }
          };
        }
      }

      // Step 1: Pre-deployment validation
      this.logger.info('Orchestrator', 'Phase 1: Pre-Deployment Validation');
      const preValidation = await this.preDeployValidator.validateChallenge(challengeName);
      
      if (!preValidation.success) {
        const fixResult = await this.preDeployValidator.autoFix(preValidation.errors);
        if (!fixResult.success) {
          return this.errorHandler.handleValidationError(preValidation);
        }
      }

      // Step 2: Deploy
      this.logger.info('Orchestrator', 'Phase 2: Deployment');
      const deployment = await this.deployer.deploy(challengeName, sessionId);
      
      if (!deployment.success) {
        return this.errorHandler.handleDeploymentError(deployment);
      }

      // Step 3: Post-deployment validation
      this.logger.info('Orchestrator', 'Phase 3: Post-Deployment Validation');
      const postValidation = await this.postDeployValidator.validate(deployment.data);
      
      if (!postValidation.success) {
        // Try to auto-fix
        const fixResult = await this.postDeployValidator.autoFix(postValidation.errors, deployment.data);
        if (!fixResult.success) {
          return this.errorHandler.handlePostDeploymentError(postValidation);
        }
      }

      this.logger.success('Orchestrator', 'Challenge deployment completed successfully');

      // Get challenge metadata for formatted response
      let challengeMetadata = null;
      let challengeDescription = 'No description available';
      let challengeType = 'Unknown';
      let flagFormat = 'CTF{...}';

      try {
        challengeMetadata = await this.gitManager.getChallengeMetadata(challengeName);
        
        if (challengeMetadata) {
          challengeDescription = challengeMetadata.description || challengeMetadata.title || challengeDescription;
          challengeType = challengeMetadata.category || challengeMetadata.subcategories?.[0] || challengeType;
          
          // Extract flag format (hide actual flag value)
          if (challengeMetadata.flag) {
            const flag = challengeMetadata.flag;
            if (flag.includes('{')) {
              flagFormat = flag.substring(0, flag.indexOf('{') + 1) + '...}';
            }
          }
        } else {
          // Fallback: Try to parse README.md
          try {
            const fs = await import('fs/promises');
            const pathModule = await import('path');
            const readmePath = pathModule.join(this.gitManager.clonePath, 'challenges', challengeName, 'README.md');
            const readmeContent = await fs.readFile(readmePath, 'utf-8');
            
            // Extract description
            const descMatch = readmeContent.match(/## Description\s*\n([^\n]+(?:\n[^\n]+)*?)(?=\n##|\n#|$)/s);
            if (descMatch) {
              challengeDescription = descMatch[1].trim();
            }
            
            // Extract flag format
            const flagMatch = readmeContent.match(/## Flag Format\s*\n([^\n]+)/);
            if (flagMatch) {
              const flag = flagMatch[1].trim();
              if (flag.includes('{')) {
                flagFormat = flag.substring(0, flag.indexOf('{') + 1) + '...}';
              }
            }
            
            // Extract category/type from difficulty or hints
            const difficultyMatch = readmeContent.match(/## Difficulty\s*\n([^\n]+)/);
            if (difficultyMatch) {
              challengeType = difficultyMatch[1].trim();
            }
          } catch (readmeError) {
            this.logger.warn('Orchestrator', 'Could not parse README.md', { error: readmeError.message });
          }
        }
      } catch (error) {
        this.logger.warn('Orchestrator', 'Could not load challenge metadata', { error: error.message });
      }

      // Format deployment response with all requested information
      const guacamoleInfo = deployment.data.guacamole || {};
      const guacamoleUrl = (guacamoleInfo && guacamoleInfo.success && guacamoleInfo.url) ? guacamoleInfo.url : 'Not available';
      const guacamoleUsername = guacamoleInfo.username || 'Not available';
      const guacamolePassword = guacamoleInfo.password || 'Not available';
      
      // Build user-friendly message with all requested information
      let message = `✅ Challenge "${challengeName}" deployed successfully!\n\n`;
      message += `**Challenge Details:**\n`;
      message += `- **Name**: ${challengeName}\n`;
      message += `- **Category**: ${challengeType}\n`;
      message += `- **Description**: ${challengeDescription}\n`;
      message += `\n**Guacamole Access:**\n`;
      message += `- **Login URL**: ${guacamoleUrl}\n`;
      message += `- **Username**: ${guacamoleUsername}\n`;
      message += `- **Password**: ${guacamolePassword}\n`;
      
      const formattedResponse = {
        success: true,
        message: message,
        challengeName: challengeName,
        challengeType: challengeType,
        challengeDescription: challengeDescription,
        flagFormat: flagFormat,
        guacamoleLoginUrl: guacamoleUrl,
        guacamoleTempUser: guacamoleUsername,
        guacamoleTempPassword: guacamolePassword,
        deployment: {
          challengeName,
          containers: deployment.data.containers,
          networks: deployment.data.networks,
          guacamole: deployment.data.guacamole
        }
      };

      return formattedResponse;

    } catch (error) {
      return this.errorHandler.handleError(error, 'Orchestrator.handleChallengeDeployment');
    }
  }

  /**
   * Handle question requests
   */
  async handleQuestion(userMessage, conversationHistory) {
    this.logger.info('Orchestrator', 'Handling question request');
    
    try {
      // Import questions agent
      const { answerQuestion } = await import('../agents/questions-agent.js');
      
      if (!userMessage || typeof userMessage !== 'string' || userMessage.trim().length === 0) {
        return {
          success: false,
          error: 'Question message is required',
          message: 'Please provide a question to answer'
        };
      }
      
      // Answer the question using the questions agent
      const result = await answerQuestion(userMessage, conversationHistory);
      
      if (!result.success) {
        return {
          success: false,
          error: result.error || 'Failed to answer question',
          message: result.fallback || 'I apologize, but I encountered an error answering your question. Please try rephrasing it.'
        };
      }
      
      this.logger.success('Orchestrator', 'Question answered successfully');
      
      return {
        success: true,
        answer: result.answer,
        message: result.answer, // For compatibility
        category: 'question',
        // Only include additionalHelp if it exists (not for greetings)
        ...(result.additionalHelp && { additionalHelp: result.additionalHelp }),
        ...(result.deploymentInfo && { deploymentInfo: result.deploymentInfo })
      };
      
    } catch (error) {
      this.logger.error('Orchestrator', 'Question handling failed', error.stack);
      return this.errorHandler.handleError(error, 'Orchestrator.handleQuestion');
    }
  }
}

export const orchestrator = new Orchestrator();


