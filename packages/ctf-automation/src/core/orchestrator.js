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
    this.logger = new Logger();
    this.gitManager = new GitManager();
  }

  /**
   * Main entry point for all requests
   */
  async processRequest(request) {
    const { message, sessionId, conversationHistory = [] } = request;
    
    try {
      this.logger.info('Orchestrator', `Processing request: ${message.substring(0, 50)}...`);

      // Step 1: Validate request
      const validationResult = await this.requestValidator.validate(message, conversationHistory);
      if (!validationResult.valid) {
        return this.errorHandler.handleValidationError(validationResult);
      }

      const { type, category, requirements, context } = validationResult;

      // Step 2: Route to appropriate handler
      switch (type) {
        case 'create':
          return await this.handleChallengeCreation(requirements, conversationHistory, sessionId);
        
        case 'deploy':
        case 'run':
          // 'run' is treated as 'deploy'
          return await this.handleChallengeDeployment(requirements, sessionId, context);
        
        case 'question':
          // Pass the original message directly, not from requirements
          return await this.handleQuestion(message, conversationHistory, requirements);
        
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
    this.logger.info('Orchestrator', 'Starting challenge creation workflow');

    try {
      // 🔍 Validate that we have sufficient details before proceeding
      const validation = this.validateCreationRequirements(requirements, conversationHistory);
      if (!validation.valid) {
        this.logger.info('Orchestrator', 'Insufficient details for challenge creation, asking for clarification');
        // Route to question handler to ask for clarification
        const originalMessage = conversationHistory.length > 0 
          ? conversationHistory[conversationHistory.length - 1]?.content 
          : 'create ctf challenge';
        return await this.handleQuestion(originalMessage, conversationHistory, {
          needsClarification: true,
          originalIntent: 'create',
          missingDetails: validation.missingDetails
        });
      }

      // Step 1: Design challenge (AI)
      this.logger.info('Orchestrator', 'Phase 1: Challenge Design');
      // Pass original message for better vulnerability extraction
      const design = await this.challengeDesigner.design(requirements, conversationHistory);
      
      if (!design.success) {
        return this.errorHandler.handleDesignError(design);
      }

      // Step 2: Build structure
      this.logger.info('Orchestrator', 'Phase 2: Structure Building');
      const structure = await this.structureBuilder.build(design.data);
      
      if (!structure.success) {
        return this.errorHandler.handleStructureError(structure);
      }

      // Step 3: Generate Dockerfiles
      this.logger.info('Orchestrator', 'Phase 3: Dockerfile Generation');
      const dockerfiles = await this.dockerfileGenerator.generate(structure.data);
      
      if (!dockerfiles.success) {
        return this.errorHandler.handleDockerfileError(dockerfiles);
      }

      // Step 4: Generate docker-compose.yml
      this.logger.info('Orchestrator', 'Phase 4: Compose Generation');
      const compose = await this.composeGenerator.generate(structure.data, dockerfiles.data);
      
      if (!compose.success) {
        return this.errorHandler.handleComposeError(compose);
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
  async handleChallengeDeployment(requirements, sessionId, context = {}) {
    this.logger.info('Orchestrator', 'Starting challenge deployment workflow');

    try {
      let { challengeName } = requirements;

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
      const formattedResponse = {
        success: true,
        challengeName: challengeName,
        challengeType: challengeType,
        challengeDescription: challengeDescription,
        flagFormat: flagFormat,
        guacamoleLoginUrl: guacamoleInfo.url || guacamoleInfo.success === false ? 'Not available' : 'Not available',
        guacamoleTempUser: guacamoleInfo.username || 'Not available',
        guacamoleTempPassword: guacamoleInfo.password || 'Not available',
        deployment: {
          challengeName,
          containers: deployment.data.containers,
          networks: deployment.data.networks,
          guacamole: deployment.data.guacamole
        },
        message: `✅ Challenge "${challengeName}" deployed successfully!`
      };

      return formattedResponse;

    } catch (error) {
      return this.errorHandler.handleError(error, 'Orchestrator.handleChallengeDeployment');
    }
  }

  /**
   * Handle question requests
   */
  async handleQuestion(userMessage, conversationHistory, requirements = {}) {
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
      
      // Pass requirements to questions agent if this is a vague creation request
      let enhancedMessage = userMessage;
      if (requirements.needsClarification && requirements.originalIntent === 'create') {
        enhancedMessage = `[VAGUE_CREATION_REQUEST] ${userMessage}`;
        // Add missing details context if available
        if (requirements.missingDetails && requirements.missingDetails.length > 0) {
          enhancedMessage += ` [MISSING: ${requirements.missingDetails.join(', ')}]`;
        }
      }
      
      // Answer the question using the questions agent
      const result = await answerQuestion(enhancedMessage, conversationHistory);
      
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

  /**
   * Validate that creation requirements have sufficient details
   * Returns { valid: boolean, missingDetails: string[] }
   */
  validateCreationRequirements(requirements, conversationHistory = []) {
    const missingDetails = [];
    
    // Check if we have a challenge type or specific vulnerability mentioned
    const hasChallengeType = requirements.challengeType && 
                            requirements.challengeType !== 'unknown' && 
                            requirements.challengeType !== null;
    
    // Check if we have services mentioned
    const hasServices = requirements.services && 
                        Array.isArray(requirements.services) && 
                        requirements.services.length > 0;
    
    // Check conversation history for technical keywords
    const lastMessage = conversationHistory.length > 0 
      ? conversationHistory[conversationHistory.length - 1]?.content || ''
      : '';
    const hasTechnicalKeywords = /(ftp|ssh|samba|smb|sql|injection|xss|eternal|blue|vulnerability|exploit|crypto|web|network|pwn|buffer|overflow|hash|encrypt|decrypt)/i.test(lastMessage);
    
    // If we don't have challenge type, services, or technical keywords, it's vague
    if (!hasChallengeType && !hasServices && !hasTechnicalKeywords) {
      missingDetails.push('vulnerability type or challenge category');
    }
    
    // Note: We don't require difficulty level as it can default to medium
    
    return {
      valid: missingDetails.length === 0,
      missingDetails
    };
  }
}

export const orchestrator = new Orchestrator();


