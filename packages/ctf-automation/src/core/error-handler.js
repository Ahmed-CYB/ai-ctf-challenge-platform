/**
 * Centralized Error Handler
 * 
 * Responsibilities:
 * - Handle all errors consistently
 * - Classify errors
 * - Provide user-friendly error messages
 * - Log errors for debugging
 */

import { Logger } from './logger.js';

export class ErrorHandler {
  constructor() {
    this.logger = new Logger();
  }

  /**
   * Handle any error
   */
  handleError(error, context) {
    this.logger.error(context, error.message, error.stack);

    return {
      success: false,
      error: 'An unexpected error occurred',
      message: this.getUserFriendlyMessage(error),
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    };
  }

  /**
   * Handle validation errors
   */
  handleValidationError(validationResult) {
    // Special handling for Windows vulnerability rejections (AI-detected)
    if (validationResult.type === 'windows_not_supported') {
      const detection = validationResult.detection || {};
      return {
        success: false,
        error: 'Windows challenges are not supported',
        message: validationResult.message || 'Windows challenges are not supported. This platform only supports Linux-based challenges.',
        type: 'windows_not_supported',
        detection: {
          os: detection.os || 'windows',
          confidence: detection.confidence || 0.8,
          reasoning: detection.reasoning || 'AI detected Windows-specific vulnerability',
          vulnerability: detection.vulnerability || null,
          cve: detection.cve || null,
          alternative: detection.alternative || null
        },
        suggestion: detection.alternative || 'Try requesting a Linux-based challenge instead, such as "create ctf challenge eternal blue" or "create ctf challenge ftp"'
      };
    }
    
    return {
      success: false,
      error: 'Validation failed',
      message: validationResult.message || validationResult.error || 'Invalid request',
      details: validationResult.details
    };
  }

  /**
   * Handle design errors
   */
  handleDesignError(designResult) {
    return {
      success: false,
      error: 'Challenge design failed',
      message: designResult.error || 'Failed to design challenge',
      details: designResult.details
    };
  }

  /**
   * Handle structure building errors
   */
  handleStructureError(structureResult) {
    return {
      success: false,
      error: 'Structure building failed',
      message: structureResult.error || 'Failed to build challenge structure',
      details: structureResult.details
    };
  }

  /**
   * Handle Dockerfile generation errors
   */
  handleDockerfileError(dockerfileResult) {
    return {
      success: false,
      error: 'Dockerfile generation failed',
      message: dockerfileResult.error || 'Failed to generate Dockerfiles',
      details: dockerfileResult.details
    };
  }

  /**
   * Handle compose generation errors
   */
  handleComposeError(composeResult) {
    return {
      success: false,
      error: 'Compose generation failed',
      message: composeResult.error || 'Failed to generate docker-compose.yml',
      details: composeResult.details
    };
  }

  /**
   * Handle save errors
   */
  handleSaveError(saveResult) {
    return {
      success: false,
      error: 'Save failed',
      message: saveResult.error || 'Failed to save challenge to repository',
      details: saveResult.details
    };
  }

  /**
   * Handle deployment errors
   */
  handleDeploymentError(deploymentResult) {
    // Extract user-friendly message without stack traces or file paths
    let userMessage = 'Challenge deploy failed';
    
    // Check for specific error types to provide better messages
    if (deploymentResult.error) {
      const errorLower = deploymentResult.error.toLowerCase();
      
      // Subnet overlap - provide helpful message
      if (errorLower.includes('subnet') || errorLower.includes('overlap')) {
        userMessage = 'Challenge deploy failed: Network configuration conflict. Please try again.';
      }
      // Container creation failure
      else if (errorLower.includes('container') || errorLower.includes('docker compose')) {
        userMessage = 'Challenge deploy failed: Could not create containers. Please check challenge configuration.';
      }
      // Generic failure
      else {
        userMessage = 'Challenge deploy failed';
      }
    }
    
    return {
      success: false,
      error: 'Deployment failed',
      message: userMessage,
      // Don't expose internal details to users
      details: process.env.NODE_ENV === 'development' ? deploymentResult.details : undefined
    };
  }

  /**
   * Handle post-deployment errors
   */
  handlePostDeploymentError(validationResult) {
    return {
      success: false,
      error: 'Post-deployment validation failed',
      message: validationResult.error || 'Deployed challenge failed validation',
      details: validationResult.details
    };
  }

  /**
   * Handle unknown request type
   */
  handleUnknownRequestType(type) {
    return {
      success: false,
      error: 'Unknown request type',
      message: `Unknown request type: ${type}. Supported types: create, deploy, question.`
    };
  }

  /**
   * Get user-friendly error message
   */
  getUserFriendlyMessage(error) {
    const errorMessage = error.message?.toLowerCase() || '';

    if (errorMessage.includes('api key') || errorMessage.includes('api_key')) {
      return 'API key is missing or invalid. Please check your .env file.';
    }

    if (errorMessage.includes('docker') || errorMessage.includes('container')) {
      return 'Docker operation failed. Please ensure Docker is running.';
    }

    if (errorMessage.includes('network') || errorMessage.includes('connection')) {
      return 'Network operation failed. Please check your network configuration.';
    }

    if (errorMessage.includes('permission') || errorMessage.includes('access')) {
      return 'Permission denied. Please check file permissions and Docker access.';
    }

    return 'An error occurred while processing your request. Please try again.';
  }
}


