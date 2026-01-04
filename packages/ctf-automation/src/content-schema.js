/**
 * Content Schema
 * IMPROVEMENT: Standardized content format for all content agents
 */

/**
 * Standard content schema interface
 * @typedef {Object} ChallengeContent
 * @property {File[]} files - Array of files
 * @property {string} flag - CTF flag
 * @property {ContentConfiguration} configuration - Configuration object
 * @property {ContentMetadata} [metadata] - Optional metadata
 */

/**
 * @typedef {Object} File
 * @property {string} name - File name
 * @property {string} [path] - File path (relative)
 * @property {string} content - File content
 */

/**
 * @typedef {Object} ContentConfiguration
 * @property {string} [vulnerability] - Vulnerability type (web)
 * @property {string} [serviceType] - Service type (network)
 * @property {string} [cryptoType] - Crypto type (crypto)
 * @property {string} difficulty - Difficulty level (easy|medium|hard)
 * @property {string} exploitPath - How to exploit
 * @property {string} [flagLocation] - Where flag is located
 * @property {string[]} tools - Required tools
 * @property {string} [setup] - Setup commands
 * @property {string[]} [hints] - Progressive hints
 * @property {string[]} [learningObjectives] - Learning objectives
 */

/**
 * @typedef {Object} ContentMetadata
 * @property {string} [author] - Content author
 * @property {string} [version] - Content version
 * @property {string[]} [tags] - Content tags
 * @property {Date} [created] - Creation date
 */

/**
 * Validate content against schema
 * @param {ChallengeContent} content - Content to validate
 * @returns {object} Validation result
 */
export function validateContentSchema(content) {
  const issues = [];
  
  // Required fields
  if (!content.files || !Array.isArray(content.files)) {
    issues.push('Content must have files array');
  }
  
  if (!content.flag || typeof content.flag !== 'string') {
    issues.push('Content must have flag string');
  }
  
  if (!content.configuration || typeof content.configuration !== 'object') {
    issues.push('Content must have configuration object');
  }
  
  // Validate files
  if (content.files) {
    content.files.forEach((file, index) => {
      if (!file.name) {
        issues.push(`File ${index} missing name`);
      }
      if (!file.content) {
        issues.push(`File ${file.name || index} missing content`);
      }
    });
  }
  
  // Validate configuration
  if (content.configuration) {
    if (!content.configuration.difficulty) {
      issues.push('Configuration missing difficulty');
    }
    if (!content.configuration.exploitPath) {
      issues.push('Configuration missing exploitPath');
    }
    if (!content.configuration.tools || !Array.isArray(content.configuration.tools)) {
      issues.push('Configuration missing tools array');
    }
    // ✅ CRITICAL: Setup commands are MANDATORY
    if (!content.configuration.setup || typeof content.configuration.setup !== 'string' || content.configuration.setup.trim().length === 0) {
      issues.push('Configuration missing setup commands (MANDATORY). The setup field must contain service startup commands.');
    }
  }
  
  return {
    valid: issues.length === 0,
    issues
  };
}

/**
 * Normalize content to schema
 * @param {object} content - Content to normalize
 * @returns {ChallengeContent} Normalized content
 */
export function normalizeContent(content) {
  return {
    files: content.files || [],
    flag: content.flag || '',
    configuration: {
      ...content.configuration,
      difficulty: content.configuration?.difficulty || 'medium',
      tools: content.configuration?.tools || [],
      hints: content.configuration?.hints || [],
      learningObjectives: content.configuration?.learningObjectives || []
    },
    metadata: {
      ...content.metadata,
      created: content.metadata?.created || new Date()
    }
  };
}

