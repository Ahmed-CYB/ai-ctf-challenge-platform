/**
 * Content Variation Manager
 * IMPROVEMENT: Ensures unique and varied challenge content
 */

import crypto from 'crypto';

/**
 * Variation strategies for different aspects
 */
const VARIATION_STRATEGIES = {
  web: {
    vulnerabilities: [
      'SQL Injection (login bypass)',
      'SQL Injection (data exfiltration)',
      'SQL Injection (blind)',
      'XSS (stored)',
      'XSS (reflected)',
      'XSS (DOM-based)',
      'File Upload (unrestricted)',
      'File Upload (path traversal)',
      'Authentication bypass',
      'CSRF',
      'SSRF',
      'XXE',
      'Command Injection',
      'JWT manipulation',
      'Session fixation'
    ],
    contexts: [
      'corporate login portal',
      'e-commerce website',
      'blog platform',
      'file sharing service',
      'admin dashboard',
      'user profile system',
      'API endpoint',
      'comment system',
      'search functionality',
      'password reset page'
    ],
    technologies: [
      'PHP with MySQL',
      'Node.js with MongoDB',
      'Python Flask with SQLite',
      'Java Spring with PostgreSQL',
      'Ruby on Rails with MySQL'
    ]
  },
  network: {
    services: [
      'FTP server',
      'SMB share',
      'SSH server',
      'Telnet service',
      'RDP service',
      'HTTP service',
      'SNMP service',
      'NFS share',
      'TFTP server',
      'Custom protocol'
    ],
    misconfigurations: [
      'Anonymous access enabled',
      'Weak default credentials',
      'Unencrypted protocol',
      'Exposed sensitive files',
      'Null session allowed',
      'Weak encryption',
      'Missing access controls',
      'Information disclosure',
      'Directory traversal',
      'Privilege escalation'
    ],
    scenarios: [
      'file server',
      'backup system',
      'development server',
      'legacy system',
      'misconfigured service',
      'exposed internal service',
      'testing environment',
      'staging server',
      'shared resource',
      'public access point'
    ]
  },
  crypto: {
    cipherTypes: [
      'Caesar cipher',
      'Vigenère cipher',
      'Substitution cipher',
      'Transposition cipher',
      'XOR cipher',
      'Base64 encoding',
      'Hex encoding',
      'ROT13',
      'Atbash cipher',
      'Rail fence cipher',
      'RSA (weak key)',
      'AES (weak implementation)',
      'Hash collision',
      'Encoding chain',
      'Custom cipher'
    ],
    contexts: [
      'encrypted message',
      'password hash',
      'encoded secret',
      'ciphertext file',
      'encrypted database',
      'secure communication',
      'hidden message',
      'encoded flag',
      'cryptographic puzzle',
      'encryption challenge'
    ]
  }
};

/**
 * Generate variation seed from scenario
 */
function generateVariationSeed(scenario, category) {
  const seedString = `${category}:${scenario.title || ''}:${scenario.description || ''}:${Date.now()}`;
  return crypto.createHash('sha256').update(seedString).digest('hex').substring(0, 16);
}

/**
 * Get random element from array using seed
 */
function seededRandom(seed, array) {
  const hash = crypto.createHash('md5').update(seed + array.join('')).digest('hex');
  const index = parseInt(hash.substring(0, 8), 16) % array.length;
  return array[index];
}

/**
 * Generate variation parameters for content generation
 * @param {string} category - Content category
 * @param {object} scenario - Scenario object
 * @returns {object} Variation parameters
 */
export function generateVariationParams(category, scenario) {
  const seed = generateVariationSeed(scenario, category);
  const strategies = VARIATION_STRATEGIES[category];
  
  if (!strategies) {
    return {};
  }

  const variations = {};
  
  switch (category) {
    case 'web':
      variations.vulnerability = seededRandom(seed + 'vuln', strategies.vulnerabilities);
      variations.context = seededRandom(seed + 'ctx', strategies.contexts);
      variations.technology = seededRandom(seed + 'tech', strategies.technologies);
      variations.complexity = seededRandom(seed + 'comp', ['simple', 'moderate', 'complex']);
      break;
      
    case 'network':
      variations.service = seededRandom(seed + 'svc', strategies.services);
      variations.misconfiguration = seededRandom(seed + 'mis', strategies.misconfigurations);
      variations.scenario = seededRandom(seed + 'scen', strategies.scenarios);
      variations.port = 20 + (parseInt(seed.substring(0, 2), 16) % 10); // Random port 20-29
      break;
      
    case 'crypto':
      variations.cipherType = seededRandom(seed + 'ciph', strategies.cipherTypes);
      variations.context = seededRandom(seed + 'ctx', strategies.contexts);
      variations.encoding = seededRandom(seed + 'enc', ['base64', 'hex', 'binary', 'ascii']);
      variations.complexity = seededRandom(seed + 'comp', ['single', 'chained', 'nested']);
      break;
  }
  
  return variations;
}

/**
 * Inject variation into AI prompt
 * @param {string} basePrompt - Base prompt
 * @param {object} variations - Variation parameters
 * @returns {string} Enhanced prompt with variations
 */
export function injectVariationsIntoPrompt(basePrompt, variations) {
  let enhancedPrompt = basePrompt;
  
  // Add variation instructions
  if (Object.keys(variations).length > 0) {
    enhancedPrompt += '\n\nVARIATION REQUIREMENTS (to ensure uniqueness):\n';
    for (const [key, value] of Object.entries(variations)) {
      enhancedPrompt += `- ${key}: ${value}\n`;
    }
    enhancedPrompt += '\nUse these variations to create a unique challenge that differs from previous ones.';
  }
  
  return enhancedPrompt;
}

/**
 * Check if content is too similar to cached content
 * @param {object} newContent - New content to check
 * @param {object} cachedContent - Cached content to compare
 * @returns {boolean} True if too similar
 */
export function isContentTooSimilar(newContent, cachedContent) {
  // Compare key characteristics
  const similarityScore = calculateSimilarity(newContent, cachedContent);
  
  // If similarity > 80%, consider it too similar
  return similarityScore > 0.8;
}

/**
 * Calculate similarity between two content objects
 */
function calculateSimilarity(content1, content2) {
  let matches = 0;
  let total = 0;
  
  // Compare vulnerability/service type
  if (content1.configuration?.vulnerability && content2.configuration?.vulnerability) {
    total++;
    if (content1.configuration.vulnerability === content2.configuration.vulnerability) {
      matches++;
    }
  }
  
  if (content1.configuration?.serviceType && content2.configuration?.serviceType) {
    total++;
    if (content1.configuration.serviceType === content2.configuration.serviceType) {
      matches++;
    }
  }
  
  if (content1.configuration?.cryptoType && content2.configuration?.cryptoType) {
    total++;
    if (content1.configuration.cryptoType === content2.configuration.cryptoType) {
      matches++;
    }
  }
  
  // Compare file structure
  if (content1.files && content2.files) {
    total++;
    const files1 = content1.files.map(f => f.name).sort().join(',');
    const files2 = content2.files.map(f => f.name).sort().join(',');
    if (files1 === files2) {
      matches++;
    }
  }
  
  return total > 0 ? matches / total : 0;
}

/**
 * Generate unique flag based on scenario and variations
 */
export function generateUniqueFlag(category, scenario, variations) {
  const seed = generateVariationSeed(scenario, category);
  const variationHash = crypto.createHash('md5')
    .update(JSON.stringify(variations))
    .digest('hex')
    .substring(0, 8);
  
  const timestamp = Date.now().toString(36).substring(0, 6);
  const random = crypto.randomBytes(4).toString('hex');
  
  return `CTF{${category}_${variationHash}_${timestamp}_${random}}`;
}

/**
 * Add randomization to fallback content
 */
export function randomizeFallbackContent(fallbackContent, variations) {
  const randomized = JSON.parse(JSON.stringify(fallbackContent)); // Deep copy
  
  // Randomize flag
  randomized.flag = generateUniqueFlag(
    fallbackContent.configuration?.vulnerability || 
    fallbackContent.configuration?.serviceType ||
    fallbackContent.configuration?.cryptoType || 'misc',
    {},
    variations
  );
  
  // Add variation-specific modifications
  if (variations.vulnerability && randomized.configuration) {
    randomized.configuration.vulnerability = variations.vulnerability.toLowerCase().split(' ')[0];
  }
  
  if (variations.service && randomized.configuration) {
    randomized.configuration.serviceType = variations.service.toLowerCase();
  }
  
  if (variations.cipherType && randomized.configuration) {
    randomized.configuration.cryptoType = variations.cipherType.toLowerCase().split(' ')[0];
  }
  
  return randomized;
}

