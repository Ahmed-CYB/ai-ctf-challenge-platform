/**
 * Content Quality Validator
 * IMPROVEMENT: Validates content quality, exploitability, and educational value
 */

/**
 * Validate content quality
 * @param {object} content - Content object from agent
 * @param {string} category - Content category (web, network, crypto)
 * @returns {object} Validation results
 */
export async function validateContentQuality(content, category) {
  const results = {
    valid: true,
    scores: {},
    issues: [],
    warnings: []
  };

  // 1. Structure Validation
  const structureCheck = validateStructure(content);
  results.scores.structure = structureCheck.score;
  if (!structureCheck.valid) {
    results.valid = false;
    results.issues.push(...structureCheck.issues);
  }

  // 2. Flag Validation
  const flagCheck = validateFlag(content.flag);
  results.scores.flag = flagCheck.score;
  if (!flagCheck.valid) {
    results.valid = false;
    results.issues.push(...flagCheck.issues);
  }

  // 3. Placeholder Detection
  const placeholderCheck = detectPlaceholders(content);
  results.scores.noPlaceholders = placeholderCheck.score;
  if (!placeholderCheck.valid) {
    results.valid = false;
    results.issues.push(...placeholderCheck.issues);
  }

  // 4. Educational Value
  const educationalCheck = scoreEducationalValue(content);
  results.scores.educational = educationalCheck.score;
  if (educationalCheck.score < 0.5) {
    results.warnings.push('Low educational value - consider adding learning objectives');
  }

  // 5. Hint Quality
  const hintCheck = validateHints(content);
  results.scores.hints = hintCheck.score;
  if (hintCheck.score < 0.5) {
    results.warnings.push('Hints may be too revealing or not helpful enough');
  }

  // 6. Category-Specific Validation
  const categoryCheck = validateCategorySpecific(content, category);
  results.scores.categorySpecific = categoryCheck.score;
  if (!categoryCheck.valid) {
    results.warnings.push(...categoryCheck.warnings);
  }

  // Calculate overall score
  const scores = Object.values(results.scores);
  results.overallScore = scores.length > 0 
    ? scores.reduce((a, b) => a + b, 0) / scores.length 
    : 0;

  return results;
}

/**
 * Validate content structure
 */
function validateStructure(content) {
  const issues = [];
  let score = 1.0;

  if (!content.files || !Array.isArray(content.files) || content.files.length === 0) {
    issues.push('Content must include at least one file');
    score = 0;
  }

  if (!content.configuration) {
    issues.push('Content must include configuration object');
    score = 0;
  }

  for (const file of content.files || []) {
    if (!file.name) {
      issues.push('File missing name');
      score -= 0.1;
    }
    if (!file.content) {
      issues.push(`File ${file.name} missing content`);
      score -= 0.2;
    }
  }

  return {
    valid: issues.length === 0,
    score: Math.max(0, score),
    issues
  };
}

/**
 * Validate flag format
 */
function validateFlag(flag) {
  const issues = [];
  let score = 1.0;

  if (!flag) {
    issues.push('Flag is missing');
    return { valid: false, score: 0, issues };
  }

  if (!/^CTF\{[a-zA-Z0-9_\-]{10,}\}$/.test(flag)) {
    issues.push('Flag does not match CTF format: CTF{...}');
    score = 0.5;
  }

  if (flag.length < 15) {
    issues.push('Flag is too short (minimum 15 characters)');
    score -= 0.2;
  }

  if (flag.includes('placeholder') || flag.includes('flag_here')) {
    issues.push('Flag contains placeholder text');
    score = 0;
  }

  return {
    valid: issues.length === 0 && score >= 0.8,
    score,
    issues
  };
}

/**
 * Detect placeholders in content
 */
function detectPlaceholders(content) {
  const issues = [];
  // IMPROVEMENT: More specific placeholder patterns - avoid false positives
  const placeholderPatterns = [
    /\[PLACEHOLDER/i,
    /\[INSERT/i,
    /\[REPLACE/i,
    /\[FILL IN/i,
    /\[ADD HERE/i,
    /TODO:\s*[A-Z]/i,  // TODO: followed by capital letter (more specific)
    /FIXME:\s*[A-Z]/i,  // FIXME: followed by capital letter
    /XXX:\s*[A-Z]/i,  // XXX: followed by capital letter
    /<REPLACE/i,
    /<!-- more code -->/i,
    /\/\/ rest of the code/i,
    /\.\.\.\s*$/m,  // Three dots at end of line (likely placeholder)
    /\.\.\.\s*\[/m,  // Three dots followed by bracket (likely placeholder)
    /\[\.\.\.\]/i  // [...] placeholder pattern
  ];

  for (const file of content.files || []) {
    for (const pattern of placeholderPatterns) {
      if (pattern.test(file.content)) {
        issues.push(`Placeholder detected in ${file.name}: ${pattern}`);
      }
    }
  }

  return {
    valid: issues.length === 0,
    score: issues.length === 0 ? 1.0 : 0,
    issues
  };
}

/**
 * Score educational value
 */
function scoreEducationalValue(content) {
  let score = 0;

  // Check for learning objectives
  if (content.configuration?.learningObjectives && 
      Array.isArray(content.configuration.learningObjectives) &&
      content.configuration.learningObjectives.length > 0) {
    score += 0.3;
  }

  // Check for hints
  if (content.configuration?.hints && 
      Array.isArray(content.configuration.hints) &&
      content.configuration.hints.length >= 2) {
    score += 0.2;
  }

  // Check for exploit path description
  if (content.configuration?.exploitPath && 
      content.configuration.exploitPath.length > 20) {
    score += 0.2;
  }

  // Check for tools list
  if (content.configuration?.tools && 
      Array.isArray(content.configuration.tools) &&
      content.configuration.tools.length > 0) {
    score += 0.1;
  }

  // Check for realistic scenario
  if (content.configuration?.vulnerability || 
      content.configuration?.serviceType ||
      content.configuration?.cryptoType) {
    score += 0.2;
  }

  return {
    score: Math.min(1.0, score),
    valid: score >= 0.5
  };
}

/**
 * Validate hint quality
 */
function validateHints(content) {
  const hints = content.configuration?.hints || [];
  let score = 0.5; // Base score

  if (hints.length === 0) {
    return { score: 0, valid: false };
  }

  if (hints.length >= 2) {
    score += 0.2;
  }

  if (hints.length >= 3) {
    score += 0.1;
  }

  // Check hint quality (not too revealing, not too vague)
  for (const hint of hints) {
    if (hint.length < 10) {
      score -= 0.1; // Too short
    }
    if (hint.length > 200) {
      score -= 0.1; // Too long
    }
    if (hint.toLowerCase().includes('flag')) {
      score -= 0.1; // Too revealing
    }
  }

  return {
    score: Math.max(0, Math.min(1.0, score)),
    valid: score >= 0.4
  };
}

/**
 * Validate category-specific requirements
 */
function validateCategorySpecific(content, category) {
  const warnings = [];
  let score = 1.0;

  switch (category) {
    case 'web':
      if (!content.configuration?.vulnerability) {
        warnings.push('Web content should specify vulnerability type');
        score -= 0.2;
      }
      if (!content.configuration?.exploitPath) {
        warnings.push('Web content should include exploit path');
        score -= 0.2;
      }
      // Check for web-specific files
      const hasWebFile = content.files?.some(f => 
        f.name.endsWith('.php') || 
        f.name.endsWith('.html') || 
        f.name.endsWith('.js') ||
        f.name.endsWith('.py')
      );
      if (!hasWebFile) {
        warnings.push('Web content should include web application files');
        score -= 0.3;
      }
      break;

    case 'network':
      if (!content.configuration?.serviceType) {
        warnings.push('Network content should specify service type');
        score -= 0.2;
      }
      if (!content.configuration?.servicePort) {
        warnings.push('Network content should specify service port');
        score -= 0.1;
      }
      if (!content.configuration?.misconfiguration) {
        warnings.push('Network content should describe misconfiguration');
        score -= 0.2;
      }
      break;

    case 'crypto':
      if (!content.configuration?.cryptoType) {
        warnings.push('Crypto content should specify crypto type');
        score -= 0.2;
      }
      if (!content.configuration?.solvingMethod) {
        warnings.push('Crypto content should include solving method');
        score -= 0.2;
      }
      // Check for ciphertext files
      const hasCiphertext = content.files?.some(f => 
        f.name.includes('cipher') || 
        f.name.includes('encrypted') ||
        f.name.includes('flag')
      );
      if (!hasCiphertext) {
        warnings.push('Crypto content should include ciphertext files');
        score -= 0.3;
      }
      break;
  }

  return {
    valid: score >= 0.6,
    score: Math.max(0, score),
    warnings
  };
}

