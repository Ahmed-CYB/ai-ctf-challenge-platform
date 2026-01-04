/**
 * Challenge Quality Scorer
 * IMPROVEMENT: Evaluates challenge quality and provides scoring metrics
 */

/**
 * Score challenge quality based on various factors
 * @param {object} challenge - Challenge object with metadata and files
 * @returns {object} Quality score and breakdown
 */
export function scoreChallengeQuality(challenge) {
  let score = 0;
  const maxScore = 100;
  const breakdown = {
    metadata: 0,
    dockerfile: 0,
    content: 0,
    educational: 0,
    security: 0
  };
  
  // 1. Metadata Quality (20 points)
  if (challenge.metadata) {
    if (challenge.metadata.description && challenge.metadata.description.length > 50) {
      breakdown.metadata += 5;
      score += 5;
    }
    if (challenge.metadata.description && challenge.metadata.description.length > 100) {
      breakdown.metadata += 5;
      score += 5;
    }
    if (challenge.metadata.hints && Array.isArray(challenge.metadata.hints) && challenge.metadata.hints.length >= 3) {
      breakdown.metadata += 5;
      score += 5;
    }
    if (challenge.metadata.learningObjectives && Array.isArray(challenge.metadata.learningObjectives) && challenge.metadata.learningObjectives.length > 0) {
      breakdown.metadata += 5;
      score += 5;
    }
  }
  
  // 2. Dockerfile Quality (20 points)
  if (challenge.dockerFiles) {
    const dockerfile = challenge.dockerFiles.victim || challenge.dockerFiles.attacker || '';
    
    if (dockerfile.includes('EXPOSE')) {
      breakdown.dockerfile += 5;
      score += 5;
    }
    if (dockerfile.includes('HEALTHCHECK')) {
      breakdown.dockerfile += 5;
      score += 5;
    }
    if (dockerfile.includes('USER') && !dockerfile.includes('root')) {
      breakdown.dockerfile += 5;
      score += 5; // Non-root user
    }
    if (dockerfile.includes('apt-get clean') || dockerfile.includes('rm -rf /var/lib/apt/lists')) {
      breakdown.dockerfile += 5;
      score += 5; // Cleanup apt cache
    }
  }
  
  // 3. Content Quality (20 points)
  if (challenge.additionalFiles && challenge.additionalFiles.length > 0) {
    breakdown.content += 10;
    score += 10;
  }
  if (challenge.flag && challenge.flag.startsWith('CTF{') && challenge.flag.length > 10) {
    breakdown.content += 5;
    score += 5;
  }
  if (challenge.metadata && challenge.metadata.difficulty) {
    breakdown.content += 5;
    score += 5;
  }
  
  // 4. Educational Value (20 points)
  if (challenge.metadata) {
    if (challenge.metadata.description && challenge.metadata.description.toLowerCase().includes('learn')) {
      breakdown.educational += 5;
      score += 5;
    }
    if (challenge.metadata.description && challenge.metadata.description.toLowerCase().includes('practice')) {
      breakdown.educational += 5;
      score += 5;
    }
    if (challenge.metadata.learningObjectives && challenge.metadata.learningObjectives.length >= 2) {
      breakdown.educational += 10;
      score += 10;
    }
  }
  
  // 5. Security Best Practices (20 points)
  if (challenge.dockerFiles) {
    const dockerfile = challenge.dockerFiles.victim || '';
    
    if (!dockerfile.includes('password') || dockerfile.match(/password.*=.*['"]\w{8,}['"]/)) {
      breakdown.security += 5;
      score += 5; // Strong password or no hardcoded password
    }
    if (dockerfile.includes('ENV') && dockerfile.includes('DEBIAN_FRONTEND=noninteractive')) {
      breakdown.security += 5;
      score += 5; // Non-interactive mode
    }
    if (!dockerfile.includes('chmod 777') || dockerfile.match(/chmod 777.*2>/)) {
      breakdown.security += 5;
      score += 5; // No overly permissive chmod or error handling
    }
    if (dockerfile.includes('RUN') && dockerfile.match(/RUN.*&&.*apt-get clean/)) {
      breakdown.security += 5;
      score += 5; // Cleanup in same layer
    }
  }
  
  const percentage = (score / maxScore) * 100;
  const grade = percentage >= 80 ? 'A' : percentage >= 60 ? 'B' : percentage >= 40 ? 'C' : 'D';
  
  return {
    score,
    maxScore,
    percentage: percentage.toFixed(1),
    grade,
    breakdown,
    recommendations: generateRecommendations(score, breakdown, challenge)
  };
}

/**
 * Generate recommendations based on score
 */
function generateRecommendations(score, breakdown, challenge) {
  const recommendations = [];
  
  if (breakdown.metadata < 15) {
    recommendations.push('Add more detailed description (100+ characters)');
    recommendations.push('Include at least 3 progressive hints');
    recommendations.push('Add learning objectives');
  }
  
  if (breakdown.dockerfile < 15) {
    recommendations.push('Add HEALTHCHECK to Dockerfile');
    recommendations.push('Use non-root user in Dockerfile');
    recommendations.push('Clean up apt cache in Dockerfile');
  }
  
  if (breakdown.educational < 15) {
    recommendations.push('Emphasize educational value in description');
    recommendations.push('Add learning objectives');
  }
  
  if (breakdown.security < 15) {
    recommendations.push('Review security best practices in Dockerfile');
    recommendations.push('Avoid hardcoded weak passwords');
    recommendations.push('Use proper file permissions');
  }
  
  if (score < 60) {
    recommendations.push('Overall: Challenge needs significant improvements before deployment');
  }
  
  return recommendations;
}

/**
 * Validate challenge difficulty matches description
 * @param {object} challenge - Challenge object
 * @returns {object} Validation result
 */
export function validateDifficulty(challenge) {
  if (!challenge.metadata || !challenge.metadata.difficulty) {
    return {
      valid: false,
      issue: 'Difficulty not specified'
    };
  }
  
  const difficulty = challenge.metadata.difficulty.toLowerCase();
  const description = challenge.metadata.description || '';
  const descriptionLower = description.toLowerCase();
  
  // Analyze complexity indicators
  let complexity = 0;
  
  // Easy indicators
  if (descriptionLower.includes('simple') || descriptionLower.includes('basic') || descriptionLower.includes('beginner')) {
    complexity = 1;
  }
  
  // Medium indicators
  if (descriptionLower.includes('intermediate') || descriptionLower.includes('moderate') || descriptionLower.includes('some')) {
    complexity = 2;
  }
  
  // Hard indicators
  if (descriptionLower.includes('advanced') || descriptionLower.includes('complex') || descriptionLower.includes('multiple') || descriptionLower.includes('chained')) {
    complexity = 3;
  }
  
  // Check if difficulty matches complexity
  const difficultyMap = { easy: 1, medium: 2, hard: 3 };
  const expectedComplexity = difficultyMap[difficulty] || 2;
  
  if (complexity > 0 && Math.abs(complexity - expectedComplexity) > 1) {
    return {
      valid: false,
      issue: `Difficulty marked as "${difficulty}" but description suggests ${complexity === 1 ? 'easy' : complexity === 2 ? 'medium' : 'hard'} complexity`,
      suggestedDifficulty: complexity === 1 ? 'easy' : complexity === 2 ? 'medium' : 'hard'
    };
  }
  
  // Check hints count matches difficulty
  const hints = challenge.metadata.hints || [];
  if (difficulty === 'easy' && hints.length < 2) {
    return {
      valid: true,
      warning: 'Easy challenges typically have 2-3 hints'
    };
  }
  if (difficulty === 'hard' && hints.length > 3) {
    return {
      valid: true,
      warning: 'Hard challenges typically have fewer hints (1-2)'
    };
  }
  
  return {
    valid: true
  };
}

