import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';
import { normalizeContent, validateContentSchema } from '../../content-schema.js';
import { generateVariationParams, injectVariationsIntoPrompt, generateUniqueFlag } from '../../content-variation-manager.js';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const CRYPTO_CONTENT_PROMPT = `You are an expert cryptography CTF challenge creator. Generate realistic cryptographic puzzles and challenges.

CRITICAL REQUIREMENTS - NO PLACEHOLDERS:
❌ NEVER use: TODO, FIXME, XXX, [PLACEHOLDER], <REPLACE>, ..., [INSERT], [ADD HERE], [FILL IN]
✅ ALWAYS generate ACTUAL ciphertext with real encrypted data
✅ Use actual encryption keys, ciphertext, and encoded values
✅ Generate complete file contents - never leave sections empty or marked for later
✅ All cryptographic data must be real and solvable

SECURITY REQUIREMENTS - NO REAL SECRETS:
❌ NEVER generate realistic API keys, tokens, or secrets (e.g., sk_live_*, AKIA*, JWT tokens)
❌ NEVER use patterns that match real secret formats (Stripe keys, AWS keys, etc.)
✅ Use simple, fake values like "test_key_12345", "dummy_token", "example_api_key"
✅ For passwords, use simple CTF-style passwords like "admin123", "password", "user"
✅ For keys/tokens, use short, clearly fake values that won't trigger secret scanners

SUPPORTED CHALLENGE TYPES:
1. Classical Ciphers: Caesar, Vigenère, Substitution, Transposition
2. Modern Encryption: RSA, AES, DES with weak keys
3. Hash Cracking: MD5, SHA, bcrypt with weak passwords
4. Encoding Chains: Base64 → Hex → ROT13 combinations
5. Custom Ciphers: XOR, one-time pad misuse

OUTPUT REQUIREMENTS:
- Generate ACTUAL ciphertext with real encrypted/encoded data (not placeholders)
- Provide complete solving method/tools with actual commands
- Include helpful hints without revealing the solution
- Flag embedded in plaintext with actual flag value

⚠️ CRITICAL - SETUP COMMANDS ARE MANDATORY:
- The "setup" field in configuration is MANDATORY and MUST be provided
- Setup commands are executed at container startup (even if no services need starting)
- Without setup commands, the challenge will fail validation
- For crypto challenges, setup may be minimal but must still be present:
  - If challenge needs a web interface: "service apache2 start" or "python app.py &" or "node server.js &"
  - If challenge is file-based only: "echo 'Crypto challenge files ready'"
- Example setup for web-based crypto challenge:
  "setup": "service apache2 start || /usr/sbin/apache2ctl -D FOREGROUND &"
- Example setup for file-based crypto challenge:
  "setup": "echo 'Crypto challenge files are ready in /challenge directory'"
- Setup commands must be executable shell commands (even if just echo statements)

Return JSON:
{
  "files": [
    {
      "name": "ciphertext.txt",
      "path": "",
      "content": "<actual encrypted data>"
    },
    {
      "name": "hint.txt",
      "path": "",
      "content": "<helpful hints>"
    }
  ],
  "flag": "CTF{actual_flag_here}",
  "configuration": {
    "cryptoType": "caesar|vigenere|rsa|...",
    "difficulty": "easy|medium|hard",
    "solvingMethod": "description of how to solve",
    "tools": ["hashcat", "john", "openssl"],
    "setup": "echo 'setup commands if needed'"
  }
}`;

/**
 * Generate cryptography challenge content
 */
export async function generateCryptoContent({ machineName, services, scenario, dependencies }) {
  // IMPROVEMENT: Check cache first
  try {
    const { getCachedContent } = await import('../../content-cache.js');
    const cached = await getCachedContent('crypto', scenario);
    if (cached) {
      console.log('✅ Using cached crypto content');
      return cached;
    }
  } catch (cacheError) {
    console.warn('⚠️  Cache check failed:', cacheError.message);
  }

  // IMPROVEMENT: Retry logic - try AI generation up to 3 times before using fallback
  const maxRetries = 3;
  let lastError = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`🤖 AI generation attempt ${attempt}/${maxRetries} for crypto content...`);
      // IMPROVEMENT: Enhanced scenario context utilization
      const scenarioContext = {
      title: scenario.title || 'Crypto Challenge',
      description: scenario.description || '',
      difficulty: scenario.difficulty || 'medium',
      learningObjectives: scenario.learningObjectives || [],
      complexity: scenario.complexity || 'intermediate',
      tags: scenario.tags || []
    };

    // IMPROVEMENT: Generate variation parameters for uniqueness
    const variations = generateVariationParams('crypto', scenario);
    
    const basePrompt = `Create a cryptography challenge for this scenario:

Scenario: ${scenarioContext.title}
Machine: ${machineName}
Context: ${scenarioContext.description}
Difficulty: ${scenarioContext.difficulty}
Complexity: ${scenarioContext.complexity}
Learning Objectives: ${scenarioContext.learningObjectives.join(', ') || 'Cryptography fundamentals'}
Tags: ${scenarioContext.tags.join(', ') || 'crypto, encryption'}
Dependencies: ${dependencies.join('; ')}

Generate complete, realistic cryptographic challenge content with actual ciphertext that:
- Matches the difficulty level (${scenarioContext.difficulty})
- Teaches the specified learning objectives
- Is solvable with appropriate tools
- Includes helpful hints without revealing the solution
- Is UNIQUE and different from previous challenges`;

    // IMPROVEMENT: Inject variations into prompt
    const prompt = injectVariationsIntoPrompt(basePrompt, variations);

    // IMPROVEMENT: Variable temperature for uniqueness (0.8-1.0 for crypto - more creative)
    const temperature = 0.8 + (Math.random() * 0.2);
    
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 12000, // IMPROVEMENT: Increased to handle larger responses
      temperature: temperature, // IMPROVEMENT: Variable for uniqueness
      system: CRYPTO_CONTENT_PROMPT + `\n\nCRITICAL: Generate UNIQUE content that differs from previous challenges. Use creative variations in cipher types, encoding methods, and puzzle structure. IMPORTANT: Always provide COMPLETE, valid JSON. Do not truncate or use placeholders.${attempt > 1 ? '\n\n⚠️ PREVIOUS ATTEMPT FAILED: The previous generation contained placeholders or incomplete content. You MUST generate ACTUAL ciphertext and complete cryptographic data with ALL values filled in. NO TODO, FIXME, XXX, [PLACEHOLDER], or any incomplete sections allowed.' : ''}`,
      messages: [{
        role: 'user',
        content: prompt
      }]
    });

    let responseText = response.content[0].text;
    
    // IMPROVEMENT: Check if response was truncated and request continuation if needed
    if (response.stop_reason === 'max_tokens') {
      console.warn('⚠️  Response was truncated, requesting continuation...');
      const continuation = await anthropic.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 6000,
        temperature: temperature,
        messages: [{
          role: 'user',
          content: `Continue the JSON response from where it was cut off. Complete the JSON object properly:\n\n${responseText.substring(responseText.lastIndexOf('{'))}`
        }]
      });
      responseText += continuation.content[0].text;
    }
    
    // Try multiple JSON extraction strategies
    let content;
    try {
      // Strategy 1: Find JSON between code blocks (greedy to get full content)
      const codeBlockMatch = responseText.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (codeBlockMatch) {
        content = JSON.parse(codeBlockMatch[1].trim());
      } else {
        // Strategy 2: Find first complete JSON object from start to balanced closing brace
        const jsonStart = responseText.indexOf('{');
        if (jsonStart === -1) {
          throw new Error('No JSON object found in response');
        }
        
        // Find matching closing brace by counting braces (handle strings properly)
        let braceCount = 0;
        let jsonEnd = -1;
        let inString = false;
        let escapeNext = false;
        
        for (let i = jsonStart; i < responseText.length; i++) {
          const char = responseText[i];
          
          if (escapeNext) {
            escapeNext = false;
            continue;
          }
          
          if (char === '\\') {
            escapeNext = true;
            continue;
          }
          
          if (char === '"' && !escapeNext) {
            inString = !inString;
            continue;
          }
          
          if (!inString) {
            if (char === '{') braceCount++;
            if (char === '}') {
              braceCount--;
              if (braceCount === 0) {
                jsonEnd = i + 1;
                break;
              }
            }
          }
        }
        
        if (jsonEnd === -1) {
          // Try to find the last closing brace as fallback
          const lastBrace = responseText.lastIndexOf('}');
          if (lastBrace > jsonStart) {
            console.warn('⚠️  Using last closing brace as fallback');
            jsonEnd = lastBrace + 1;
          } else {
            throw new Error('Incomplete JSON object in response');
          }
        }
        
        const jsonString = responseText.substring(jsonStart, jsonEnd);
        content = JSON.parse(jsonString);
      }
    } catch (parseError) {
      console.error('❌ JSON parsing failed:', parseError.message);
      console.error('Response preview:', responseText.substring(0, 2000));
      throw new Error(`Invalid JSON from crypto agent: ${parseError.message}`);
    }

    // IMPROVEMENT: Normalize and validate schema
    content = normalizeContent(content);
    const schemaValidation = validateContentSchema(content);
    if (!schemaValidation.valid) {
      console.warn('⚠️  Schema validation issues:', schemaValidation.issues);
      
      // ✅ CRITICAL: Setup commands are MANDATORY - throw error to trigger retry
      if (schemaValidation.issues.some(issue => issue.includes('setup'))) {
        throw new Error(`MANDATORY setup commands missing in configuration. The setup field must contain service startup commands that will be executed at container startup. Example: "setup": "service apache2 start || /usr/sbin/apache2ctl -D FOREGROUND &" or "setup": "echo 'Crypto challenge files ready'"`);
      }
      
      // Fix common issues (non-critical)
      if (!content.configuration.difficulty) {
        content.configuration.difficulty = 'medium';
      }
      if (!content.configuration.tools) {
        content.configuration.tools = [];
      }
    }

    // Validate content
    if (!content.files || content.files.length === 0) {
      throw new Error('Crypto content must include files');
    }

    // IMPROVEMENT: Generate unique flag with variations
    if (!content.flag || !/^CTF\{[a-zA-Z0-9_\-]{10,}\}$/.test(content.flag)) {
      content.flag = generateUniqueFlag('crypto', scenario, variations);
    }

    // IMPROVEMENT: Validate content quality
    try {
      const { validateContentQuality } = await import('../../content-quality-validator.js');
      const qualityCheck = await validateContentQuality(content, 'crypto');
      
      if (!qualityCheck.valid) {
        console.warn('⚠️  Content quality issues:', qualityCheck.issues);
        throw new Error(`Content quality validation failed: ${qualityCheck.issues.join(', ')}`);
      }
      
      if (qualityCheck.warnings.length > 0) {
        console.warn('⚠️  Content quality warnings:', qualityCheck.warnings);
      }
      
      console.log(`✅ Generated crypto content: ${content.files.length} files (quality: ${(qualityCheck.overallScore * 100).toFixed(1)}%)`);
      
      // IMPROVEMENT: Cache high-quality content
      if (qualityCheck.overallScore >= 0.7) {
        try {
          const { saveToCache } = await import('../../content-cache.js');
          await saveToCache('crypto', scenario, content, qualityCheck.overallScore);
        } catch (cacheError) {
          console.warn('⚠️  Failed to cache content:', cacheError.message);
        }
      }
    } catch (qualityError) {
      console.warn('⚠️  Quality validation failed:', qualityError.message);
      // Continue anyway if validation fails
    }

    // IMPROVEMENT: Validate no obvious placeholders (smarter check - only in file content, not filenames)
    for (const file of content.files) {
      const fileContent = file.content || '';
      
      // IMPROVEMENT: More precise placeholder patterns - only flag actual placeholders, not legitimate content
      const placeholderPatterns = [
        // Explicit placeholder markers (high confidence)
        /\[PLACEHOLDER[^\]]*\]/i,  // [PLACEHOLDER] or [PLACEHOLDER: ...]
        /<REPLACE[^>]*>/i,          // <REPLACE> or <REPLACE: ...>
        /\[INSERT[^\]]*HERE[^\]]*\]/i,  // [INSERT HERE] or [INSERT ... HERE]
        /\[ADD[^\]]*HERE[^\]]*\]/i,     // [ADD HERE] or [ADD ... HERE]
        /\[FILL[^\]]*IN[^\]]*\]/i,      // [FILL IN] or [FILL ... IN]
        /\[\.\.\.\]/i,                   // [...]
        
        // TODO/FIXME/XXX only if they appear to be actual placeholders (not in comments or legitimate text)
        // Check for TODO: at start of line or after whitespace, followed by action words
        /(?:^|\s)(?:TODO|FIXME|XXX):\s*(?:ADD|INSERT|REPLACE|FILL|IMPLEMENT|COMPLETE)/i,
        
        // Three dots patterns - only flag if they appear to be placeholders (not in log files or legitimate ellipsis)
        // Only flag if ... appears alone on a line or followed by placeholder-like text
        /^\s*\.\.\.\s*$/m,  // ... alone on a line
        /\.\.\.\s*\[(?:PLACEHOLDER|INSERT|ADD|FILL)/i  // ... followed by placeholder marker
      ];
      
      // IMPROVEMENT: Skip placeholder check for log files and certain file types that may legitimately contain these patterns
      const skipPlaceholderCheck = /\.(log|txt|conf|config|ini|json|xml)$/i.test(file.name) && 
                                   (fileContent.length > 1000 || fileContent.split('\n').length > 20);
      
      if (!skipPlaceholderCheck) {
        for (const pattern of placeholderPatterns) {
          if (pattern.test(fileContent)) {
            console.warn(`⚠️  Placeholder detected in ${file.name}: ${pattern}`);
            throw new Error(`Placeholder detected in ${file.name}`);
          }
        }
      } else {
        // For log/config files, only check for explicit placeholder markers, not TODO or ...
        const strictPlaceholderPatterns = [
          /\[PLACEHOLDER[^\]]*\]/i,
          /<REPLACE[^>]*>/i,
          /\[INSERT[^\]]*HERE[^\]]*\]/i,
          /\[ADD[^\]]*HERE[^\]]*\]/i,
          /\[FILL[^\]]*IN[^\]]*\]/i
        ];
        
        for (const pattern of strictPlaceholderPatterns) {
          if (pattern.test(fileContent)) {
            console.warn(`⚠️  Placeholder detected in ${file.name}: ${pattern}`);
            throw new Error(`Placeholder detected in ${file.name}`);
          }
        }
      }
    }

      console.log(`✅ Successfully generated crypto content on attempt ${attempt}`);
      return content;

    } catch (error) {
      console.error(`❌ Crypto content generation attempt ${attempt} failed:`, error.message);
      lastError = error;
      
      // If this is not the last attempt, continue to retry
      if (attempt < maxRetries) {
        console.log(`🔄 Retrying AI generation... (${attempt + 1}/${maxRetries})`);
        // Small delay before retry to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }
    }
  }

  // All retries failed - only use fallback as absolute last resort
  console.error('❌ All AI generation attempts failed. Using fallback as last resort.');
  console.error('Last error:', lastError?.message);
  
  const { getFallbackContent } = await import('../../content-fallback-manager.js');
  const difficulty = scenario.difficulty || 'easy';
  console.log(`⚠️  Using fallback content for crypto (${difficulty}) - this should be rare`);
  return getFallbackContent('crypto', difficulty, scenario);
}

/**
 * Fallback crypto content if AI generation fails
 */
function generateFallbackCryptoContent() {
  const flag = `CTF{crypto_${generateRandomString(12)}}`;
  const ciphertext = caesarEncode(flag, 13); // ROT13

  return {
    files: [
      {
        name: 'ciphertext.txt',
        path: '',
        content: ciphertext
      },
      {
        name: 'hint.txt',
        path: '',
        content: 'This looks like a rotation cipher. Try ROT13.'
      }
    ],
    flag: flag,
    configuration: {
      cryptoType: 'caesar',
      difficulty: 'easy',
      solvingMethod: 'Use ROT13 or try all 26 rotations',
      tools: ['tr', 'python', 'cyberchef'],
      setup: ''
    }
  };
}

/**
 * Caesar cipher encoding
 */
function caesarEncode(text, shift) {
  return text.split('').map(char => {
    if (char.match(/[a-z]/i)) {
      const code = char.charCodeAt(0);
      const base = code >= 65 && code <= 90 ? 65 : 97;
      return String.fromCharCode(((code - base + shift) % 26) + base);
    }
    return char;
  }).join('');
}

/**
 * Generate random string
 */
function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789_';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
