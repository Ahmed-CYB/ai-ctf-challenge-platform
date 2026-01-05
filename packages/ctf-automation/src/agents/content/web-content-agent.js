import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';
import { normalizeContent, validateContentSchema } from '../../content-schema.js';
import { generateVariationParams, injectVariationsIntoPrompt, generateUniqueFlag } from '../../content-variation-manager.js';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const WEB_CONTENT_PROMPT = `You are an expert web security CTF challenge creator. Generate vulnerable web applications with realistic code.

🔧 PRIMARY REFERENCE FOR DOCKER CONFIGURATIONS - VULHUB:
- **ALWAYS reference Vulhub** (https://github.com/vulhub/vulhub) for correct web application Docker configurations
- Vulhub provides 200+ WORKING Dockerfiles and docker-compose.yml for web vulnerabilities
- **Search Vulhub repository** for relevant examples matching your challenge type (Apache, Nginx, PHP, Node.js, etc.)
- Use Vulhub examples to ensure:
  * Correct web server configurations (Apache, Nginx)
  * Proper database connection setups (MySQL, PostgreSQL)
  * Working docker-compose.yml with multiple services
  * Correct file permissions and directory structures

CRITICAL REQUIREMENTS - NO PLACEHOLDERS:
❌ NEVER use: TODO, FIXME, XXX, [PLACEHOLDER], <REPLACE>, ..., [INSERT], [ADD HERE], [FILL IN]
✅ ALWAYS generate COMPLETE, WORKING code with real values
✅ Use actual database queries, file paths, usernames, passwords, and configuration values
✅ Generate complete file contents - never leave sections empty or marked for later
✅ All code must be syntactically correct and executable

SECURITY REQUIREMENTS - NO REAL SECRETS:
❌ NEVER generate realistic API keys, tokens, or secrets (e.g., sk_live_*, AKIA*, JWT tokens)
❌ NEVER use patterns that match real secret formats (Stripe keys, AWS keys, etc.)
✅ Use simple, fake values like "test_key_12345", "dummy_token", "example_api_key"
✅ For passwords, use simple CTF-style passwords like "admin123", "password", "user"
✅ For keys/tokens, use short, clearly fake values that won't trigger secret scanners

SUPPORTED VULNERABILITIES:
1. SQL Injection: Login bypass, data exfiltration, blind SQLi
2. Cross-Site Scripting (XSS): Stored, Reflected, DOM-based
3. CSRF: State-changing operations
4. File Upload: Unrestricted upload, path traversal
5. Authentication: Weak credentials, session fixation, JWT flaws
6. SSRF: Internal network access
7. XXE: XML external entity injection
8. Command Injection: OS command execution

OUTPUT REQUIREMENTS:
- Generate COMPLETE, WORKING web application code with ALL values filled in
- Include vulnerability with realistic exploit path using actual commands
- Provide complete database setup with real schema and data
- Flag hidden in appropriate location with actual flag value

⚠️ CRITICAL - SETUP COMMANDS ARE MANDATORY:
- The "setup" field in configuration is MANDATORY and MUST be provided
- Setup commands are executed at container startup to start services
- Without setup commands, services will NOT start and the challenge will fail
- Setup must include:
  1. Database initialization (if needed): "mysql < /challenge/database.sql" or "psql < /challenge/database.sql"
  2. Web server startup: "service apache2 start" or "service nginx start" or "python app.py &" or "node server.js &"
  3. Any initialization scripts or commands needed
- Example setup for PHP web app with MySQL:
  "setup": "service mysql start && mysql < /challenge/database.sql && service apache2 start || /usr/sbin/apache2ctl -D FOREGROUND &"
- Example setup for Node.js web app:
  "setup": "cd /challenge && npm install && node server.js &"
- Example setup for Python Flask app:
  "setup": "cd /challenge && pip install -r requirements.txt && python app.py &"
- Setup commands must be executable shell commands that start the web service
- Use "service <name> start" for systemd-based systems, or direct execution with "&" for background processes

Return JSON:
{
  "files": [
    {
      "name": "index.php",
      "path": "",
      "content": "<complete PHP code>"
    },
    {
      "name": "database.sql",
      "path": "",
      "content": "<database schema and data>"
    }
  ],
  "flag": "CTF{actual_flag}",
  "configuration": {
    "vulnerability": "sqli|xss|csrf|...",
    "difficulty": "easy|medium|hard",
    "exploitPath": "description of how to exploit",
    "flagLocation": "where flag is hidden",
    "tools": ["sqlmap", "burpsuite", "nikto"],
    "setup": "database setup commands"
  }
}`;

/**
 * Generate web application challenge content
 */
export async function generateWebContent({ machineName, services, scenario, dependencies }) {
  // IMPROVEMENT: Check cache first
  try {
    const { getCachedContent } = await import('../../content-cache.js');
    const cached = await getCachedContent('web', scenario);
    if (cached) {
      console.log('✅ Using cached web content');
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
      console.log(`🤖 AI generation attempt ${attempt}/${maxRetries} for web content...`);
      // IMPROVEMENT: Enhanced scenario context utilization
      const scenarioContext = {
      title: scenario.title || 'Web Challenge',
      description: scenario.description || '',
      difficulty: scenario.difficulty || 'medium',
      learningObjectives: scenario.learningObjectives || [],
      complexity: scenario.complexity || 'intermediate',
      tags: scenario.tags || []
    };

    // IMPROVEMENT: Generate variation parameters for uniqueness
    const variations = generateVariationParams('web', scenario);
    
    const basePrompt = `Create a vulnerable web application for this scenario:

Scenario: ${scenarioContext.title}
Machine: ${machineName}
Services: ${services.join(', ')}
Context: ${scenarioContext.description}
Difficulty: ${scenarioContext.difficulty}
Complexity: ${scenarioContext.complexity}
Learning Objectives: ${scenarioContext.learningObjectives.join(', ') || 'Web security fundamentals'}
Tags: ${scenarioContext.tags.join(', ') || 'web, security'}
Dependencies: ${dependencies.join('; ')}

Generate a complete, working vulnerable web application with embedded flag that:
- Matches the difficulty level (${scenarioContext.difficulty})
- Teaches the specified learning objectives
- Is realistic and exploitable
- Includes appropriate hints without revealing the solution
- Is UNIQUE and different from previous challenges`;

    // IMPROVEMENT: Inject variations into prompt
    const prompt = injectVariationsIntoPrompt(basePrompt, variations);

    // IMPROVEMENT: Variable temperature for uniqueness (0.7-0.9)
    const temperature = 0.7 + (Math.random() * 0.2);
    
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 16000,
      temperature: temperature, // IMPROVEMENT: Variable for uniqueness
      system: WEB_CONTENT_PROMPT + `\n\nCRITICAL: Generate UNIQUE content that differs from previous challenges. Use creative variations in code structure, vulnerability implementation, and scenario details. IMPORTANT: Always provide COMPLETE, valid JSON. Do not truncate or use placeholders.${attempt > 1 ? '\n\n⚠️ PREVIOUS ATTEMPT FAILED: The previous generation contained placeholders or incomplete content. You MUST generate COMPLETE, working code with ALL values filled in. NO TODO, FIXME, XXX, [PLACEHOLDER], or any incomplete sections allowed.' : ''}`,
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
        max_tokens: 8000,
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
      throw new Error(`Invalid JSON from web agent: ${parseError.message}`);
    }

    // IMPROVEMENT: Normalize and validate schema
    content = normalizeContent(content);
    const schemaValidation = validateContentSchema(content);
    if (!schemaValidation.valid) {
      console.warn('⚠️  Schema validation issues:', schemaValidation.issues);
      
      // ✅ CRITICAL: Setup commands are MANDATORY - throw error to trigger retry
      if (schemaValidation.issues.some(issue => issue.includes('setup'))) {
        throw new Error(`MANDATORY setup commands missing in configuration. The setup field must contain service startup commands that will be executed at container startup. Example: "setup": "service mysql start && mysql < /challenge/database.sql && service apache2 start || /usr/sbin/apache2ctl -D FOREGROUND &"`);
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
      throw new Error('Web content must include files');
    }

    // IMPROVEMENT: Generate unique flag with variations
    if (!content.flag || !/^CTF\{[a-zA-Z0-9_\-]{10,}\}$/.test(content.flag)) {
      content.flag = generateUniqueFlag('web', scenario, variations);
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

      console.log(`✅ Generated web content: ${content.files.length} files`);
      console.log(`✅ Successfully generated web content on attempt ${attempt}`);
      return content;

    } catch (error) {
      console.error(`❌ Web content generation attempt ${attempt} failed:`, error.message);
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
  console.log(`⚠️  Using fallback content for web (${difficulty}) - this should be rare`);
  return getFallbackContent('web', difficulty, scenario);
}

/**
 * Fallback web content if AI generation fails
 * DEPRECATED: Use content-fallback-manager.js instead
 */
function generateFallbackWebContent() {
  const flag = `CTF{web_${generateRandomString(12)}}`;

  const indexPHP = `<?php
// Simple SQL Injection Challenge
$servername = "localhost";
$username = "root";
$password = "password";
$dbname = "ctf_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    
    // Vulnerable SQL query
    $sql = "SELECT * FROM users WHERE username = '$user' AND password = '$pass'";
    $result = $conn->query($sql);
    
    if ($result && $result->num_rows > 0) {
        $row = $result->fetch_assoc();
        echo "<h1>Welcome, " . $row['username'] . "!</h1>";
        echo "<p>Flag: " . $row['flag'] . "</p>";
    } else {
        echo "<h1>Login Failed</h1>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login Page</h2>
    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username"><br>
        <label>Password:</label><br>
        <input type="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>`;

  const databaseSQL = `CREATE DATABASE IF NOT EXISTS ctf_db;
USE ctf_db;

CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50),
    password VARCHAR(50),
    flag VARCHAR(100)
);

INSERT INTO users (username, password, flag) VALUES 
('admin', 'secure_password_123', '${flag}'),
('user', 'password', 'CTF{fake_flag}');`;

  return {
    files: [
      {
        name: 'index.php',
        path: '',
        content: indexPHP
      },
      {
        name: 'database.sql',
        path: '',
        content: databaseSQL
      }
    ],
    flag: flag,
    configuration: {
      vulnerability: 'sqli',
      difficulty: 'easy',
      exploitPath: "Login form is vulnerable to SQL injection. Try: username=admin' OR '1'='1 with any password",
      flagLocation: 'Database table: users, column: flag (admin row)',
      tools: ['sqlmap', 'burpsuite'],
      setup: `apt-get update && apt-get install -y mysql-server php-mysql
service mysql start
mysql < /challenge/database.sql
service apache2 start`
    }
  };
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
