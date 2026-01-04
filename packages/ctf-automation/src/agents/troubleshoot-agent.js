import Anthropic from '@anthropic-ai/sdk';
import { execSync } from 'child_process';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514';

const TROUBLESHOOT_SYSTEM_PROMPT = `You are an expert DevOps and Docker troubleshooting assistant specializing in CTF challenge deployment.

CRITICAL RESTRICTIONS:
❌ NEVER modify platform/website code (React, TypeScript, backend services)
❌ NEVER touch: src/, backend/, database/, public/, node_modules/
✅ ONLY modify challenge files: Dockerfile, docker-compose.yml, configs, scripts
✅ Files you CAN modify: vsftpd.conf, nginx.conf, apache2.conf, etc.

You are troubleshooting DEPLOYED CTF CHALLENGES, not the platform itself!

SPECIAL FOCUS ON FILE PATH ISSUES:
- Check if COPY/ADD commands in Dockerfile match actual file locations
- When you see "not found" errors, list all files in the directory structure provided
- Verify relative paths in COPY commands match the actual file tree
- Common fix: Change "COPY flag.txt" to "COPY path/to/flag.txt" based on actual location
- Always examine the "File Tree" section to understand actual file locations

Your responsibilities:
1. Analyze container failures and error logs
2. Diagnose configuration issues (Dockerfile, docker-compose, service configs)
3. Pay SPECIAL ATTENTION to file path mismatches in Dockerfiles
4. Suggest fixes ONLY for challenge files
5. Implement iterative problem-solving (try multiple solutions if needed)
6. Verify fixes work before marking as resolved

ALLOWED FILES TO MODIFY:
- Dockerfile, Dockerfile.*, *.Dockerfile
- docker-compose.yml, docker-compose.*.yml
- Service configs: vsftpd.conf, nginx.conf, apache2.conf, my.cnf, etc.
- Application files WITHIN challenge directory
- flag.txt, README.md (in challenge)
- Challenge-specific scripts and configs

FORBIDDEN FILES (NEVER TOUCH):
- Platform source code: src/, backend/, database/
- Node modules: node_modules/, package.json (platform level)
- Platform configs: vite.config.ts, tsconfig.json
- Database schema: database/schema.sql
- Authentication: src/services/auth.ts
- Any TypeScript/React files

Common Issues You Handle:
- Container crashes and exit codes
- Port conflicts and network issues
- Configuration file syntax errors
- Missing dependencies or packages
- Permission and file system issues
- Service startup failures (nginx, vsftpd, apache, etc.)
- Resource constraints (memory, CPU, disk)

Troubleshooting Process:
1. **Identify**: Check container status, read logs, examine exit codes
2. **Analyze**: Determine root cause from error messages
3. **Plan**: Create step-by-step fix strategy
4. **Execute**: Apply fixes ONLY to challenge files
5. **Verify**: Test that containers start and services work
6. **Iterate**: If fix fails, try alternative approaches

Output Format:
{
  "issue": "Brief description of the problem",
  "root_cause": "Technical explanation of why it's failing",
  "attempted_fixes": ["List of fixes tried"],
  "working_solution": {
    "files_to_modify": [
      {
        "path": "path/to/file",
        "changes": "Specific code changes to make",
        "file_type": "challenge_file|config|dockerfile"
      }
    ],
    "commands": ["Commands to rebuild/restart"],
    "verification": "How to verify it works"
  },
  "confidence": "high|medium|low"
}

VALIDATION: Before modifying ANY file, ensure it's within the challenge directory and NOT platform code!

Be concise, technical, and solution-oriented. Focus on practical fixes over theory.`;

/**
 * Troubleshoot a failing CTF challenge deployment
 */
export async function troubleshootChallenge(challengePath, options = {}) {
  const {
    maxAttempts = 3,
    autoFix = true
  } = options;

  console.log(`\n🔧 Starting troubleshooting for: ${challengePath}`);
  
  const diagnostics = await gatherDiagnostics(challengePath);
  
  if (diagnostics.allRunning) {
    console.log('✅ All containers are running. No issues detected.');
    return { success: true, message: 'Challenge is healthy' };
  }

  console.log(`\n⚠️ Issues detected. Attempting to fix (max ${maxAttempts} attempts)...`);
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    console.log(`\n--- Attempt ${attempt}/${maxAttempts} ---`);
    
    const solution = await getSolution(diagnostics, attempt);
    
    if (!solution) {
      console.log('❌ Could not generate solution');
      continue;
    }

    console.log(`\n🎯 Issue: ${solution.issue}`);
    console.log(`📋 Root Cause: ${solution.root_cause}`);
    
    if (autoFix && solution.working_solution) {
      const fixed = await applyFix(challengePath, solution.working_solution);
      
      if (fixed) {
        console.log('✅ Fix applied successfully!');
        
        // Re-check diagnostics
        const newDiagnostics = await gatherDiagnostics(challengePath);
        
        if (newDiagnostics.allRunning) {
          console.log('🎉 All containers now running!');
          return {
            success: true,
            attempts: attempt,
            solution: solution
          };
        } else {
          console.log('⚠️ Some containers still failing. Trying next approach...');
          diagnostics = newDiagnostics; // Update diagnostics for next attempt
        }
      }
    } else {
      console.log('\n📝 Suggested fix:');
      console.log(JSON.stringify(solution.working_solution, null, 2));
      return {
        success: false,
        solution: solution,
        message: 'Manual intervention required'
      };
    }
  }

  return {
    success: false,
    message: `Failed to fix after ${maxAttempts} attempts`
  };
}

/**
 * Gather diagnostic information about the challenge
 */
async function gatherDiagnostics(challengePath) {
  const diagnostics = {
    path: challengePath,
    containerStatus: [],
    logs: {},
    composeFile: null,
    dockerfiles: [],
    fileTree: '',
    allRunning: true
  };

  try {
    // Change to challenge directory
    process.chdir(challengePath);

    // Get complete file tree structure (CRITICAL for debugging path issues)
    try {
      const treeOutput = execSync('dir /s /b', { encoding: 'utf8', cwd: challengePath });
      diagnostics.fileTree = treeOutput;
      console.log('\n📁 File tree:\n', treeOutput);
    } catch (error) {
      diagnostics.fileTree = `Error getting file tree: ${error.message}`;
    }

    // Get docker-compose file
    if (fs.existsSync('docker-compose.yml')) {
      diagnostics.composeFile = fs.readFileSync('docker-compose.yml', 'utf8');
    }

    // Get container status - USE NEW "docker compose" (no hyphen)
    try {
      const psOutput = execSync('docker compose ps -a', { encoding: 'utf8' });
      diagnostics.containerStatus.push(psOutput);
      
      // Check if any containers are not running
      if (psOutput.includes('Exited') || psOutput.includes('Exit')) {
        diagnostics.allRunning = false;
      }
    } catch (error) {
      // If docker compose ps fails, containers probably don't exist yet
      diagnostics.containerStatus.push(`No containers running (${error.message})`);
      diagnostics.allRunning = false;
    }

    // Get logs from all services - USE NEW "docker compose" (no hyphen)
    try {
      const services = execSync('docker compose config --services', { encoding: 'utf8' })
        .split('\n')
        .filter(s => s.trim());
      
      for (const service of services) {
        try {
          const logs = execSync(`docker compose logs --tail=50 ${service}`, { 
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe']
          });
          diagnostics.logs[service] = logs;
        } catch (error) {
          diagnostics.logs[service] = `No logs yet (${error.message})`;
        }
      }
    } catch (error) {
      console.log('Could not get service list:', error.message);
    }

    // Find all Dockerfiles
    const findDockerfiles = (dir) => {
      const items = fs.readdirSync(dir);
      for (const item of items) {
        const fullPath = path.join(dir, item);
        if (fs.statSync(fullPath).isDirectory() && item !== 'node_modules') {
          findDockerfiles(fullPath);
        } else if (item.startsWith('Dockerfile')) {
          const relativePath = path.relative(challengePath, fullPath);
          diagnostics.dockerfiles.push({
            path: relativePath,
            content: fs.readFileSync(fullPath, 'utf8')
          });
        }
      }
    };
    findDockerfiles(challengePath);

  } catch (error) {
    console.error('Error gathering diagnostics:', error.message);
  }

  return diagnostics;
}

/**
 * Get solution from AI based on diagnostics
 */
async function getSolution(diagnostics, attemptNumber) {
  try {
    const userMessage = `
Challenge Path: ${diagnostics.path}

=== FILE TREE (CRITICAL - Use this to verify paths in COPY commands) ===
${diagnostics.fileTree}

Container Status:
${diagnostics.containerStatus.join('\n')}

Logs:
${Object.entries(diagnostics.logs).map(([service, log]) => 
  `=== ${service} ===\n${log}`
).join('\n\n')}

Docker Compose:
${diagnostics.composeFile || 'Not found'}

Dockerfiles:
${diagnostics.dockerfiles.map(d => 
  `=== ${d.path} ===\n${d.content}`
).join('\n\n')}

This is attempt ${attemptNumber}. ${attemptNumber > 1 ? 'Previous attempts did not fully resolve the issue.' : ''}

IMPORTANT: Look at the FILE TREE above. If you see "COPY flag.txt" but the file tree shows "ftp-data\\hidden\\flag.txt", 
you MUST fix the path to match: "COPY ftp-data/hidden/flag.txt" or restructure the files.

Please analyze and provide a solution focusing on path mismatches.`;

    const completion = await anthropic.messages.create({
      model: ANTHROPIC_MODEL,
      max_tokens: 8192,
      temperature: 0.3,
      system: TROUBLESHOOT_SYSTEM_PROMPT,
      messages: [
        { role: 'user', content: userMessage }
      ]
    });

    // Parse Claude's response - it returns text that should be JSON
    const responseText = completion.content[0].text;
    const solution = JSON.parse(responseText);
    return solution;

  } catch (error) {
    console.error('Error getting solution from Claude:', error.message);
    return null;
  }
}

/**
 * Validate that a file path is safe to modify (challenge files only)
 */
function isSafeToModify(filePath, challengePath) {
  const normalizedPath = path.normalize(filePath).toLowerCase();
  const normalizedChallengePath = path.normalize(challengePath).toLowerCase();
  
  // CRITICAL: File must be within challenge directory
  if (!normalizedPath.startsWith(normalizedChallengePath)) {
    console.error(`❌ BLOCKED: File outside challenge directory: ${filePath}`);
    return false;
  }
  
  // Forbidden paths (platform code)
  const forbiddenPaths = [
    'src/', 'backend/', 'database/', 'public/', 
    'node_modules/', '.git/', '.venv/',
    'ctf-automation/src/', 'ctf-automation/package.json'
  ];
  
  for (const forbidden of forbiddenPaths) {
    if (normalizedPath.includes(forbidden.toLowerCase())) {
      console.error(`❌ BLOCKED: Forbidden path detected: ${forbidden} in ${filePath}`);
      return false;
    }
  }
  
  // Forbidden file types (platform code)
  const forbiddenExtensions = ['.tsx', '.ts', '.jsx'];
  const ext = path.extname(filePath).toLowerCase();
  if (forbiddenExtensions.includes(ext)) {
    console.error(`❌ BLOCKED: Platform code file type: ${ext}`);
    return false;
  }
  
  // Forbidden specific files
  const forbiddenFiles = [
    'package.json', 'package-lock.json',
    'vite.config.ts', 'tsconfig.json',
    'schema.sql', 'auth.ts'
  ];
  
  const fileName = path.basename(filePath).toLowerCase();
  if (forbiddenFiles.includes(fileName) && !normalizedPath.includes('challenge')) {
    console.error(`❌ BLOCKED: Platform config file: ${fileName}`);
    return false;
  }
  
  // Allowed file patterns (challenge files)
  const allowedPatterns = [
    /dockerfile/i,
    /docker-compose.*\.yml$/i,
    /\.conf$/i,
    /\.config$/i,
    /\.cfg$/i,
    /\.ini$/i,
    /flag\.txt$/i,
    /readme\.md$/i,
    /\.sh$/i,
    /\.py$/i,
    /\.js$/i,
    /\.php$/i,
    /\.html$/i,
    /\.sql$/i
  ];
  
  const isAllowed = allowedPatterns.some(pattern => pattern.test(filePath));
  
  if (!isAllowed) {
    console.warn(`⚠️ WARNING: Unusual file type: ${filePath}`);
  }
  
  return true;
}

/**
 * Apply the suggested fix
 */
async function applyFix(challengePath, solution) {
  try {
    console.log('\n🔨 Applying fix...');

    // Validate we're in a challenge directory
    if (!challengePath.includes('challenge') && !challengePath.includes('test-')) {
      console.error('❌ SAFETY CHECK FAILED: Not in a challenge directory!');
      console.error(`   Path: ${challengePath}`);
      return false;
    }

    // Apply file changes
    if (solution.files_to_modify) {
      for (const fileChange of solution.files_to_modify) {
        const filePath = path.join(challengePath, fileChange.path);
        
        // CRITICAL SAFETY CHECK
        if (!isSafeToModify(filePath, challengePath)) {
          console.error(`❌ SKIPPING unsafe file: ${fileChange.path}`);
          continue;
        }
        
        console.log(`  📝 Modifying ${fileChange.path}...`);
        
        // Backup original file
        if (fs.existsSync(filePath)) {
          fs.copyFileSync(filePath, `${filePath}.backup`);
          console.log(`     💾 Backup created: ${fileChange.path}.backup`);
        }
        
        // Write new content
        fs.writeFileSync(filePath, fileChange.changes, 'utf8');
        console.log(`     ✅ File updated`);
      }
    }

    // Execute commands
    if (solution.commands) {
      for (const command of solution.commands) {
        // Validate command is docker-related
        if (!command.includes('docker') && !command.includes('compose')) {
          console.warn(`⚠️ SKIPPING non-docker command: ${command}`);
          continue;
        }
        
        console.log(`  🚀 Running: ${command}`);
        execSync(command, { 
          cwd: challengePath,
          stdio: 'inherit'
        });
      }
    }

    console.log('✅ Fix applied');
    return true;

  } catch (error) {
    console.error('❌ Error applying fix:', error.message);
    return false;
  }
}

/**
 * Run diagnostics only (no fixes)
 */
export async function diagnoseChallenge(challengePath) {
  console.log(`\n🔍 Running diagnostics for: ${challengePath}`);
  
  const diagnostics = await gatherDiagnostics(challengePath);
  
  console.log('\n📊 Diagnostic Results:');
  console.log(`   All Running: ${diagnostics.allRunning ? '✅' : '❌'}`);
  console.log(`   Containers: ${diagnostics.containerStatus.length}`);
  console.log(`   Log Entries: ${Object.keys(diagnostics.logs).length}`);
  
  return diagnostics;
}

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const challengePath = process.argv[2] || process.cwd();
  const autoFix = process.argv.includes('--fix');
  
  if (autoFix) {
    troubleshootChallenge(challengePath, { autoFix: true })
      .then(result => {
        console.log('\n' + JSON.stringify(result, null, 2));
        process.exit(result.success ? 0 : 1);
      });
  } else {
    diagnoseChallenge(challengePath)
      .then(() => process.exit(0));
  }
}
