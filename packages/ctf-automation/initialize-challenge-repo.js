import simpleGit from 'simple-git';
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

// Get project root directory (2 levels up from this file)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;
const REPO_URL = process.env.REPO_URL || 'https://github.com/Ahmed-CYB/mcp-test.git';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER || 'Ahmed-CYB';
const GITHUB_REPO = process.env.GITHUB_REPO || 'mcp-test';

/**
 * Initialize base challenge repository structure
 */
async function initializeChallengeRepo() {
  try {
    console.log('🚀 Initializing challenge repository...');
    
    // Create repository URL with token if available
    const repoUrl = GITHUB_TOKEN 
      ? `https://${GITHUB_TOKEN}@github.com/${GITHUB_OWNER}/${GITHUB_REPO}.git`
      : REPO_URL;
    
    const git = simpleGit(CLONE_PATH);
    
    // Check if repository exists
    let repoExists = false;
    try {
      await fs.access(path.join(CLONE_PATH, '.git'));
      repoExists = true;
      console.log('✅ Repository already exists');
    } catch {
      console.log('📥 Cloning repository...');
      await git.clone(repoUrl, CLONE_PATH);
      repoExists = true;
    }
    
    if (repoExists) {
      // Pull latest changes
      console.log('📥 Pulling latest changes...');
      await git.pull('origin', 'main').catch(() => git.pull('origin', 'master'));
    }
    
    // Create base directory structure
    console.log('\n📁 Creating base repository structure...');
    
    const challengesDir = path.join(CLONE_PATH, 'challenges');
    await fs.mkdir(challengesDir, { recursive: true });
    console.log('✅ Created challenges/ directory');
    
    // Create .gitkeep to ensure challenges directory is tracked
    const gitkeepPath = path.join(challengesDir, '.gitkeep');
    await fs.writeFile(gitkeepPath, '# This file ensures the challenges directory is tracked by git\n');
    console.log('✅ Created challenges/.gitkeep');
    
    // Create README.md for the repository
    const readmePath = path.join(CLONE_PATH, 'README.md');
    const readmeContent = `# CTF Challenge Repository

This repository contains all CTF challenges created by the AI CTF Challenge Platform automation system.

## Repository Structure

\`\`\`
challenges/
└── {challenge-name}/
    ├── docker-compose.yml      # Multi-container orchestration
    ├── metadata.json           # Challenge metadata
    ├── README.md              # Challenge description and instructions
    ├── Dockerfile             # Victim container configuration
    ├── attacker/
    │   └── Dockerfile.attacker # Attacker (Kali Linux) configuration
    └── {machine-name}/        # Additional victim machines (if multi-machine)
        └── Dockerfile
\`\`\`

## Challenge Structure

Each challenge directory contains:

- **docker-compose.yml**: Defines all containers (victim, attacker, database, etc.) and their network configuration
- **metadata.json**: Challenge metadata including name, description, difficulty, category, flag, and hints
- **README.md**: Human-readable challenge description and learning objectives
- **Dockerfile(s)**: Container configurations for victim machines
- **attacker/Dockerfile.attacker**: Kali Linux attacker machine configuration

## Challenge Categories

- **Network**: FTP, SSH, SMB, Telnet, and other network protocol challenges
- **Web**: SQL injection, XSS, CSRF, and other web vulnerabilities
- **Crypto**: Encryption, encoding, hashing, and cipher challenges

## Automation

All challenges in this repository are automatically created, validated, and deployed by the CTF Challenge Platform automation system.

## Usage

Challenges are automatically deployed when requested through the platform's chat interface. Each challenge gets:
- Isolated Docker network with private IPs
- Kali Linux attacker machine with required tools
- Victim machine(s) with configured vulnerabilities
- Guacamole access for browser-based terminal access

## Notes

- Challenges use private IPs only (no port mappings)
- Each challenge gets a unique subnet (172.20-30.X.0/24)
- Attacker machine always at .3 IP address
- Victim machines at randomized IPs (.10-.200)
`;

    // Check if README exists, if not create it
    try {
      await fs.access(readmePath);
      console.log('⚠️  README.md already exists, skipping...');
    } catch {
      await fs.writeFile(readmePath, readmeContent, 'utf-8');
      console.log('✅ Created README.md');
    }
    
    // Create .gitignore if it doesn't exist
    const gitignorePath = path.join(CLONE_PATH, '.gitignore');
    const gitignoreContent = `# CTF Challenge Repository .gitignore

# OS files
.DS_Store
Thumbs.db
*.swp
*.swo
*~

# IDE files
.vscode/
.idea/
*.sublime-*

# Logs
*.log
logs/

# Temporary files
tmp/
temp/
*.tmp

# Docker
.dockerignore

# Environment files
.env
.env.local

# Node modules (if any)
node_modules/

# Build artifacts
dist/
build/
`;

    try {
      await fs.access(gitignorePath);
      console.log('⚠️  .gitignore already exists, skipping...');
    } catch {
      await fs.writeFile(gitignorePath, gitignoreContent, 'utf-8');
      console.log('✅ Created .gitignore');
    }
    
    // Stage all new files
    console.log('\n📝 Staging files...');
    await git.addConfig('user.name', 'CTF Automation').catch(() => {});
    await git.addConfig('user.email', 'ctf-automation@localhost').catch(() => {});
    
    // Check if there are changes to commit
    const status = await git.status();
    
    if (status.files.length === 0 && status.not_added.length === 0) {
      console.log('✅ Repository is already up to date');
    } else {
      // Add all files
      await git.add('.');
      console.log('✅ Files staged');
      
      // Commit if there are changes
      if (status.files.length > 0 || status.not_added.length > 0) {
        console.log('\n💾 Committing base structure...');
        await git.commit('Initialize challenge repository base structure');
        console.log('✅ Changes committed');
        
        // Push to GitHub
        console.log('\n🚀 Pushing to GitHub...');
        await git.push('origin', 'main').catch(() => git.push('origin', 'master'));
        console.log('✅ Changes pushed to GitHub');
      }
    }
    
    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('✅ REPOSITORY INITIALIZATION COMPLETE');
    console.log('='.repeat(60));
    console.log('\n📊 Repository Structure:');
    console.log('   📁 challenges/          - Challenge directories will be created here');
    console.log('   📄 README.md           - Repository documentation');
    console.log('   📄 .gitignore          - Git ignore rules');
    console.log('   📄 challenges/.gitkeep - Ensures challenges directory is tracked');
    console.log('\n✅ Repository is ready for challenge automation!');
    console.log('\n📝 Next steps:');
    console.log('   - Challenges will be automatically created in challenges/ directory');
    console.log('   - Each challenge will have its own subdirectory with all required files');
    console.log('   - All changes will be automatically committed and pushed to GitHub');
    
  } catch (error) {
    console.error('\n❌ Error initializing repository:', error);
    throw error;
  }
}

// Run initialization
initializeChallengeRepo()
  .then(() => {
    console.log('\n✅ Initialization completed successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Initialization failed:', error.message);
    process.exit(1);
  });

