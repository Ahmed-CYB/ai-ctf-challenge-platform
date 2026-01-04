import simpleGit from 'simple-git';
import fs from 'fs/promises';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config();

// Get project root directory (2 levels up from this file)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;
const REPO_URL = process.env.REPO_URL || 'https://github.com/Ahmed-CYB/mcp-test.git';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_OWNER = process.env.GITHUB_OWNER || 'Ahmed-CYB';
const GITHUB_REPO = process.env.GITHUB_REPO || 'mcp-test';
const GITHUB_API_BASE = 'https://api.github.com';

export class GitManager {
  constructor() {
    this.git = simpleGit();
    this.clonePath = CLONE_PATH;
    // Use token in the URL for authentication
    this.repoUrl = GITHUB_TOKEN 
      ? `https://${GITHUB_TOKEN}@github.com/${GITHUB_OWNER}/${GITHUB_REPO}.git`
      : REPO_URL;
    this.trackedFiles = new Set(); // Track files added in current session
    this.pendingFiles = new Map(); // Track files pending commit (for rollback)
  }

  async ensureRepository() {
    try {
      const gitDir = path.join(this.clonePath, '.git');
      
      // Check if .git directory exists and is valid
      try {
        await fs.access(gitDir);
        
        // Verify it's actually a valid git repository
        const gitRepo = simpleGit(this.clonePath);
        try {
          // Try to get status to verify it's a valid repo
          await gitRepo.status();
          
          // Check if remote is configured correctly
          const remotes = await gitRepo.getRemotes(true);
          const hasCorrectRemote = remotes.some(r => 
            r.refs.fetch?.includes(`${GITHUB_OWNER}/${GITHUB_REPO}`) ||
            r.refs.push?.includes(`${GITHUB_OWNER}/${GITHUB_REPO}`)
          );
          
          if (!hasCorrectRemote && remotes.length > 0) {
            console.log('⚠️  Remote mismatch, updating remote URL...');
            await gitRepo.removeRemote('origin').catch(() => {});
            await gitRepo.addRemote('origin', this.repoUrl);
          } else if (remotes.length === 0) {
            console.log('⚠️  No remote configured, adding remote...');
            await gitRepo.addRemote('origin', this.repoUrl);
          }
          
          console.log('Repository already exists, pulling latest changes from GitHub...');
          const pullResult = await gitRepo.pull('origin', 'main').catch(() => {
            // Try 'master' if 'main' fails
            return gitRepo.pull('origin', 'master');
          });
          if (pullResult && pullResult.summary && pullResult.summary.changes > 0) {
            console.log(`✅ Successfully pulled ${pullResult.summary.changes} change(s) from GitHub`);
          } else {
            console.log('✅ Repository is up to date with GitHub');
          }
          return true;
        } catch (gitError) {
          // .git exists but repository might be corrupted - try to fix it
          console.warn('⚠️  Git repository appears corrupted, attempting to fix...');
          
          try {
            // Try to reinitialize the repository
            const gitRepo = simpleGit(this.clonePath);
            
            // Check if we can at least initialize
            await gitRepo.init();
            
            // Add remote if it doesn't exist
            const remotes = await gitRepo.getRemotes();
            if (remotes.length === 0) {
              await gitRepo.addRemote('origin', this.repoUrl);
            } else {
              // Update existing remote
              await gitRepo.removeRemote('origin').catch(() => {});
              await gitRepo.addRemote('origin', this.repoUrl);
            }
            
            // Try to fetch and reset
            await gitRepo.fetch('origin');
            const branches = await gitRepo.branchLocal();
            const defaultBranch = branches.current || 'main';
            
            try {
              await gitRepo.checkout(['-f', `origin/${defaultBranch}`]).catch(() => {
                return gitRepo.checkout(['-f', 'origin/main']).catch(() => {
                  return gitRepo.checkout(['-f', 'origin/master']);
                });
              });
            } catch {
              // If checkout fails, try reset
              await gitRepo.reset(['--hard', `origin/${defaultBranch}`]).catch(() => {
                return gitRepo.reset(['--hard', 'origin/main']).catch(() => {
                  return gitRepo.reset(['--hard', 'origin/master']);
                });
              });
            }
            
            console.log('✅ Successfully fixed and updated repository');
            return true;
          } catch (fixError) {
            console.warn('⚠️  Could not fix repository, will reinitialize...');
            throw new Error('Repository fix failed');
          }
        }
      } catch (error) {
        // .git doesn't exist - try to initialize or clone
        console.log('Repository not found, initializing...');
        
        // Check if directory exists
        let directoryExists = false;
        try {
          await fs.access(this.clonePath);
          directoryExists = true;
        } catch {
          // Directory doesn't exist, we'll create it
        }
        
        if (directoryExists) {
          // Directory exists but isn't a git repo - try to initialize it
          console.log('Directory exists but is not a git repository, initializing...');
          try {
            const gitRepo = simpleGit(this.clonePath);
            await gitRepo.init();
            await gitRepo.addRemote('origin', this.repoUrl);
            
            // Try to fetch and checkout
            await gitRepo.fetch('origin');
            
            // Try to checkout main or master branch
            try {
              await gitRepo.checkout(['-f', 'origin/main']);
            } catch {
              try {
                await gitRepo.checkout(['-f', 'origin/master']);
              } catch {
                // If both fail, just initialize empty repo
                console.warn('⚠️  Could not checkout remote branch, repository initialized but empty');
              }
            }
            
            console.log('✅ Successfully initialized repository from existing directory');
            return true;
          } catch (initError) {
            console.warn('⚠️  Could not initialize in existing directory:', initError.message);
            console.log('Removing directory to perform fresh clone...');
            
            // If initialization fails, delete and clone fresh
            await fs.rm(this.clonePath, { recursive: true, force: true });
            await new Promise(resolve => setTimeout(resolve, 500));
          }
        }
        
        // Ensure parent directory exists
        const parentDir = path.dirname(this.clonePath);
        await fs.mkdir(parentDir, { recursive: true });
        
        // Clone the repository
        await this.git.clone(this.repoUrl, this.clonePath);
        console.log('✅ Successfully cloned repository');
        return true;
      }
    } catch (error) {
      console.error('❌ Error ensuring repository:', error);
      throw new Error(`Failed to setup repository: ${error.message}`);
    }
  }

  async addFile(fileName, content) {
    try {
      await this.ensureRepository();
      
      const filePath = path.join(this.clonePath, fileName);
      
      // Create directory if needed
      const dir = path.dirname(filePath);
      
      // Check if directory path exists and is a file (not a directory)
      // This handles cases where a file like .hidden_compliance might exist as a directory
      try {
        const dirStat = await fs.stat(dir);
        if (!dirStat.isDirectory()) {
          // If parent path is a file, remove it and create as directory
          console.log(`⚠️  Parent path exists as file, removing: ${dir}`);
          await fs.unlink(dir);
        }
      } catch (statError) {
        // Path doesn't exist, which is fine - we'll create it
      }
      
      // Check if the file path itself exists as a directory
      try {
        const fileStat = await fs.stat(filePath);
        if (fileStat.isDirectory()) {
          // If file path is a directory, remove it
          console.log(`⚠️  File path exists as directory, removing: ${filePath}`);
          await fs.rmdir(filePath, { recursive: true });
        }
      } catch (statError) {
        // File doesn't exist, which is fine
      }
      
      // Now create the directory structure
      await fs.mkdir(dir, { recursive: true });
      
      // Write file
      await fs.writeFile(filePath, content, 'utf-8');
      console.log(`Created file: ${fileName}`);
      
      // Track file for GitHub API commit
      this.trackedFiles.add(fileName);
      // Track for potential rollback
      this.pendingFiles.set(fileName, filePath);
      
      return filePath;
    } catch (error) {
      console.error('Error adding file:', error);
      throw new Error(`Failed to add file: ${error.message}`);
    }
  }

  /**
   * Get file content as base64 for GitHub API
   */
  async getFileContentBase64(fileName) {
    const filePath = path.join(this.clonePath, fileName);
    let content = await fs.readFile(filePath, 'utf-8');
    
    // Sanitize secrets before encoding
    content = this.sanitizeSecrets(content);
    
    return Buffer.from(content, 'utf-8').toString('base64');
  }

  /**
   * Get the default branch name (main or master)
   */
  async getDefaultBranch() {
    try {
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}`, {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      const repo = await response.json();
      return repo.default_branch || 'main';
    } catch (error) {
      console.warn('Failed to get default branch, using "main" as fallback:', error.message);
      return 'main';
    }
  }

  /**
   * Get the SHA of the latest commit on the default branch
   */
  async getLatestCommitSha(branch = 'main') {
    try {
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/ref/heads/${branch}`, {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      const ref = await response.json();
      return ref.object.sha;
    } catch (error) {
      throw new Error(`Failed to get latest commit SHA: ${error.message}`);
    }
  }

  /**
   * Get the tree SHA from a commit SHA
   */
  async getTreeSha(commitSha) {
    try {
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/commits/${commitSha}`, {
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json'
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      const commit = await response.json();
      return commit.tree.sha;
    } catch (error) {
      throw new Error(`Failed to get tree SHA: ${error.message}`);
    }
  }

  /**
   * Sanitize content to remove potential secrets before committing
   * Replaces secret-like patterns with safe placeholders
   */
  sanitizeSecrets(content) {
    if (typeof content !== 'string') {
      return content;
    }

    let sanitized = content;
    const replacements = [];

    // Common secret patterns (GitHub secret scanning detects these)
    const secretPatterns = [
      // Stripe API keys (most common false positive)
      {
        pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
        replacement: 'sk_live_XXXXXXXXXXXXXXXXXXXXXXXX',
        type: 'Stripe Live API Key'
      },
      {
        pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
        replacement: 'sk_test_XXXXXXXXXXXXXXXXXXXXXXXX',
        type: 'Stripe Test API Key'
      },
      {
        pattern: /pk_live_[a-zA-Z0-9]{24,}/g,
        replacement: 'pk_live_XXXXXXXXXXXXXXXXXXXXXXXX',
        type: 'Stripe Live Publishable Key'
      },
      // AWS keys
      {
        pattern: /AKIA[0-9A-Z]{16}/g,
        replacement: 'AKIAXXXXXXXXXXXXXXXX',
        type: 'AWS Access Key ID'
      },
      {
        pattern: /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}/g,
        replacement: 'aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
        type: 'AWS Secret Access Key'
      },
      // Generic API keys (long alphanumeric strings that look like keys)
      {
        pattern: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*([a-zA-Z0-9_\-]{32,})/gi,
        replacement: (match) => {
          const parts = match.split(/[=:]/);
          if (parts.length >= 2) {
            return `${parts[0]}=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`;
          }
          return match;
        },
        type: 'Generic API Key'
      },
      // JWT tokens
      {
        pattern: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
        replacement: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkV4YW1wbGUifQ.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
        type: 'JWT Token'
      },
      // Database connection strings with passwords
      {
        pattern: /(?:mysql|postgres|mongodb|redis):\/\/[^:]+:([^@]+)@/g,
        replacement: (match, password) => match.replace(password, 'XXXXXX'),
        type: 'Database Password'
      },
      // Private keys (RSA, EC, etc.)
      {
        pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
        replacement: '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----',
        type: 'Private Key'
      }
    ];

    for (const { pattern, replacement, type } of secretPatterns) {
      const matches = sanitized.match(pattern);
      if (matches) {
        sanitized = sanitized.replace(pattern, replacement);
        replacements.push({
          type,
          count: matches.length
        });
      }
    }

    if (replacements.length > 0) {
      console.warn(`⚠️  Sanitized ${replacements.length} secret pattern(s) before commit:`);
      replacements.forEach(r => {
        console.warn(`   - ${r.type}: ${r.count} occurrence(s)`);
      });
    }

    return sanitized;
  }

  /**
   * Create a blob in GitHub repository
   */
  async createBlob(contentBase64) {
    try {
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/blobs`, {
        method: 'POST',
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          content: contentBase64,
          encoding: 'base64'
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`GitHub API error: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const blob = await response.json();
      return blob.sha;
    } catch (error) {
      throw new Error(`Failed to create blob: ${error.message}`);
    }
  }


  /**
   * Normalize file path for GitHub API
   * - Normalize path separators to forward slashes
   * - Remove double slashes
   * - Resolve parent directory references (..)
   * - Remove leading/trailing slashes
   * - Ensure no empty path components
   */
  normalizePath(filePath) {
    // Normalize path separators to forward slashes (GitHub uses Unix-style paths)
    let normalized = filePath.replace(/\\/g, '/');
    
    // Remove double slashes
    normalized = normalized.replace(/\/+/g, '/');
    
    // Split path into components
    const parts = normalized.split('/').filter(part => part.length > 0);
    
    // Resolve parent directory references (..)
    const resolvedParts = [];
    for (const part of parts) {
      if (part === '..') {
        if (resolvedParts.length > 0) {
          resolvedParts.pop(); // Remove parent directory
        }
        // If we're at the root, ignore '..'
      } else if (part !== '.') {
        resolvedParts.push(part);
      }
      // Ignore '.' (current directory)
    }
    
    // Join back and ensure it starts with the expected prefix
    normalized = resolvedParts.join('/');
    
    // Ensure no leading slash (GitHub paths are relative to repo root)
    normalized = normalized.replace(/^\/+/, '');
    
    return normalized;
  }

  /**
   * Create a new tree with updated files
   * When base_tree is provided, GitHub API automatically preserves existing files
   * and only updates/adds the files specified in the tree array
   */
  async createTree(baseTreeSha, filePaths) {
    try {
      // Create blobs for new/updated files
      const tree = [];
      
      // Add new/updated files (GitHub API will preserve existing files via base_tree)
      for (const filePath of filePaths) {
        // Normalize path to fix double slashes, path traversal, etc.
        const normalizedPath = this.normalizePath(filePath);
        
        // Skip if path is invalid after normalization
        if (!normalizedPath || normalizedPath === '' || normalizedPath.startsWith('../')) {
          console.warn(`⚠️  Skipping invalid path: ${filePath} (normalized: ${normalizedPath})`);
          continue;
        }
        
        const contentBase64 = await this.getFileContentBase64(filePath);
        const blobSha = await this.createBlob(contentBase64);
        
        tree.push({
          path: normalizedPath,
          mode: '100644',
          type: 'blob',
          sha: blobSha
        });
      }

      // Create the tree (base_tree preserves existing files)
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/trees`, {
        method: 'POST',
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          base_tree: baseTreeSha,
          tree: tree
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`GitHub API error: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const newTree = await response.json();
      return newTree.sha;
    } catch (error) {
      throw new Error(`Failed to create tree: ${error.message}`);
    }
  }

  /**
   * Create a commit using GitHub API
   */
  async createCommit(treeSha, parentSha, message) {
    try {
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/commits`, {
        method: 'POST',
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: message,
          tree: treeSha,
          parents: [parentSha]
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`GitHub API error: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const commit = await response.json();
      return commit.sha;
    } catch (error) {
      throw new Error(`Failed to create commit: ${error.message}`);
    }
  }

  /**
   * Update branch reference to point to new commit
   */
  async updateRef(branch, commitSha) {
    try {
      const response = await fetch(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs/heads/${branch}`, {
        method: 'PATCH',
        headers: {
          'Authorization': `token ${GITHUB_TOKEN}`,
          'Accept': 'application/vnd.github.v3+json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sha: commitSha
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`GitHub API error: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const ref = await response.json();
      return ref;
    } catch (error) {
      throw new Error(`Failed to update ref: ${error.message}`);
    }
  }

  async commitAndPush(commitMessage, userMessage = '') {
    try {
      if (!GITHUB_TOKEN) {
        console.warn('⚠️  No GitHub token found - files saved locally only');
        console.warn('⚠️  Files are saved at:', this.clonePath);
        return { committed: false, pushed: false, message: 'No GitHub token - files saved locally' };
      }

      // Check if there are any files to commit
      if (this.trackedFiles.size === 0) {
        console.log('Nothing to commit - no changes detected');
        return { committed: false, pushed: false, message: 'No changes to commit' };
      }

      console.log(`📤 Committing ${this.trackedFiles.size} files using GitHub API...`);

      // Get default branch
      const branch = await this.getDefaultBranch();
      console.log(`📍 Using branch: ${branch}`);

      // Get latest commit SHA
      const latestCommitSha = await this.getLatestCommitSha(branch);
      console.log(`📝 Latest commit SHA: ${latestCommitSha.substring(0, 7)}`);

      // Get base tree SHA
      const baseTreeSha = await this.getTreeSha(latestCommitSha);
      console.log(`🌲 Base tree SHA: ${baseTreeSha.substring(0, 7)}`);

      // Create new tree with all files
      const filePaths = Array.from(this.trackedFiles);
      const newTreeSha = await this.createTree(baseTreeSha, filePaths);
      console.log(`🌲 New tree SHA: ${newTreeSha.substring(0, 7)}`);

      // Create commit
      const newCommitSha = await this.createCommit(newTreeSha, latestCommitSha, commitMessage || userMessage);
      console.log(`✅ Commit created: ${newCommitSha.substring(0, 7)}`);

      // Update branch reference
      await this.updateRef(branch, newCommitSha);
      console.log(`🚀 Branch ${branch} updated to commit ${newCommitSha.substring(0, 7)}`);

      // Clear tracked files after successful commit
      this.trackedFiles.clear();

      console.log(`✅ Successfully committed and pushed ${filePaths.length} files to GitHub`);
      return { committed: true, pushed: true, commitSha: newCommitSha, branch: branch };
    } catch (error) {
      console.error('❌ Error committing and pushing via GitHub API:', error);
      throw new Error(`Failed to commit and push via GitHub API: ${error.message}`);
    }
  }

  async getFileContent(fileName) {
    try {
      await this.ensureRepository();
      
      const filePath = path.join(this.clonePath, fileName);
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      console.error('Error reading file:', error);
      throw new Error(`Failed to read file: ${error.message}`);
    }
  }

  async listChallenges() {
    try {
      await this.ensureRepository();
      
      const challenges = [];
      const challengesDir = path.join(this.clonePath, 'challenges');
      
      // Check if challenges directory exists
      try {
        await fs.access(challengesDir);
      } catch {
        // Challenges directory doesn't exist yet
        return challenges;
      }
      
      const entries = await fs.readdir(challengesDir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isDirectory()) {
          // Check if directory contains a Dockerfile (indicating it's a challenge)
          const dockerfilePath = path.join(challengesDir, entry.name, 'Dockerfile');
          try {
            await fs.access(dockerfilePath);
            challenges.push(entry.name);
          } catch {
            // No Dockerfile, not a challenge directory
          }
        }
      }
      
      return challenges;
    } catch (error) {
      console.error('Error listing challenges:', error);
      throw new Error(`Failed to list challenges: ${error.message}`);
    }
  }

  async getChallengeMetadata(challengeName) {
    try {
      await this.ensureRepository();
      
      const metadataPath = path.join(this.clonePath, 'challenges', challengeName, 'metadata.json');
      
      try {
        const content = await fs.readFile(metadataPath, 'utf-8');
        return JSON.parse(content);
      } catch (error) {
        // Metadata file doesn't exist
        return null;
      }
    } catch (error) {
      console.error('Error getting challenge metadata:', error);
      throw new Error(`Failed to get metadata: ${error.message}`);
    }
  }

  /**
   * Generate a unique challenge name by checking existing challenges
   * ALWAYS creates NEW challenges with unique names, even for same vulnerability types
   * @param {string} baseName - The base name to make unique
   * @returns {Promise<string>} - A unique challenge name
   */
  async generateUniqueChallengeName(baseName) {
    try {
      // Normalize base name
      let normalizedName = baseName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');

      // Get list of existing challenges
      const existingChallenges = await this.listChallenges();
      console.log(`📋 Found ${existingChallenges.length} existing challenges in repository`);

      // Check if base name is unique (exact match)
      if (!existingChallenges.includes(normalizedName)) {
        // Also check for similar names (to prevent "corporate-data-breach" vs "corporate-data-breach-investigation")
        const isSimilar = existingChallenges.some(existing => {
          // Check if one name contains the other (with at least 10 chars overlap)
          const minLength = Math.min(normalizedName.length, existing.length);
          if (minLength < 10) return false;
          
          // Check if names are too similar (one is substring of other with 80%+ overlap)
          const longer = normalizedName.length > existing.length ? normalizedName : existing;
          const shorter = normalizedName.length > existing.length ? existing : normalizedName;
          
          // If shorter name is 80%+ of longer name, they're too similar
          if (shorter.length / longer.length >= 0.8) {
            return longer.includes(shorter) || shorter.includes(longer.substring(0, shorter.length));
          }
          
          return false;
        });
        
        if (!isSimilar) {
        console.log(`✅ Challenge name "${normalizedName}" is unique`);
        return normalizedName;
        } else {
          console.log(`⚠️  Challenge name "${normalizedName}" is too similar to existing challenges, generating unique name...`);
        }
      }

      // Name exists, generate NEW unique challenge with creative naming
      console.log(`⚠️  Challenge "${normalizedName}" already exists, creating NEW challenge with unique name...`);
      
      // Extract vulnerability type for contextual naming
      const vulnType = normalizedName.split('-')[0]; // e.g., "ftp", "sql", "xss"
      
      // Creative suffix patterns based on vulnerability type
      const creativeSuffixes = {
        'ftp': ['misconfigured', 'anonymous', 'writable', 'backdoor', 'exposed', 'legacy', 'insecure-config', 'weak-auth'],
        'sql': ['blind', 'union-based', 'time-based', 'error-based', 'boolean', 'stacked', 'second-order', 'out-of-band'],
        'xss': ['stored', 'reflected', 'dom-based', 'blind', 'mutation', 'universal', 'filter-bypass', 'self-xss'],
        'smb': ['null-session', 'guest-access', 'eternalblue', 'anonymous', 'relay', 'signing-disabled', 'share-enum'],
        'ssh': ['weak-keys', 'bruteforce', 'default-creds', 'config-vuln', 'port-forwarding', 'key-leak', 'outdated'],
        'web': ['lfi', 'rfi', 'idor', 'csrf', 'xxe', 'ssrf', 'deserialization', 'race-condition'],
        'default': ['v2', 'advanced', 'pro', 'elite', 'master', 'expert', 'extended', 'enhanced', 'ultimate', 'redux']
      };
      
      const suffixes = creativeSuffixes[vulnType] || creativeSuffixes['default'];
      
      // Try creative suffixes
      for (const suffix of suffixes) {
        const candidateName = `${normalizedName}-${suffix}`;
        if (!existingChallenges.includes(candidateName)) {
          console.log(`✅ Generated NEW unique challenge: "${candidateName}"`);
          return candidateName;
        }
      }

      // If all creative suffixes taken, add variant numbers
      for (let i = 1; i <= 50; i++) {
        const candidateName = `${normalizedName}-variant-${i}`;
        if (!existingChallenges.includes(candidateName)) {
          console.log(`✅ Generated NEW unique challenge: "${candidateName}"`);
          return candidateName;
        }
      }

      // Use timestamp-based unique ID for guaranteed uniqueness
      const timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, ''); // YYYYMMDD format
      const timeBasedName = `${normalizedName}-${timestamp}`;
      
      if (!existingChallenges.includes(timeBasedName)) {
        console.log(`✅ Generated NEW unique challenge with date: "${timeBasedName}"`);
        return timeBasedName;
      }

      // Final fallback: timestamp with milliseconds (guaranteed unique)
      const uniqueId = Date.now().toString(36).slice(-6); // Short base36 ID
      const fallbackName = `${normalizedName}-${uniqueId}`;
      console.log(`✅ Generated NEW unique challenge with ID: "${fallbackName}"`);
      return fallbackName;
      
    } catch (error) {
      console.error('Error generating unique challenge name:', error);
      // Fallback: use short unique identifier (always creates NEW challenge)
      const uniqueId = Date.now().toString(36).slice(-6);
      const fallbackName = `${baseName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${uniqueId}`;
      console.warn(`⚠️  Using fallback name with unique ID: ${fallbackName}`);
      return fallbackName;
    }
  }

  /**
   * Clean up files after a failed commit
   * IMPROVEMENT: Rollback mechanism for failed GitHub pushes
   * @param {string} challengeName - Challenge name to clean up
   */
  async cleanupFailedCommit(challengeName) {
    try {
      console.log(`🧹 Cleaning up files for failed commit: ${challengeName}`);
      
      const challengeDir = path.join(this.clonePath, 'challenges', challengeName);
      
      // Check if challenge directory exists
      try {
        await fs.access(challengeDir);
      } catch {
        console.log(`⚠️  Challenge directory doesn't exist: ${challengeDir}`);
        return;
      }

      // Remove challenge directory
      await fs.rm(challengeDir, { recursive: true, force: true });
      console.log(`✅ Removed challenge directory: ${challengeDir}`);

      // Remove from tracked files
      const filesToRemove = Array.from(this.trackedFiles).filter(f => f.includes(challengeName));
      for (const file of filesToRemove) {
        this.trackedFiles.delete(file);
        this.pendingFiles.delete(file);
      }

      console.log(`✅ Cleaned up ${filesToRemove.length} tracked files for ${challengeName}`);
    } catch (error) {
      console.error(`❌ Failed to cleanup files for ${challengeName}:`, error.message);
      // Don't throw - cleanup failures shouldn't break the flow
    }
  }
}

export const gitManager = new GitManager();
