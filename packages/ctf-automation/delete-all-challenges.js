import { Octokit } from 'octokit';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN
});

const owner = process.env.GITHUB_OWNER || 'Ahmed-CYB';
const repo = process.env.GITHUB_REPO || 'mcp-test';

// Get project root directory (2 levels up from this file)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');
const DEFAULT_CLONE_PATH = path.join(projectRoot, 'challenges-repo');

const CLONE_PATH = process.env.CLONE_PATH || DEFAULT_CLONE_PATH;

/**
 * List all challenges in the repository
 */
async function listAllChallenges() {
  try {
    const challengesPath = path.join(CLONE_PATH, 'challenges');
    
    // Check if challenges directory exists
    try {
      await fs.access(challengesPath);
    } catch {
      console.log('⚠️  Challenges directory does not exist');
      return [];
    }
    
    // Read all directories in challenges folder
    const entries = await fs.readdir(challengesPath, { withFileTypes: true });
    const challenges = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name);
    
    return challenges;
  } catch (error) {
    console.error('Error listing challenges:', error);
    return [];
  }
}

/**
 * Delete a challenge directory from GitHub
 */
async function deleteChallengeFromGitHub(challengeName) {
  try {
    const challengePath = `challenges/${challengeName}`;
    
    console.log(`\n🗑️  Deleting challenge: ${challengeName}...`);
    
    // Get all files in the challenge directory recursively
    const filesToDelete = [];
    
    async function getFilesRecursive(dirPath, relativePath = '') {
      try {
        const fullPath = path.join(CLONE_PATH, dirPath, relativePath);
        const entries = await fs.readdir(fullPath, { withFileTypes: true });
        
        for (const entry of entries) {
          const entryRelativePath = path.join(relativePath, entry.name).replace(/\\/g, '/');
          const entryFullPath = path.join(fullPath, entry.name);
          
          if (entry.isDirectory()) {
            await getFilesRecursive(dirPath, entryRelativePath);
          } else {
            const githubPath = `${challengePath}/${entryRelativePath}`;
            filesToDelete.push(githubPath);
          }
        }
      } catch (error) {
        // Directory might not exist locally, but we still need to delete from GitHub
        console.log(`⚠️  Could not read directory locally: ${relativePath}`);
      }
    }
    
    // Get files from local directory if it exists
    const localChallengePath = path.join(CLONE_PATH, challengePath);
    try {
      await fs.access(localChallengePath);
      await getFilesRecursive(challengePath);
    } catch {
      console.log(`⚠️  Challenge directory doesn't exist locally, will delete from GitHub directly`);
    }
    
    // If we couldn't get files from local directory, try to get them from GitHub
    if (filesToDelete.length === 0) {
      try {
        const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
          owner,
          repo,
          path: challengePath
        });
        
        // GitHub API returns an array for directories
        if (Array.isArray(data)) {
          // Recursively get all files
          async function getFilesFromGitHub(dirPath) {
            try {
              const { data: dirData } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
                owner,
                repo,
                path: dirPath
              });
              
              if (Array.isArray(dirData)) {
                for (const item of dirData) {
                  if (item.type === 'file') {
                    filesToDelete.push(item.path);
                  } else if (item.type === 'dir') {
                    await getFilesFromGitHub(item.path);
                  }
                }
              }
            } catch (error) {
              console.log(`⚠️  Could not read directory from GitHub: ${dirPath}`);
            }
          }
          
          await getFilesFromGitHub(challengePath);
        }
      } catch (error) {
        if (error.status === 404) {
          console.log(`⚠️  Challenge ${challengeName} not found in GitHub (may already be deleted)`);
          return { success: true, deleted: 0 };
        }
        throw error;
      }
    }
    
    if (filesToDelete.length === 0) {
      console.log(`⚠️  No files found for challenge ${challengeName}`);
      return { success: true, deleted: 0 };
    }
    
    console.log(`📋 Found ${filesToDelete.length} files to delete`);
    
    // Delete all files
    let deletedCount = 0;
    let failedCount = 0;
    
    for (const filePath of filesToDelete) {
      try {
        // Get file SHA (required for deletion)
        const { data: fileData } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
          owner,
          repo,
          path: filePath
        });
        
        // Delete the file
        await octokit.request('DELETE /repos/{owner}/{repo}/contents/{path}', {
          owner,
          repo,
          path: filePath,
          message: `Delete challenge: ${challengeName}`,
          sha: fileData.sha
        });
        
        deletedCount++;
        process.stdout.write(`\r  ✅ Deleted ${deletedCount}/${filesToDelete.length} files...`);
      } catch (error) {
        if (error.status === 404) {
          // File already deleted, skip
          deletedCount++;
        } else {
          console.error(`\n❌ Failed to delete ${filePath}: ${error.message}`);
          failedCount++;
        }
      }
    }
    
    console.log(`\n✅ Deleted ${deletedCount} files for challenge: ${challengeName}`);
    if (failedCount > 0) {
      console.log(`⚠️  Failed to delete ${failedCount} files`);
    }
    
    return { success: true, deleted: deletedCount, failed: failedCount };
  } catch (error) {
    console.error(`❌ Error deleting challenge ${challengeName}:`, error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Delete all challenges from GitHub
 */
async function deleteAllChallenges() {
  try {
    console.log('🔍 Listing all challenges...');
    const challenges = await listAllChallenges();
    
    if (challenges.length === 0) {
      console.log('✅ No challenges found to delete');
      return;
    }
    
    console.log(`\n📋 Found ${challenges.length} challenges:`);
    challenges.forEach((challenge, index) => {
      console.log(`   ${index + 1}. ${challenge}`);
    });
    
    console.log(`\n🗑️  Starting deletion of ${challenges.length} challenges...`);
    console.log('⚠️  This will permanently delete all challenges from GitHub!');
    
    const results = [];
    for (const challenge of challenges) {
      const result = await deleteChallengeFromGitHub(challenge);
      results.push({ challenge, ...result });
      
      // Small delay to avoid rate limiting
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    
    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 DELETION SUMMARY');
    console.log('='.repeat(60));
    
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    const totalDeleted = results.reduce((sum, r) => sum + (r.deleted || 0), 0);
    
    console.log(`\n✅ Successfully deleted: ${successful.length} challenges`);
    console.log(`❌ Failed to delete: ${failed.length} challenges`);
    console.log(`📁 Total files deleted: ${totalDeleted}`);
    
    if (failed.length > 0) {
      console.log('\n❌ Failed challenges:');
      failed.forEach(r => {
        console.log(`   - ${r.challenge}: ${r.error || 'Unknown error'}`);
      });
    }
    
    console.log('\n✅ Deletion process completed!');
    
  } catch (error) {
    console.error('❌ Error deleting challenges:', error);
    throw error;
  }
}

// Run the deletion
deleteAllChallenges()
  .then(() => {
    console.log('\n✅ All challenges deleted successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Failed to delete challenges:', error);
    process.exit(1);
  });

