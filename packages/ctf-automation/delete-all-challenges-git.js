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
 * Delete all challenges from GitHub repository
 */
async function deleteAllChallenges() {
  try {
    console.log('🔍 Listing all challenges...');
    
    // Ensure repository is cloned
    const git = simpleGit(CLONE_PATH);
    
    // Check if repository exists
    try {
      await fs.access(path.join(CLONE_PATH, '.git'));
      console.log('✅ Repository found, pulling latest changes...');
      await git.pull('origin', 'main').catch(() => git.pull('origin', 'master'));
    } catch {
      console.log('📥 Cloning repository...');
      const repoUrl = GITHUB_TOKEN 
        ? `https://${GITHUB_TOKEN}@github.com/${GITHUB_OWNER}/${GITHUB_REPO}.git`
        : REPO_URL;
      await git.clone(repoUrl, CLONE_PATH);
    }
    
    // List all challenges
    const challengesDir = path.join(CLONE_PATH, 'challenges');
    
    try {
      await fs.access(challengesDir);
    } catch {
      console.log('⚠️  Challenges directory does not exist - no challenges to delete');
      return;
    }
    
    const entries = await fs.readdir(challengesDir, { withFileTypes: true });
    const challenges = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name);
    
    if (challenges.length === 0) {
      console.log('✅ No challenges found to delete');
      return;
    }
    
    console.log(`\n📋 Found ${challenges.length} challenges:`);
    challenges.forEach((challenge, index) => {
      console.log(`   ${index + 1}. ${challenge}`);
    });
    
    console.log(`\n🗑️  Deleting ${challenges.length} challenges from GitHub...`);
    console.log('⚠️  This will permanently delete all challenges!');
    
    // Remove each challenge directory
    for (const challenge of challenges) {
      const challengePath = path.join(challengesDir, challenge);
      const relativePath = `challenges/${challenge}`;
      
      try {
        // Check if directory exists
        await fs.access(challengePath);
        
        // Remove directory using git rm
        console.log(`\n🗑️  Deleting: ${challenge}...`);
        await git.rm(['-r', relativePath]);
        console.log(`   ✅ Staged for deletion: ${challenge}`);
      } catch (error) {
        if (error.message.includes('did not match any files')) {
          console.log(`   ⚠️  Challenge ${challenge} not tracked in git (may already be deleted)`);
        } else {
          console.error(`   ❌ Error deleting ${challenge}: ${error.message}`);
        }
      }
    }
    
    // Check if there are any changes to commit
    const status = await git.status();
    
    if (status.deleted.length === 0) {
      console.log('\n⚠️  No changes to commit (challenges may already be deleted)');
      return;
    }
    
    console.log(`\n📝 Committing deletion of ${status.deleted.length} challenge directories...`);
    
    // Commit the deletion
    await git.addConfig('user.name', 'CTF Automation').catch(() => {});
    await git.addConfig('user.email', 'ctf-automation@localhost').catch(() => {});
    
    await git.commit(`Delete all challenges (${challenges.length} challenges removed)`);
    console.log('✅ Changes committed');
    
    // Push to GitHub
    console.log('\n🚀 Pushing changes to GitHub...');
    await git.push('origin', 'main').catch(() => git.push('origin', 'master'));
    console.log('✅ Changes pushed to GitHub');
    
    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('✅ DELETION COMPLETE');
    console.log('='.repeat(60));
    console.log(`\n📊 Summary:`);
    console.log(`   - Challenges deleted: ${challenges.length}`);
    console.log(`   - Files/directories removed: ${status.deleted.length}`);
    console.log(`   - Changes committed and pushed to GitHub`);
    console.log('\n✅ All challenges have been deleted from GitHub!');
    
  } catch (error) {
    console.error('\n❌ Error deleting challenges:', error);
    throw error;
  }
}

// Run the deletion
deleteAllChallenges()
  .then(() => {
    console.log('\n✅ Process completed successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Process failed:', error.message);
    process.exit(1);
  });

