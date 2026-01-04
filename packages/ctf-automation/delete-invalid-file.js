import { Octokit } from 'octokit';
import dotenv from 'dotenv';

dotenv.config();

const octokit = new Octokit({
  auth: process.env.GITHUB_TOKEN
});

const owner = process.env.GITHUB_OWNER || 'Ahmed-CYB';
const repo = process.env.GITHUB_REPO || 'mcp-test';

async function deleteInvalidFile() {
  try {
    console.log('Attempting to delete "hello world " file...');
    
    // Get file SHA
    const { data } = await octokit.request('GET /repos/{owner}/{repo}/contents/{path}', {
      owner,
      repo,
      path: 'hello world '
    });
    
    console.log('Found file, deleting...');
    
    // Delete the file
    await octokit.request('DELETE /repos/{owner}/{repo}/contents/{path}', {
      owner,
      repo,
      path: 'hello world ',
      message: 'Remove invalid filename (trailing space - Windows incompatible)',
      sha: data.sha
    });
    
    console.log('✅ Successfully deleted "hello world " file');
  } catch (error) {
    console.error('Error:', error.message);
  }
}

deleteInvalidFile();
