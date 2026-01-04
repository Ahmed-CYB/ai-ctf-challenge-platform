import { createUniversalChallenge } from './agents/universal-structure-agent.js';
import { deployChallenge } from './agents/deploy-agent.js';

async function testChallengeCreation() {
  console.log('ðŸ§ª Testing challenge creation...');
  
  const userMessage = 'create ftp ctf challenge for testing';
  const sessionId = 'test-session-' + Date.now();
  
  try {
    // Step 1: Create challenge
    console.log('ðŸ“ Step 1: Creating challenge...');
    const createResult = await createUniversalChallenge(
      userMessage,
      [],
      (progress) => console.log('Progress:', progress)
    );
    
    console.log('âœ… Challenge created:', createResult.challengeName);
    
    // Step 2: Deploy challenge
    console.log('ðŸš€ Step 2: Deploying challenge...');
    const deployResult = await deployChallenge(
      `deploy ${createResult.challengeName}`,
      [],
      sessionId
    );
    
    console.log('âœ… Challenge deployed:', deployResult);
    
    return { success: true, createResult, deployResult };
  } catch (error) {
    console.error('âŒ Test failed:', error);
    return { success: false, error: error.message };
  }
}

testChallengeCreation();
