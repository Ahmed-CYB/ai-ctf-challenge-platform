import { gitManager } from '../git-manager.js';

export async function getExistingChallenges() {
  try {
    console.log('Retrieving existing challenges...');

    await gitManager.ensureRepository();
    const challengeNames = await gitManager.listChallenges();

    const challenges = [];

    for (const name of challengeNames) {
      const metadata = await gitManager.getChallengeMetadata(name);
      if (metadata) {
        challenges.push({
          name,
          title: metadata.title,
          description: metadata.description,
          difficulty: metadata.difficulty,
          category: metadata.category,
          hints: metadata.hints?.length || 0
        });
      } else {
        // Challenge without metadata
        challenges.push({
          name,
          title: name,
          description: 'No description available',
          difficulty: 'unknown',
          category: 'unknown',
          hints: 0
        });
      }
    }

    console.log(`Found ${challenges.length} challenges`);

    return {
      success: true,
      count: challenges.length,
      challenges
    };

  } catch (error) {
    console.error('Error retrieving challenges:', error);
    return {
      success: false,
      error: 'Failed to retrieve challenges',
      details: error.message
    };
  }
}
