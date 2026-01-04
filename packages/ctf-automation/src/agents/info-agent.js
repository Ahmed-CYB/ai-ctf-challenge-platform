import OpenAI from 'openai';
import { gitManager } from '../git-manager.js';
import dotenv from 'dotenv';

dotenv.config();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const SYSTEM_PROMPT = `You are a CTF challenge information assistant. When a user asks about a specific challenge, provide detailed information including:
- Challenge description
- Difficulty level
- Category
- Hints (without revealing the flag)
- Learning objectives
- Tips for solving
- Flag format (e.g., "CTF{...}" or "flag{...}") but NEVER the actual flag content

CRITICAL RULES:
- NEVER reveal the actual flag value
- NEVER mention the flag location/path
- Only mention the flag format (e.g., "The flag follows the format: CTF{...}")
- Focus on the challenge methodology and learning objectives

Be helpful and educational, but don't give away the solution directly. Encourage learning and problem-solving.`;

export async function getChallengeInfo(userMessage, conversationHistory = []) {
  try {
    console.log('Getting challenge information...');

    // Extract challenge name from message or conversation history
    let challengeName = extractChallengeName(userMessage);
    
    // Check conversation history if not found
    if (!challengeName && conversationHistory.length > 0) {
      console.log('Searching conversation history for challenge context...');
      
      const recentMessages = conversationHistory.slice(-10).reverse();
      
      for (const msg of recentMessages) {
        // Look for recently created or deployed challenges
        if (msg.role === 'assistant' && msg.content) {
          const creationMatch = msg.content.match(/Challenge\s+"([a-z0-9\-]+)"\s+(created|deployed)\s+successfully/i) ||
                               msg.content.match(/challengeName["\s:]+([a-z0-9\-]+)/i) ||
                               msg.content.match(/"name"\s*:\s*"([a-z0-9\-]+)"/i);
          
          if (creationMatch && creationMatch[1]) {
            challengeName = creationMatch[1];
            console.log(`Found challenge in conversation: ${challengeName}`);
            break;
          }
        }
        
        if (msg.role === 'user') {
          const extractedName = extractChallengeName(msg.content);
          if (extractedName && extractedName !== 'it' && extractedName !== 'that') {
            challengeName = extractedName;
            console.log(`Found challenge name in user message: ${challengeName}`);
            break;
          }
        }
      }
    }
    
    if (!challengeName) {
      const challenges = await gitManager.listChallenges();
      return {
        success: false,
        message: 'Please specify which challenge you want to know about.',
        availableChallenges: challenges
      };
    }

    // Get challenge metadata
    await gitManager.ensureRepository();
    const metadata = await gitManager.getChallengeMetadata(challengeName);

    if (!metadata) {
      const challenges = await gitManager.listChallenges();
      return {
        success: false,
        message: `Challenge "${challengeName}" not found.`,
        availableChallenges: challenges
      };
    }

    // Prepare metadata WITHOUT flag value - only show format
    const safeMetadata = {
      title: metadata.title,
      description: metadata.description,
      difficulty: metadata.difficulty,
      category: metadata.category,
      hints: metadata.hints,
      flagFormat: metadata.flag ? `${metadata.flag.substring(0, metadata.flag.indexOf('{') + 1)}...}` : 'CTF{...}'
    };

    // Use OpenAI to generate a helpful explanation
    const messages = [
      { role: 'system', content: SYSTEM_PROMPT }
    ];
    
    // Add recent conversation history
    const recentHistory = conversationHistory.slice(-5);
    messages.push(...recentHistory);
    
    // Add current question with SAFE metadata (no flag value)
    messages.push({ 
      role: 'user', 
      content: `Tell me about the CTF challenge "${metadata.title}". Here's the metadata (flag value hidden for security): ${JSON.stringify(safeMetadata, null, 2)}`
    });

    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4',
      messages,
      temperature: 0.7,
      max_tokens: 1000
    });

    const explanation = completion.choices[0].message.content.trim();

    return {
      success: true,
      challenge: {
        name: challengeName,
        title: metadata.title,
        description: metadata.description,
        difficulty: metadata.difficulty,
        category: metadata.category,
        hints: metadata.hints,
        flagFormat: metadata.flag ? `${metadata.flag.substring(0, metadata.flag.indexOf('{') + 1)}...}` : 'CTF{...}'
      },
      explanation,
      deployCommand: `To deploy this challenge, say: "Deploy ${challengeName}"`
    };

  } catch (error) {
    console.error('Error getting challenge info:', error);
    return {
      success: false,
      error: 'Failed to get challenge information',
      details: error.message
    };
  }
}

function extractChallengeName(message) {
  // Try to extract challenge name from various message formats
  const patterns = [
    /about\s+([a-z0-9\-]+)/i,
    /what\s+is\s+([a-z0-9\-]+)/i,
    /tell\s+me\s+about\s+([a-z0-9\-]+)/i,
    /explain\s+([a-z0-9\-]+)/i,
    /info\s+([a-z0-9\-]+)/i,
    /([a-z0-9\-]+)/i
  ];

  for (const pattern of patterns) {
    const match = message.match(pattern);
    if (match && match[1]) {
      const name = match[1].toLowerCase();
      const excludeWords = ['the', 'a', 'an', 'this', 'that', 'please', 'can', 'you', 'it', 'challenge'];
      if (!excludeWords.includes(name)) {
        return name;
      }
    }
  }

  return null;
}
