/**
 * ChatGPT Service
 * Simple integration for CTF challenge generation
 * 
 * To connect to real ChatGPT:
 * 1. Add your API key to the OPENAI_API_KEY constant below
 * 2. The sendMessage function will automatically use the real API
 */

// TODO: Replace with your actual OpenAI API key
const OPENAI_API_KEY = 'YOUR_API_KEY_HERE';
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

interface ChatMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface ChatGPTResponse {
  choices: {
    message: {
      content: string;
    };
  }[];
}

/**
 * Send a message to ChatGPT and get a response
 * @param userMessage - The user's message
 * @param conversationHistory - Previous messages in the conversation (optional)
 * @returns ChatGPT's response
 */
export async function sendMessageToChatGPT(
  userMessage: string,
  conversationHistory: ChatMessage[] = []
): Promise<string> {
  // If API key is not configured, return mock response
  if (OPENAI_API_KEY === 'YOUR_API_KEY_HERE' || !OPENAI_API_KEY) {
    console.log('Using mock mode - configure OPENAI_API_KEY to use real ChatGPT');
    return getMockResponse(userMessage);
  }

  try {
    // Build the messages array with system prompt
    const messages: ChatMessage[] = [
      {
        role: 'system',
        content: `You are an expert CTF (Capture The Flag) challenge creator for cybersecurity education. 
Your role is to help users create realistic, educational cybersecurity challenges.

When a user asks you to create a challenge:
1. Confirm you understand their request
2. Ask any clarifying questions if needed
3. Generate a complete challenge including:
   - Title
   - Description
   - Category (Web Exploitation, Cryptography, Reverse Engineering, Forensics, Binary Exploitation, OSINT)
   - Difficulty (Beginner, Intermediate, Advanced)
   - Hints
   - Solution approach

Be conversational, friendly, and educational. Help users learn while creating challenges.`
      },
      ...conversationHistory,
      {
        role: 'user',
        content: userMessage
      }
    ];

    // Call OpenAI API
    const response = await fetch(OPENAI_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini', // Using the faster, cheaper model. Change to 'gpt-4' for better quality
        messages: messages,
        temperature: 0.7,
        max_tokens: 1000
      })
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error?.message || `API Error: ${response.status}`);
    }

    const data: ChatGPTResponse = await response.json();
    return data.choices[0]?.message?.content || 'No response generated';

  } catch (error) {
    console.error('ChatGPT API Error:', error);
    throw error;
  }
}

/**
 * Mock response for testing without API key
 */
function getMockResponse(userMessage: string): string {
  const lowerMessage = userMessage.toLowerCase();

  // Initial greeting
  if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
    return "Hello! I'm ready to help you create CTF challenges. What kind of challenge would you like to build today?";
  }

  // Parse request for challenge creation
  let category = '';
  let difficulty = '';

  if (lowerMessage.includes('web') || lowerMessage.includes('sql') || lowerMessage.includes('xss')) {
    category = 'Web Exploitation';
  } else if (lowerMessage.includes('crypto') || lowerMessage.includes('cipher')) {
    category = 'Cryptography';
  } else if (lowerMessage.includes('reverse')) {
    category = 'Reverse Engineering';
  } else if (lowerMessage.includes('forensic')) {
    category = 'Forensics';
  } else if (lowerMessage.includes('pwn') || lowerMessage.includes('buffer')) {
    category = 'Binary Exploitation';
  } else if (lowerMessage.includes('osint')) {
    category = 'OSINT';
  }

  if (lowerMessage.includes('beginner') || lowerMessage.includes('easy')) {
    difficulty = 'Beginner';
  } else if (lowerMessage.includes('intermediate') || lowerMessage.includes('medium')) {
    difficulty = 'Intermediate';
  } else if (lowerMessage.includes('advanced') || lowerMessage.includes('hard')) {
    difficulty = 'Advanced';
  }

  // If we detected a challenge request
  if (category && difficulty) {
    return `Great! I'll help you create a ${difficulty.toLowerCase()} level ${category} challenge.

I'm thinking of a challenge called "${getChallengeTitle(category)}" that would be perfect for your needs.

The challenge will involve ${getChallengeDescription(category)} and should take approximately ${getEstimatedTime(difficulty)} to complete.

Would you like me to proceed with generating the complete challenge including the Docker environment and deployment configuration?`;
  }

  // Generic response if unclear
  return "I'd be happy to help you create a CTF challenge! Please specify:\n\n1. Challenge category (Web, Crypto, Reverse Engineering, Forensics, Binary, OSINT)\n2. Difficulty level (Beginner, Intermediate, Advanced)\n\nFor example: 'Create a beginner web exploitation challenge'";
}

function getChallengeTitle(category: string): string {
  const titles: Record<string, string> = {
    'Web Exploitation': 'SQL Injection Login Bypass',
    'Cryptography': 'Caesar Cipher Decoder',
    'Reverse Engineering': 'Password Checker Analysis',
    'Forensics': 'Hidden Message Hunt',
    'Binary Exploitation': 'Buffer Overflow Challenge',
    'OSINT': 'Digital Footprint Investigation'
  };
  return titles[category] || 'Custom Challenge';
}

function getChallengeDescription(category: string): string {
  const descriptions: Record<string, string> = {
    'Web Exploitation': 'exploiting a vulnerable login form to bypass authentication',
    'Cryptography': 'decrypting a message using classical cipher techniques',
    'Reverse Engineering': 'analyzing a binary to extract hidden credentials',
    'Forensics': 'examining files to uncover hidden data',
    'Binary Exploitation': 'exploiting memory corruption vulnerabilities',
    'OSINT': 'gathering intelligence from publicly available sources'
  };
  return descriptions[category] || 'solving a security challenge';
}

function getEstimatedTime(difficulty: string): string {
  const times: Record<string, string> = {
    'Beginner': '10-20 minutes',
    'Intermediate': '20-40 minutes',
    'Advanced': '40-90 minutes'
  };
  return times[difficulty] || '30 minutes';
}

/**
 * Check if ChatGPT API is properly configured
 */
export function isChatGPTConfigured(): boolean {
  return OPENAI_API_KEY !== 'YOUR_API_KEY_HERE' && OPENAI_API_KEY.length > 0;
}
