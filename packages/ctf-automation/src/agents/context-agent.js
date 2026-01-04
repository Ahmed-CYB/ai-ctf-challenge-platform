/**
 * Context Agent - AI-powered context extraction from conversation history
 * 
 * This agent uses AI to understand user intent and extract challenge names
 * from conversation context, even when not explicitly mentioned.
 */

import Anthropic from '@anthropic-ai/sdk';
import dotenv from 'dotenv';

dotenv.config();

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY
});

const SYSTEM_PROMPT = `You are a Context Extraction Agent for a CTF (Capture The Flag) challenge platform.

Your job is to analyze conversation history and extract:
1. The challenge name that the user is referring to (even if not explicitly mentioned)
2. The user's intent (create, deploy, run, etc.)
3. Any missing context needed to fulfill the request

**IMPORTANT RULES:**
- When user says "deploy", "run", "start", "launch", or similar commands without a challenge name, look in the conversation history for the MOST RECENT challenge that was created
- "run" and "deploy" mean the same thing - both mean to deploy/start a challenge
- Challenge names are typically in kebab-case format (e.g., "corporate-ftp-breach", "eternalblue-samba-exploit")
- **CRITICAL**: If multiple challenges exist in history, ALWAYS use the MOST RECENT one (the last one mentioned/created)
- Scan conversation history from MOST RECENT to OLDEST, and return the FIRST challenge name you find
- If user explicitly mentions a challenge name, use that instead of context
- Commands like "deploy it", "run it", "start it", "deploy", "run" refer to the last created challenge
- Commands like "deploy corporate-ftp-breach" or "run corporate-ftp-breach" already have the name, so return it as-is
- Look for patterns like "Challenge 'name' created successfully" or "Challenge 'name' pushed" - these indicate the most recent challenge

**OUTPUT FORMAT:**
Return a JSON object with:
{
  "challengeName": "the-challenge-name" or null if not found,
  "intent": "create" | "deploy" | "run" | "question" | "unknown",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation of how you determined this"
}

**EXAMPLES:**

Conversation:
- User: "create ctf challenge ftp"
- Assistant: "✅ Challenge 'corporate-ftp-breach' created successfully!"
- User: "deploy it"

Your response:
{
  "challengeName": "corporate-ftp-breach",
  "intent": "deploy",
  "confidence": 0.95,
  "reasoning": "User said 'deploy it' after challenge 'corporate-ftp-breach' was created, so 'it' refers to that challenge"
}

Conversation:
- User: "create ctf challenge ftp"
- Assistant: "✅ Challenge 'corporate-ftp-breach' created successfully!"
- User: "run corporate-ftp-breach"

Your response:
{
  "challengeName": "corporate-ftp-breach",
  "intent": "deploy",
  "confidence": 1.0,
  "reasoning": "User explicitly mentioned the challenge name 'corporate-ftp-breach'"
}

Conversation:
- User: "deploy"

Your response:
{
  "challengeName": null,
  "intent": "deploy",
  "confidence": 0.3,
  "reasoning": "User wants to deploy but no challenge name found in conversation history"
}`;

export class ContextAgent {
  constructor() {
    this.model = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-20250514';
  }

  /**
   * Extract challenge name and intent from conversation context
   * @param {string} currentMessage - The current user message
   * @param {Array} conversationHistory - Array of previous messages [{role, content}, ...]
   * @returns {Promise<object>} Extracted context with challengeName and intent
   */
  async extractContext(currentMessage, conversationHistory = []) {
    try {
      // Build conversation context for AI
      const conversationText = this.buildConversationText(conversationHistory, currentMessage);

      const response = await anthropic.messages.create({
        model: this.model,
        max_tokens: 500,
        system: SYSTEM_PROMPT,
        messages: [
          {
            role: 'user',
            content: `Analyze this conversation and extract the challenge name and intent:

${conversationText}

Current user message: "${currentMessage}"

Extract the challenge name (if any) and user intent. Return JSON only.`
          }
        ]
      });

      // Parse AI response
      const content = response.content[0];
      if (content.type === 'text') {
        const text = content.text.trim();
        
        // Extract JSON from response (handle markdown code blocks)
        let jsonText = text;
        const jsonMatch = text.match(/```(?:json)?\s*(\{[\s\S]*\})\s*```/);
        if (jsonMatch) {
          jsonText = jsonMatch[1];
        } else {
          // Try to find JSON object in text
          const braceMatch = text.match(/\{[\s\S]*\}/);
          if (braceMatch) {
            jsonText = braceMatch[0];
          }
        }

        const context = JSON.parse(jsonText);
        return {
          challengeName: context.challengeName || null,
          intent: context.intent || 'unknown',
          confidence: context.confidence || 0.5,
          reasoning: context.reasoning || 'No reasoning provided'
        };
      }

      // Fallback
      return {
        challengeName: null,
        intent: 'unknown',
        confidence: 0.0,
        reasoning: 'Failed to parse AI response'
      };
    } catch (error) {
      console.error('[ContextAgent] Error extracting context:', error.message);
      
      // Fallback: try to extract challenge name from conversation history manually
      const fallbackName = this.extractChallengeNameFromHistory(conversationHistory);
      
      return {
        challengeName: fallbackName,
        intent: this.guessIntent(currentMessage),
        confidence: fallbackName ? 0.6 : 0.3,
        reasoning: 'Using fallback extraction method'
      };
    }
  }

  /**
   * Build conversation text from history
   */
  buildConversationText(history, currentMessage) {
    if (!history || history.length === 0) {
      return `No previous conversation. Current message: "${currentMessage}"`;
    }

    const lines = history.map(msg => {
      const role = msg.role === 'user' ? 'User' : 'Assistant';
      const content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
      return `${role}: ${content}`;
    });

    return lines.join('\n');
  }

  /**
   * Fallback: Extract challenge name from conversation history manually
   * Prioritizes the MOST RECENT challenge created
   */
  extractChallengeNameFromHistory(conversationHistory) {
    if (!conversationHistory || conversationHistory.length === 0) {
      return null;
    }

    // Look for challenge names in assistant responses (most recent first)
    // This ensures we get the latest challenge when user says "deploy it"
    for (let i = conversationHistory.length - 1; i >= 0; i--) {
      const msg = conversationHistory[i];
      if (msg.role === 'assistant') {
        const content = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content);
        
        // Priority patterns (most specific first, most recent wins)
        // Pattern 1: "Challenge 'name' created successfully" or "Challenge 'name' pushed"
        const createdPattern = /Challenge\s+['"]([a-z0-9-]+)['"]\s+(?:created|pushed|saved)/i;
        const createdMatch = content.match(createdPattern);
        if (createdMatch && createdMatch[1]) {
          return createdMatch[1];
        }
        
        // Pattern 2: "challengeName": "name" in JSON
        const jsonPattern = /challengeName['"]?\s*:\s*['"]([a-z0-9-]+)['"]/i;
        const jsonMatch = content.match(jsonPattern);
        if (jsonMatch && jsonMatch[1]) {
          return jsonMatch[1];
        }
        
        // Pattern 3: "name": "challenge-name" in JSON (from challenge data)
        const namePattern = /"name"\s*:\s*['"]([a-z0-9-]+)['"]/i;
        const nameMatch = content.match(namePattern);
        if (nameMatch && nameMatch[1]) {
          return nameMatch[1];
        }
        
        // Pattern 4: Any kebab-case challenge name (generic, but only if no specific pattern matched)
        // This is a fallback for edge cases
        const genericPattern = /\b([a-z0-9]+(?:-[a-z0-9]+){2,})\b/i;
        const genericMatch = content.match(genericPattern);
        if (genericMatch && genericMatch[1]) {
          // Validate it looks like a challenge name (at least 2 hyphens, reasonable length)
          const candidate = genericMatch[1];
          if (candidate.length >= 10 && candidate.split('-').length >= 2) {
            return candidate;
          }
        }
      }
    }

    return null;
  }

  /**
   * Fallback: Guess intent from message
   */
  guessIntent(message) {
    const msg = message.toLowerCase().trim();
    if (msg.includes('create') || msg.includes('make') || msg.includes('generate')) {
      return 'create';
    }
    // "run" and "deploy" are synonyms - both mean deploy/start
    if (msg.includes('deploy') || msg.includes('run') || msg.includes('start') || msg.includes('launch')) {
      return 'deploy';
    }
    if (msg.includes('question') || msg.includes('ask') || msg.includes('what') || msg.includes('how')) {
      return 'question';
    }
    return 'unknown';
  }
}

export const contextAgent = new ContextAgent();

