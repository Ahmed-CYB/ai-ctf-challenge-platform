/**
 * Confirmation Agent - Uses OpenAI to classify user responses as confirmation/denial/other
 */

import OpenAI from 'openai';
import dotenv from 'dotenv';
import { Logger } from '../core/logger.js';

dotenv.config();

const logger = new Logger();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const CONFIRMATION_SYSTEM_PROMPT = `You are a confirmation classifier. Your job is to determine if a user's message is:
1. **CONFIRMATION** - User agrees/proceeds (yes, confirm, proceed, go ahead, ok, sure, yep, yeah, do it, deploy, continue)
2. **DENIAL** - User declines/cancels (no, cancel, stop, don't, abort, nevermind, nope, nah)
3. **OTHER** - User is asking a question, making a statement, or saying something unrelated

Examples:
- "yes" → CONFIRMATION
- "confirm" → CONFIRMATION
- "proceed" → CONFIRMATION
- "go ahead" → CONFIRMATION
- "ok" → CONFIRMATION
- "sure" → CONFIRMATION
- "deploy it" → CONFIRMATION
- "no" → DENIAL
- "cancel" → DENIAL
- "stop" → DENIAL
- "don't do it" → DENIAL
- "what happens if I deploy?" → OTHER
- "tell me more" → OTHER
- "how long will it take?" → OTHER

Respond ONLY with valid JSON:
{
  "classification": "CONFIRMATION|DENIAL|OTHER",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation"
}`;

/**
 * Classify user response as confirmation, denial, or other
 */
export async function classifyConfirmation(userMessage) {
  if (!userMessage || typeof userMessage !== 'string' || userMessage.trim().length === 0) {
    return {
      classification: 'OTHER',
      confidence: 0.5,
      reasoning: 'Empty or invalid message'
    };
  }

  const maxRetries = 3;
  let lastError = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await openai.chat.completions.create({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [
          {
            role: 'system',
            content: CONFIRMATION_SYSTEM_PROMPT
          },
          {
            role: 'user',
            content: userMessage
          }
        ],
        response_format: { type: 'json_object' },
        temperature: 0.3,
        max_tokens: 150
      });

      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error('Empty response from OpenAI');
      }

      const result = JSON.parse(content);
      
      // Validate result
      if (!result.classification || !['CONFIRMATION', 'DENIAL', 'OTHER'].includes(result.classification)) {
        throw new Error('Invalid classification result');
      }

      logger.info('ConfirmationAgent', 'Classification result', {
        classification: result.classification,
        confidence: result.confidence,
        message: userMessage.substring(0, 50)
      });

      return {
        classification: result.classification,
        confidence: result.confidence || 0.8,
        reasoning: result.reasoning || 'No reasoning provided'
      };

    } catch (error) {
      lastError = error;
      logger.warn('ConfirmationAgent', `Classification attempt ${attempt}/${maxRetries} failed`, {
        error: error.message
      });

      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  // Fallback: Simple keyword matching
  logger.warn('ConfirmationAgent', 'All attempts failed, using fallback keyword matching');
  const messageLower = userMessage.toLowerCase().trim();
  
  const confirmationKeywords = ['yes', 'y', 'confirm', 'proceed', 'go ahead', 'ok', 'okay', 'sure', 'yep', 'yeah', 'do it', 'deploy', 'continue'];
  const denialKeywords = ['no', 'n', 'cancel', 'stop', "don't", 'dont', 'abort', 'nevermind', 'never mind', 'nope', 'nah'];
  
  if (confirmationKeywords.some(keyword => messageLower.includes(keyword))) {
    return {
      classification: 'CONFIRMATION',
      confidence: 0.7,
      reasoning: 'Keyword match (fallback)'
    };
  }
  
  if (denialKeywords.some(keyword => messageLower.includes(keyword))) {
    return {
      classification: 'DENIAL',
      confidence: 0.7,
      reasoning: 'Keyword match (fallback)'
    };
  }
  
  return {
    classification: 'OTHER',
    confidence: 0.5,
    reasoning: 'Fallback: no clear confirmation or denial detected'
  };
}

