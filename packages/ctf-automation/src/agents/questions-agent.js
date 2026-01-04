import OpenAI from 'openai';
import dotenv from 'dotenv';

dotenv.config();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const SYSTEM_PROMPT = `You are a friendly and knowledgeable CTF (Capture The Flag) and cybersecurity assistant.

**CRITICAL CLASSIFICATION RULES - READ CAREFULLY:**

**STEP 1: CLASSIFY THE USER'S MESSAGE FIRST**

Before responding, classify the message into one of these categories:

1. **CONVERSATIONAL/GREETING** - Simple greetings, casual chat, social pleasantries
   Examples: "hello", "hi", "hey", "how are you", "what's up", "thanks", "bye", "good morning"
   
2. **TECHNICAL QUESTION** - Questions about vulnerabilities, exploits, tools, CTF techniques, cybersecurity concepts
   Examples: "what are xrdp vulnerabilities", "how do I exploit SQL injection", "explain buffer overflow"
   
3. **PLATFORM/GENERAL QUESTION** - Questions about using this platform, what the platform can do, general capabilities
   Examples: "what can you do", "what can this platform do", "how do I create a challenge", "how do I deploy", "what are your capabilities"
   - For "what can you do" type questions: Give a brief overview of platform capabilities (create challenges, deploy, answer questions)
   - Do NOT launch into detailed technical explanations about specific vulnerabilities
   - Do NOT provide step-by-step guides unless specifically asked
   - Keep it concise and focused on platform features

**STEP 2: RESPOND APPROPRIATELY BASED ON CLASSIFICATION**

**FOR CONVERSATIONAL/GREETING MESSAGES:**
- Respond with ONLY 1-2 short, friendly sentences
- Do NOT mention vulnerabilities, exploits, CTF challenges, or technical topics
- Do NOT provide instructions on creating challenges
- Do NOT give examples or detailed explanations
- Just be friendly and ask how you can help
- Examples:
  * User: "hello" → You: "Hello! How can I help you with CTF challenges today?"
  * User: "how are you" → You: "I'm doing well, thanks! Ready to help with CTF challenges. What would you like to know?"
  * User: "thanks" → You: "You're welcome! Anything else I can help with?"

**FOR TECHNICAL QUESTIONS:**
- Provide detailed, educational answers
- Include examples, commands, CVEs, exploitation methods
- Be thorough and helpful

**FOR PLATFORM/GENERAL QUESTIONS:**
- Provide clear, concise overview of platform capabilities
- For "what can you do" questions: List main features briefly (create challenges, deploy challenges, answer questions)
- Do NOT provide detailed technical explanations about vulnerabilities or exploits
- Do NOT give step-by-step guides unless specifically asked
- Keep responses focused on what the platform can do, not how to exploit vulnerabilities
- Examples:
  * "what can you do" → "I can help you create CTF challenges, deploy existing challenges, and answer questions about cybersecurity and CTF techniques. What would you like to do?"
  * "what can this platform do" → "This platform lets you create, deploy, and practice CTF challenges. You can ask me to create challenges, deploy them, or ask questions about cybersecurity."

**ABSOLUTE RULE:**
If the user says "hello", "hi", "hey", "how are you", or any simple greeting, you MUST respond with ONLY a brief friendly greeting (1-2 sentences). DO NOT launch into explanations about creating challenges, vulnerabilities, or any technical topics. Just greet them and ask how you can help.

**OTHER GUIDELINES:**
- **Exact Commands**: When users ask for "exact commands" or "specific commands", you MUST provide commands with the ACTUAL IP addresses, ports, and container names from the deployment information provided. Do NOT use placeholders like "TARGET_IP" or "example.com" - use the real values from the deployment context.

Be encouraging and supportive of their learning journey.`;

/**
 * Extract deployment information from conversation history
 */
function extractDeploymentInfo(conversationHistory) {
  // Look for recent deployment messages (last 20 messages)
  const recentMessages = conversationHistory.slice(-20).reverse();
  
  for (const msg of recentMessages) {
    if (msg.role === 'assistant' && msg.content) {
      // Try to extract deployment info from assistant messages
      // Look for patterns like "IP:PORT", "attackerIP", "victimIP", etc.
      
      // Check if message contains deployment info
      const ipPattern = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
      const ips = msg.content.match(ipPattern);
      
      // Look for container names
      const containerPattern = /ctf-([a-z0-9\-]+)-(attacker|victim)/i;
      const containerMatch = msg.content.match(containerPattern);
      
      // Look for challenge name
      const challengePattern = /Challenge\s+"([a-z0-9\-]+)"\s+deployed/i;
      const challengeMatch = msg.content.match(challengePattern);
      
      if (ips && ips.length > 0) {
        const deploymentInfo = {
          challengeName: challengeMatch ? challengeMatch[1] : null,
          attackerIP: ips.find(ip => ip.endsWith('.3')) || ips[0], // Attacker is usually .3
          victimIP: ips.find(ip => !ip.endsWith('.3') && !ip.endsWith('.1')) || ips[ips.length - 1],
          containerName: containerMatch ? containerMatch[0] : null,
          allIPs: ips
        };
        
        // Also check metadata if available
        if (msg.metadata && msg.metadata.deployment) {
          deploymentInfo.attackerIP = msg.metadata.deployment.attackerIP || deploymentInfo.attackerIP;
          deploymentInfo.victimIP = msg.metadata.deployment.victimIP || deploymentInfo.victimIP;
          deploymentInfo.challengeName = msg.metadata.deployment.challengeName || deploymentInfo.challengeName;
        }
        
        return deploymentInfo;
      }
    }
  }
  
  return null;
}

export async function answerQuestion(userMessage, conversationHistory = []) {
  try {
    console.log('Answering general question...');
    
    // Check if user is asking for exact commands
    const wantsExactCommands = /exact|specific|actual|real|give me the|show me the|what is the/i.test(userMessage);
    
    // Extract deployment info if available
    const deploymentInfo = extractDeploymentInfo(conversationHistory);
    
    // Build enhanced system prompt - AI will classify the question type itself
    let enhancedSystemPrompt = SYSTEM_PROMPT;
    
    // Add explicit instruction for greetings and general questions at the top
    const messageLower = userMessage.trim().toLowerCase();
    const isGreeting = /^(hello|hi|hey|greetings|good (morning|afternoon|evening)|what's up|sup|how are you|how's it going|how do you do|what's going on|nice to meet you)\s*[!?.]*$/i.test(messageLower);
    const isGeneralQuestion = /^(what can you do|what can this platform do|what are your capabilities|what do you do|how can you help|what features|what are the features)\s*[!?.]*$/i.test(messageLower);
    
    if (isGreeting) {
      enhancedSystemPrompt = `**CRITICAL: THIS IS A SIMPLE GREETING. RESPOND WITH ONLY 1-2 FRIENDLY SENTENCES. DO NOT MENTION VULNERABILITIES, EXPLOITS, CTF CHALLENGES, OR ANY TECHNICAL TOPICS. JUST GREET THEM AND ASK HOW YOU CAN HELP.**

Example responses:
- "hello" → "Hello! How can I help you with CTF challenges today?"
- "how are you" → "I'm doing well, thanks! Ready to help with CTF challenges. What would you like to know?"

${SYSTEM_PROMPT}`;
    } else if (isGeneralQuestion) {
      enhancedSystemPrompt = `**CRITICAL: THIS IS A GENERAL QUESTION ABOUT PLATFORM CAPABILITIES. RESPOND WITH A BRIEF OVERVIEW (2-3 SENTENCES) OF WHAT THE PLATFORM CAN DO. DO NOT PROVIDE DETAILED TECHNICAL EXPLANATIONS ABOUT VULNERABILITIES, EXPLOITS, OR STEP-BY-STEP GUIDES. JUST LIST THE MAIN FEATURES BRIEFLY.**

Example response:
- "what can you do" → "I can help you create CTF challenges, deploy existing challenges, and answer questions about cybersecurity and CTF techniques. What would you like to do?"

${SYSTEM_PROMPT}`;
    }
    
    if (deploymentInfo && wantsExactCommands) {
      enhancedSystemPrompt += `\n\n**DEPLOYMENT CONTEXT (USE THESE EXACT VALUES):**
- Challenge Name: ${deploymentInfo.challengeName || 'unknown'}
- Attacker IP: ${deploymentInfo.attackerIP}
- Victim IP: ${deploymentInfo.victimIP}
- Container Name: ${deploymentInfo.containerName || 'ctf-' + (deploymentInfo.challengeName || 'challenge') + '-attacker'}
- All IPs in network: ${deploymentInfo.allIPs.join(', ')}

When providing commands, use these EXACT values. For example:
- Instead of "nmap TARGET_IP", use "nmap ${deploymentInfo.victimIP}"
- Instead of "hydra -l admin -P passwords.txt ftp://TARGET", use "hydra -l admin -P passwords.txt ftp://${deploymentInfo.victimIP}"
- Instead of "curl http://example.com", use "curl http://${deploymentInfo.victimIP}:8080"

Always provide the complete, ready-to-run command with actual IPs and ports.`;
    }

    // Build messages array with conversation history
    const messages = [
      { role: 'system', content: enhancedSystemPrompt }
    ];

    // For greetings and general questions, don't include conversation history to avoid technical context bleeding in
    // For technical questions, include recent history for context
    if (!isGreeting && !isGeneralQuestion) {
      // Add conversation history (limited to last 10 messages to manage token usage)
      const recentHistory = conversationHistory.slice(-10);
      messages.push(...recentHistory);
    }

    // Add current user message
    messages.push({ role: 'user', content: userMessage });

    // Adjust parameters based on question type
    const temperature = (isGreeting || isGeneralQuestion) ? 0.9 : 0.7; // Higher temperature for more natural conversational responses
    const maxTokens = isGreeting ? 100 : (isGeneralQuestion ? 200 : 2000); // Limit tokens for greetings/general questions to force brevity
    
    const completion = await openai.chat.completions.create({
      model: process.env.OPENAI_MODEL || 'gpt-4',
      messages,
      temperature,
      max_tokens: maxTokens
    });

    const answer = completion.choices[0].message.content.trim();

    // Check if answer is conversational (short, friendly) vs technical (long, detailed)
    // AI will have already classified and responded appropriately
    const isConversationalResponse = answer.length < 200 && !answer.includes('CVE') && !answer.includes('exploit') && !answer.includes('vulnerability');
    
    return {
      success: true,
      answer,
      // Only show additional help for technical questions (longer responses)
      additionalHelp: isConversationalResponse ? undefined : 'You can also:\n- Create a new challenge: "Create a web challenge about SQL injection"\n- Deploy a challenge: "Deploy challenge-name"\n- Get challenge info: "Tell me about challenge-name"',
      deploymentInfo: deploymentInfo || undefined // Include deployment info if available
    };

  } catch (error) {
    console.error('Error answering question:', error);
    return {
      success: false,
      error: 'Failed to answer question',
      details: error.message,
      fallback: 'I apologize, but I encountered an error. Please try rephrasing your question.'
    };
  }
}
