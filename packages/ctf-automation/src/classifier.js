import OpenAI from 'openai';
import dotenv from 'dotenv';

dotenv.config();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const SYSTEM_PROMPT = `You are a CTF request classifier. Analyze the user's message and categorize it into one of these categories:

- Create: User wants to create a NEW CTF challenge. Keywords: "create", "make", "generate", "new challenge", "build a challenge", "provide", "give me", "practice range", "practice environment", "setup", "set up", "create for me", "create an environment", "create a challenge"
  CRITICAL: If the message contains "create" + ("environment" OR "challenge" OR "practice" OR "for me"), it MUST be classified as Create, NOT Question.
  IMPORTANT: If user asks to "provide", "give me", "create for me", or wants a "practice range/environment" for a tool, this is a CREATE request, not Deploy or Question.
- Deploy: User wants to deploy an EXISTING challenge from the repository. Keywords: "deploy [challenge-name]", "run [challenge-name]", "start [challenge-name]", "launch [challenge-name]", "spin up [challenge-name]"
  IMPORTANT: Deploy requests MUST include a specific challenge name. If no challenge name is mentioned, it's likely a Create request.
- ChallengeInfo: User wants information about a SPECIFIC challenge. Keywords: "what is", "how does", "explain", "tell me about [challenge name]"
- Question: User has a GENERAL question about CTFs, cybersecurity, or the platform. Keywords: "what are", "how to", "explain", "teach me", "hello", "hi", "hey", greetings
  CRITICAL: If the message contains "create" + ("environment" OR "challenge" OR "practice" OR "for me"), it MUST be classified as Create, NOT Question.
  IMPORTANT: Simple greetings like "hello", "hi", "hey" should be classified as Question (they're conversational, not action requests).

Respond ONLY with valid JSON in this exact format:
{
  "category": "Create|Deploy|ChallengeInfo|Question",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation",
  "challengeTypes": ["web", "network", "crypto"],  // ARRAY of types, challenges can have multiple categories
  "challengeType": "primary_type",  // Main type (backward compatibility)
  "requiredTools": ["tool1", "tool2", "..."]  // Include ALL tools needed, including basics
}

For challengeType, detect from context:
- web: SQL injection, XSS, web vulnerabilities, web servers
- network: port scanning, packet analysis, network traffic
- pwn: buffer overflow, binary exploitation, reverse engineering
- crypto: encryption, decryption, hashing, cryptography
- misc: general security, social engineering, OSINT

For requiredTools, extract specific tools mentioned or inferred:
**IMPORTANT**: ALWAYS include basic tools for each category!
- Web: burpsuite, sqlmap, nikto, gobuster, dirb, wfuzz, ffuf + curl, wget, python3
- Network: nmap, wireshark, tcpdump, netcat, hping3, masscan + ssh, nc, net-tools, iputils-ping
- Pwn: gdb, pwntools, ghidra, radare2, objdump, ltrace, strace + python3, gcc
- Crypto: hashcat, john, openssl, cyberchef + python3, openssl
- Common (ALWAYS): python3, curl, wget, git, vim, nano, bash, ssh`;

export async function classify(message, conversationHistory = []) {
  const maxRetries = 3;
  let lastError = null;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Build context from conversation history if available
      let contextMessage = message;
      if (conversationHistory && conversationHistory.length > 0) {
        // Check if message is a confirmation/continuation
        const messageLower = message.toLowerCase().trim();
        const isConfirmation = messageLower === 'yes' || 
                              messageLower === 'y' ||
                              messageLower.includes('yes please') ||
                              messageLower.includes('create that') ||
                              messageLower.includes('do that') ||
                              messageLower.includes('make that');
        
        if (isConfirmation) {
          // Look for previous challenge request in history
          const recentHistory = conversationHistory.slice(-5).reverse();
          for (const msg of recentHistory) {
            if (msg.role === 'user' && msg.content) {
              const contentLower = msg.content.toLowerCase();
              if (contentLower.includes('create') || 
                  contentLower.includes('make') || 
                  contentLower.includes('generate') ||
                  contentLower.includes('ftp') ||
                  contentLower.includes('challenge')) {
                contextMessage = `${message}\n\nContext from previous message: ${msg.content}`;
                console.log('📝 Using context from conversation history for classification');
                break;
              }
            }
          }
        }
      }
      
      const completion = await openai.chat.completions.create({
        model: process.env.OPENAI_MODEL || 'gpt-4',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: contextMessage }
        ],
        temperature: 0.3,
        max_tokens: 200, // Increased to avoid truncation
        response_format: { type: "json_object" } // Force JSON mode if supported
      });

      let responseText = completion.choices[0].message.content.trim();
      
      // Remove markdown code blocks if present
      const TRIPLE_BACKTICK = String.fromCharCode(96, 96, 96);
      if (responseText.startsWith(TRIPLE_BACKTICK)) {
        const lines = responseText.split('\n');
        lines.shift(); // Remove first line
        const lastLine = lines[lines.length - 1];
        if (lastLine && lastLine.trim() === TRIPLE_BACKTICK) {
          lines.pop(); // Remove last line
        }
        responseText = lines.join('\n');
      }
      
      // Try to extract JSON from response
      let jsonText = responseText;
      
      // Try to find JSON object in response
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        jsonText = jsonMatch[0];
      }
      
      // Parse JSON response
      const result = JSON.parse(jsonText);
      
      // Validate category
      const validCategories = ['Create', 'Deploy', 'ChallengeInfo', 'Question'];
      if (!validCategories.includes(result.category)) {
        throw new Error('Invalid category: ' + result.category);
      }

      // Set defaults if not provided
      result.challengeType = result.challengeType || (result.challengeTypes && result.challengeTypes[0]) || null;
      result.challengeTypes = result.challengeTypes || (result.challengeType ? [result.challengeType] : []);
      result.requiredTools = result.requiredTools || [];
      
      // Add basic tools based on challenge types
      const basicToolsByType = {
        web: ['curl', 'wget', 'python3', 'nikto', 'dirb', 'gobuster', 'sqlmap', 'burpsuite', 'hydra'],
        network: ['ssh', 'nc', 'net-tools', 'iputils-ping', 'ftp', 'lftp', 'telnet', 'ssh-client', 'smbclient', 'nfs-common', 'snmp', 'tftp'],
        pwn: ['python3', 'gcc', 'gdb', 'pwntools', 'ropper', 'patchelf'],
        crypto: ['openssl', 'python3', 'john', 'hashcat', 'gpg']
      };
      
      const basicTools = ['python3', 'bash', 'git', 'vim', 'nano', 'curl', 'wget'];
      for (const type of result.challengeTypes) {
        if (basicToolsByType[type]) {
          basicTools.push(...basicToolsByType[type]);
        }
      }
      result.requiredTools = [...new Set([...result.requiredTools, ...basicTools])];

      return result;
      
    } catch (error) {
      lastError = error;
      console.error(`Classification error (attempt ${attempt}/${maxRetries}):`, error.message);
      
      if (attempt < maxRetries) {
        // Wait a bit before retrying
        await new Promise(resolve => setTimeout(resolve, 500 * attempt));
        continue;
      }
      
      // If all retries failed, use fallback
      console.error('All classification attempts failed, using fallback...');
    }
  }
  
  // Fallback classification if all retries failed
  // Fallback to keyword-based classification
  const messageLower = message.toLowerCase();
  
  if (messageLower.match(/\b(create|make|generate|new)\b.*\bchallenge\b/) ||
      messageLower.includes('create') && (messageLower.includes('ftp') || messageLower.includes('network') || messageLower.includes('crypto') || messageLower.includes('web'))) {
    const detectedType = detectChallengeTypeFallback(messageLower);
    return { 
      category: 'Create', 
      confidence: 0.7, 
      reasoning: 'Fallback: detected "create challenge" keywords',
      challengeType: detectedType,
      challengeTypes: detectedType ? [detectedType] : [],
      requiredTools: detectToolsFallback(messageLower)
    };
  }
  
  if (messageLower.match(/\b(deploy|run|start|launch|spin up)\b/)) {
    return { 
      category: 'Deploy', 
      confidence: 0.7, 
      reasoning: 'Fallback: detected "deploy" keywords',
      challengeType: null,
      requiredTools: []
    };
  }
  
  if (messageLower.match(/\b(what is|how does|tell me about|explain)\b.*\b[A-Z]/)) {
    return { 
      category: 'ChallengeInfo', 
      confidence: 0.6, 
      reasoning: 'Fallback: detected specific challenge inquiry',
      challengeType: null,
      requiredTools: []
    };
  }
  
  return { 
    category: 'Question', 
    confidence: 0.5, 
    reasoning: 'Fallback: default to general question',
    challengeType: null,
    requiredTools: []
  };
}

/**
 * Fallback challenge type detection
 */
function detectChallengeTypeFallback(message) {
  if (message.match(/\b(sql|xss|web|http|injection|csrf|ssrf)\b/i)) return 'web';
  if (message.match(/\b(nmap|network|packet|port|scan|wireshark|ftp|ssh|smb|samba|telnet|tcp|udp|networking)\b/i)) return 'network';
  // Forensics category removed
  if (message.match(/\b(pwn|buffer|overflow|binary|exploit|reverse)\b/i)) return 'pwn';
  if (message.match(/\b(crypto|cryptography|encrypt|decrypt|hash|cipher|rsa|aes|encoding)\b/i)) return 'crypto';
  return null; // Return null instead of 'misc' to trigger clarification
}

/**
 * Fallback tool detection
 */
function detectToolsFallback(message) {
  const tools = [];
  const toolMap = {
    // Web
    'burpsuite|burp': 'burpsuite',
    'sqlmap': 'sqlmap',
    'nikto': 'nikto',
    'gobuster|dirb|dirbuster': 'gobuster',
    'ffuf|wfuzz': 'ffuf',
    
    // Network
    'nmap': 'nmap',
    'wireshark': 'wireshark',
    'tcpdump': 'tcpdump',
    'netcat|nc': 'netcat',
    
    // Forensics
    'binwalk': 'binwalk',
    'foremost': 'foremost',
    'volatility': 'volatility',
    'strings': 'strings',
    'exiftool': 'exiftool',
    'steghide|stegsolve': 'steghide',
    
    // Pwn
    'gdb|pwndbg|gef': 'gdb',
    'ghidra': 'ghidra',
    'radare2|r2': 'radare2',
    'pwntools': 'python3-pwntools',
    
    // Crypto
    'hashcat': 'hashcat',
    'john|johntheripper': 'john',
    'openssl': 'openssl'
  };
  
  for (const [pattern, tool] of Object.entries(toolMap)) {
    if (new RegExp(pattern, 'i').test(message)) {
      tools.push(tool);
    }
  }
  
  return tools;
}

