# Context Awareness Implementation

## Overview

Added AI-powered context awareness to the CTF platform so the system can understand user intent and extract challenge names from conversation history, even when not explicitly mentioned.

## Features Implemented

### 1. Context Agent (`packages/ctf-automation/src/agents/context-agent.js`)

A new AI agent that:
- Analyzes conversation history to extract challenge names
- Understands user intent (create, deploy, run, etc.)
- Handles ambiguous commands like "deploy it", "run it", or just "deploy"
- Uses Anthropic Claude for intelligent context extraction
- Falls back to pattern matching if AI fails

**Key Capabilities:**
- Extracts challenge names from conversation history
- Understands that "run" and "deploy" are synonyms
- Identifies the most recent challenge when user says "it" or omits the name
- Provides confidence scores and reasoning

### 2. Enhanced Request Validator (`packages/ctf-automation/src/core/request-validator.js`)

Updated to:
- Use the Context Agent to extract challenge names from conversation
- Prioritize challenge name extraction in this order:
  1. Explicitly mentioned in current message
  2. From AI context extraction (conversation history)
  3. From classification
  4. From message parsing
- Handle "run" as a synonym for "deploy"
- Better pattern matching for challenge names

### 3. Updated Orchestrator (`packages/ctf-automation/src/core/orchestrator.js`)

Enhanced to:
- Accept context from request validator
- Use context-extracted challenge names when explicit name is missing
- Provide better error messages with context reasoning
- Handle "run" command as deployment request

## How It Works

### Example Flow:

1. **User**: "create ctf challenge ftp"
   - System creates challenge "corporate-ftp-breach"
   - Response: "✅ Challenge 'corporate-ftp-breach' created successfully!"

2. **User**: "deploy it" or "run it" or just "deploy"
   - Context Agent analyzes conversation history
   - Finds "corporate-ftp-breach" as the most recent challenge
   - Extracts challenge name: "corporate-ftp-breach"
   - System deploys the challenge

3. **User**: "run corporate-ftp-breach"
   - Context Agent sees explicit challenge name
   - Uses it directly (no need for context lookup)

## Benefits

✅ **Natural Language Understanding**: Users can say "deploy it" after creating a challenge
✅ **Context Awareness**: System remembers what challenge was just created
✅ **Flexible Commands**: "run", "deploy", "start" all work the same way
✅ **Better UX**: No need to remember or type full challenge names
✅ **Intelligent Fallbacks**: Multiple layers of extraction ensure robustness

## Technical Details

### Context Extraction Priority:

1. **AI-Powered Extraction** (Primary):
   - Uses Claude to analyze conversation history
   - Understands natural language references
   - Provides confidence scores

2. **Pattern Matching** (Fallback):
   - Extracts kebab-case challenge names
   - Looks for patterns like "Challenge 'name' created"
   - Searches conversation history manually

3. **Message Parsing** (Last Resort):
   - Extracts challenge names from current message
   - Handles "deploy <name>" patterns

### Error Handling:

- If challenge name cannot be determined, provides helpful error message
- Includes context reasoning when available
- Suggests explicit challenge name format

## Usage Examples

```javascript
// User says "deploy" after creating a challenge
// Context Agent extracts: "corporate-ftp-breach"
// System deploys the challenge

// User says "run corporate-ftp-breach"
// Context Agent sees explicit name
// System deploys the challenge

// User says "deploy it"
// Context Agent finds last created challenge
// System deploys that challenge
```

## Files Modified

1. `packages/ctf-automation/src/agents/context-agent.js` - **NEW FILE**
2. `packages/ctf-automation/src/core/request-validator.js` - **UPDATED**
3. `packages/ctf-automation/src/core/orchestrator.js` - **UPDATED**

## Testing

To test the context awareness:

1. Create a challenge: "create ctf challenge ftp"
2. Deploy without name: "deploy" or "deploy it" or "run it"
3. System should automatically use the challenge name from context

## Future Enhancements

- Store last challenge name in session metadata for faster lookup
- Support multiple challenges in conversation ("deploy the ftp one")
- Add conversation summarization for very long histories
- Support challenge name aliases/nicknames

---

**Status**: ✅ Implemented and ready for testing

