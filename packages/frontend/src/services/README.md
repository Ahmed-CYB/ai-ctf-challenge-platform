# ChatGPT Integration Guide

## Quick Setup

To connect this application to real ChatGPT:

### 1. Get an OpenAI API Key

1. Go to [platform.openai.com](https://platform.openai.com)
2. Sign up or log in
3. Navigate to API Keys section
4. Create a new API key
5. Copy the key (starts with `sk-`)

### 2. Add Your API Key

Open `services/chatgpt.ts` and replace:

```typescript
const OPENAI_API_KEY = 'YOUR_API_KEY_HERE';
```

with:

```typescript
const OPENAI_API_KEY = 'sk-your-actual-api-key-here';
```

### 3. That's It!

The application will automatically:
- Use real ChatGPT responses instead of mock data
- Have more natural conversations
- Generate better challenge descriptions
- Provide more helpful guidance

## Model Configuration

By default, we use `gpt-4o-mini` which is:
- Fast
- Cost-effective (~$0.15 per 1M input tokens)
- Great for most use cases

To use a more powerful model, change this line in `chatgpt.ts`:

```typescript
model: 'gpt-4o-mini'  // Change to 'gpt-4' for better quality
```

## Cost Estimation

Typical costs per challenge generation:
- **gpt-4o-mini**: ~$0.001 per challenge
- **gpt-4**: ~$0.01 per challenge

## Security Note

⚠️ **Important**: In production, NEVER store API keys in frontend code!

For production deployment:
1. Move the API calls to a backend server
2. Store API keys in environment variables
3. Add rate limiting
4. Implement user authentication

## Testing

The app works in both modes:
- **With API key**: Real ChatGPT responses
- **Without API key**: Mock responses for testing

Check the header in the app - it will show:
- "Powered by ChatGPT" when connected
- "Demo Mode" when using mock responses

## Conversation History

To enable multi-turn conversations (coming soon), you can pass previous messages:

```typescript
await sendMessageToChatGPT(userMessage, [
  { role: 'user', content: 'Previous message' },
  { role: 'assistant', content: 'Previous response' }
]);
```

## Troubleshooting

### "API Error: 401"
- Check that your API key is correct
- Make sure it starts with `sk-`
- Verify your OpenAI account has credits

### "API Error: 429"
- You've hit rate limits
- Wait a few seconds and try again
- Consider upgrading your OpenAI plan

### "Network Error"
- Check your internet connection
- Verify OpenAI services are online
- Check browser console for CORS issues

## Support

For issues with:
- **OpenAI API**: Check [platform.openai.com/docs](https://platform.openai.com/docs)
- **This integration**: Review the code in `services/chatgpt.ts`
