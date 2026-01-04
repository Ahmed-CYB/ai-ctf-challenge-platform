# CTF Automation Service

A complete automation service for creating, deploying, and managing CTF (Capture The Flag) challenges using AI, Git, and Docker.

## Features

- 🤖 **AI-Powered Challenge Creation**: Generate complete CTF challenges using OpenAI
- 🚀 **Automated Deployment**: Build and deploy Docker containers automatically
- 📦 **Git Integration**: Manage challenges in GitHub repository
- 🔍 **Smart Classification**: Automatically routes requests to the right agent
- 💬 **Chat Interface**: Natural language interaction for all operations

## Architecture

```
User Message
    ↓
Classifier (determines intent)
    ↓
┌─────────────┬──────────────┬───────────────┬──────────────┐
│   Create    │    Deploy    │ ChallengeInfo │   Question   │
│   Agent     │    Agent     │     Agent     │    Agent     │
└─────────────┴──────────────┴───────────────┴──────────────┘
      ↓              ↓               ↓              ↓
   Git Mgr      Git + Docker      Git Mgr       OpenAI
      ↓              ↓               ↓              ↓
   GitHub        Container      Metadata       Answer
```

## Prerequisites

- Node.js 18+
- Docker Desktop
- GitHub account with personal access token
- OpenAI API key

## Setup

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Configure environment:**
   
   Copy `.env.example` to `.env` and fill in your credentials:
   ```bash
   cp .env.example .env
   ```

   Required variables:
   - `OPENAI_API_KEY`: Your OpenAI API key
   - `GITHUB_TOKEN`: GitHub personal access token with repo access
   - `GITHUB_OWNER`: GitHub username (default: Ahmed-CYB)
   - `GITHUB_REPO`: Repository name (default: mcp-test)

3. **Ensure Docker is running:**
   ```bash
   docker --version
   ```

## Usage

### Start the server

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
```

The server will start on port 3003 (configurable via PORT env variable).

### API Endpoints

#### Health Check
```bash
GET http://localhost:3003/health
```

#### Chat Interface
```bash
POST http://localhost:3003/api/chat
Content-Type: application/json

{
  "message": "Create a web challenge about SQL injection"
}
```

### Example Requests

**Create a Challenge:**
```json
{
  "message": "Create an easy web challenge about XSS vulnerabilities"
}
```

**Deploy a Challenge:**
```json
{
  "message": "Deploy sql-injection-challenge"
}
```

**Get Challenge Info:**
```json
{
  "message": "Tell me about sql-injection-challenge"
}
```

**Ask a Question:**
```json
{
  "message": "What is SQL injection and how does it work?"
}
```

## Components

### Classifier (`src/classifier.js`)
Routes requests to appropriate agents based on intent:
- **Create**: Generate new challenges
- **Deploy**: Launch existing challenges
- **ChallengeInfo**: Get challenge details
- **Question**: Answer general questions

### Agents

#### Create Agent (`src/agents/create-agent.js`)
- Uses OpenAI to generate complete CTF challenges
- Creates Dockerfile and all necessary files
- Commits to GitHub repository

#### Deploy Agent (`src/agents/deploy-agent.js`)
- Builds Docker images from challenge directories
- Runs containers with auto-assigned ports
- Returns access URL for deployed challenges

#### Info Agent (`src/agents/info-agent.js`)
- Retrieves challenge metadata from repository
- Uses OpenAI to generate helpful explanations
- Provides hints without spoiling solutions

#### Questions Agent (`src/agents/questions-agent.js`)
- Answers general CTF and cybersecurity questions
- Provides educational content
- Suggests platform features

### Managers

#### Git Manager (`src/git-manager.js`)
- Clones and pulls from GitHub
- Creates files in repository
- Commits and pushes changes
- Lists challenges and reads metadata

#### Docker Manager (`src/docker-manager.js`)
- Builds Docker images
- Runs containers with port mapping
- Manages container lifecycle
- Extracts runtime information

## Challenge Structure

Each challenge in the repository has this structure:

```
challenge-name/
├── Dockerfile          # Container configuration
├── metadata.json       # Challenge information
├── index.html          # Web files (if web challenge)
├── flag.txt           # Challenge flag
└── ...                # Other challenge files
```

### Metadata Format

```json
{
  "title": "SQL Injection Challenge",
  "description": "Learn about SQL injection vulnerabilities",
  "difficulty": "easy",
  "category": "web",
  "flag": "CTF{example_flag}",
  "hints": [
    "Look at the login form",
    "Try using special SQL characters"
  ]
}
```

## Integration with Frontend

To integrate with your CTF platform frontend:

1. **Update the Chat Interface** ([src/components/CTFChatInterface.tsx](src/components/CTFChatInterface.tsx)):

```typescript
const response = await fetch('http://localhost:3003/api/chat', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ message: userMessage })
});

const data = await response.json();
// Handle response data
```

2. **Display Challenge URLs:**
When a challenge is deployed, the response includes:
```json
{
  "deployment": {
    "url": "http://localhost:32768",
    "containerId": "...",
    "containerName": "...",
    "hostPort": "32768"
  }
}
```

3. **Show Challenge Information:**
Use the Info Agent response to display challenge details in your UI.

## Troubleshooting

### Port Conflicts
If port 3003 is in use, change it in `.env`:
```
PORT=3004
```

### Docker Issues
- Ensure Docker Desktop is running
- Check Docker daemon: `docker ps`
- Verify Docker socket access

### Git Issues
- Verify GitHub token has repo access
- Check repository permissions
- Ensure CLONE_PATH directory is writable

### OpenAI Issues
- Verify API key is valid
- Check API rate limits
- Monitor token usage

## Development

### Project Structure
```
ctf-automation/
├── src/
│   ├── index.js                    # Main server
│   ├── classifier.js               # Request classifier
│   ├── git-manager.js              # Git operations
│   ├── docker-manager.js           # Docker operations
│   └── agents/
│       ├── create-agent.js         # Challenge creation
│       ├── deploy-agent.js         # Challenge deployment
│       ├── info-agent.js           # Challenge information
│       ├── questions-agent.js      # Q&A handler
│       └── retriever-agent.js      # Challenge listing
├── .env                            # Configuration (create from .env.example)
├── .env.example                    # Configuration template
├── package.json                    # Dependencies
└── README.md                       # This file
```

### Adding New Features

To add a new agent or feature:
1. Create new file in `src/agents/`
2. Export main function
3. Import in `src/index.js`
4. Add routing logic in request handler

## License

This project is part of the AI CTF Challenge Platform.

## Support

For issues or questions:
1. Check the logs in the terminal
2. Verify environment variables
3. Ensure all services (Docker, GitHub) are accessible
4. Review error messages in API responses
