# API Key Setup Guide 🔑

## ❌ Current Error

```
Could not resolve authentication method. Expected either apiKey or authToken to be set.
```

This means the `ANTHROPIC_API_KEY` environment variable is **not set** in the Docker container.

---

## ✅ Solution

### Option 1: Create .env File (Recommended)

Create a `.env` file in the project root:

```bash
# .env file
ANTHROPIC_API_KEY=your_anthropic_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
GITHUB_TOKEN=your_github_token_here
DB_PASSWORD=ctf_password_123
```

**Location**: `C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\.env`

### Option 2: Set Environment Variables in Docker Compose

The Docker Compose file will automatically read from `.env` file if it exists.

**Current configuration** (in `docker/docker-compose.ctf.yml`):
```yaml
environment:
  ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
  OPENAI_API_KEY: ${OPENAI_API_KEY}
  GITHUB_TOKEN: ${GITHUB_TOKEN}
```

This means it reads from:
1. `.env` file (if exists)
2. System environment variables
3. Defaults to empty string (causes error)

---

## 🔧 Quick Fix Steps

### Step 1: Create .env File
```powershell
# In project root
New-Item -Path .env -ItemType File -Force
```

### Step 2: Add Your API Keys
```powershell
# Edit .env file and add:
ANTHROPIC_API_KEY=sk-ant-api03-...
OPENAI_API_KEY=sk-...
GITHUB_TOKEN=ghp_...
DB_PASSWORD=ctf_password_123
```

### Step 3: Restart CTF Service
```bash
npm run ctf:restart
```

---

## 🔍 Verify API Key is Set

```bash
# Check if API key is in container
docker exec ctf-automation-new printenv ANTHROPIC_API_KEY

# Should show your API key (not empty)
```

---

## 📝 Required API Keys

| Key | Purpose | Where to Get |
|-----|---------|--------------|
| `ANTHROPIC_API_KEY` | **REQUIRED** - AI challenge generation | https://console.anthropic.com/ |
| `OPENAI_API_KEY` | Optional - Alternative AI | https://platform.openai.com/ |
| `GITHUB_TOKEN` | Optional - Challenge repository | https://github.com/settings/tokens |

**Minimum Required**: `ANTHROPIC_API_KEY` (for challenge creation to work)

---

## ⚠️ Security Note

- **Never commit `.env` file to Git**
- `.env` should be in `.gitignore`
- Use different keys for development/production

---

**Status**: ⚠️ **API Key Missing** - Create `.env` file with `ANTHROPIC_API_KEY`



