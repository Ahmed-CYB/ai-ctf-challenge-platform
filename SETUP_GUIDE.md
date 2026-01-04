# Complete Setup Guide - AI CTF Challenge Platform

This guide will help you set up and run the entire AI CTF Challenge Platform from scratch.

## 📋 Prerequisites

Before starting, ensure you have:

- ✅ **Node.js** 18+ and npm 9+
- ✅ **Docker Desktop** installed and running
- ✅ **Git** installed
- ✅ **API Keys**:
  - Anthropic API Key (for Claude)
  - OpenAI API Key (for GPT models)
  - GitHub Personal Access Token (for repository management)

## 🚀 Step-by-Step Setup

### Step 1: Clone and Navigate to Project

```bash
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy"
```

### Step 2: Configure Environment Variables

1. **Check if `.env` file exists** in the project root:
   ```bash
   # If it doesn't exist, create it from .env.example
   copy .env.example .env
   ```

2. **Edit `.env` file** with your API keys:
   ```env
   # Required API Keys
   OPENAI_API_KEY=sk-proj-your-key-here
   OPENAI_MODEL=gpt-4o
   
   ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
   ANTHROPIC_MODEL=claude-sonnet-4-20250514
   
   GITHUB_TOKEN=github_pat_your-token-here
   GITHUB_OWNER=Ahmed-CYB
   GITHUB_REPO=mcp-test
   
   # Database Configuration (for new Docker infrastructure)
   DB_PASSWORD=ctf_password_123
   GUACAMOLE_DB_PASSWORD=guacamole_password_123
   GUACAMOLE_ROOT_PASSWORD=root_password_123
   ```

### Step 3: Install Dependencies

```bash
npm run install:all
```

This installs dependencies for all packages in the monorepo.

### Step 4: Start Infrastructure Services

Start the long-running infrastructure services (PostgreSQL, Guacamole DB, Guacamole Server):

```bash
npm run infra:up
```

**Wait for services to be healthy** (about 30-60 seconds):
- ✅ PostgreSQL should be ready on port `5433`
- ✅ Guacamole MySQL should be ready on port `3307`
- ✅ Guacamole Server should be ready on port `8081`

**Check status:**
```bash
docker ps --filter "name=postgres-new" --filter "name=guacamole" --format "table {{.Names}}\t{{.Status}}"
```

### Step 5: Start Application Services

Start the frontend, backend, and CTF automation services:

```bash
npm run app:up
```

This starts:
- ✅ Frontend on `http://localhost:4000`
- ✅ Backend API on `http://localhost:4002`
- ✅ CTF Automation Service on `http://localhost:4003`

### Step 6: Start CTF Automation Service

Start the CTF automation service (separate container):

```bash
npm run ctf:up
```

**Note:** The CTF automation service will wait for the Guacamole DB to be ready automatically.

### Step 7: Verify All Services

Check that all services are running:

```bash
npm run health
```

Or manually check:
- Frontend: http://localhost:4000
- Backend: http://localhost:4002/api/health
- CTF Service: http://localhost:4003/health
- Guacamole: http://localhost:8081

## 🔧 Troubleshooting

### Issue 1: Guacamole DB Not Starting

If the Guacamole DB container keeps failing or shows errors:

**Solution: Reset the Guacamole DB volume**

```bash
# Stop infrastructure services
npm run infra:down

# Remove the Guacamole DB volume (WARNING: This deletes all Guacamole data)
docker volume rm ai-ctf-challenge-platform-copy_guacamole_db_new_data

# Restart infrastructure
npm run infra:up
```

**Wait 1-2 minutes** for the MySQL container to fully initialize.

### Issue 2: CTF Automation Service Can't Connect to Guacamole DB

If you see errors like:
```
⏳ Waiting for ctf-guacamole-db-new to be ready (attempt X/10)...
```

**Check the Guacamole DB container:**
```bash
docker logs ctf-guacamole-db-new
```

**If you see MySQL initialization errors:**
1. Stop the container: `docker stop ctf-guacamole-db-new`
2. Remove the volume (see Issue 1 above)
3. Restart: `npm run infra:up`

### Issue 3: Database Connection Refused

If you see `connect ECONNREFUSED` errors:

**For PostgreSQL:**
```bash
# Check if PostgreSQL is running
docker ps | grep postgres-new

# Check logs
docker logs ctf-postgres-new
```

**For Guacamole MySQL:**
```bash
# Check if MySQL is running
docker ps | grep guacamole-db-new

# Check logs
docker logs ctf-guacamole-db-new
```

### Issue 4: Port Already in Use

If a port is already in use:

**Windows PowerShell:**
```powershell
# Find process using port
Get-NetTCPConnection -LocalPort 4003 | Select-Object -ExpandProperty OwningProcess

# Kill process (replace PID with actual process ID)
Stop-Process -Id <PID> -Force
```

**Or change the port** in the respective `docker-compose.yml` file.

### Issue 5: API Keys Not Working

If you see authentication errors:

1. **Verify `.env` file exists** in project root
2. **Check Docker Compose** loads `.env`:
   ```yaml
   env_file:
     - ../.env
   ```
3. **Restart services** after changing `.env`:
   ```bash
   npm run ctf:restart
   ```

## 📊 Service Status Commands

### View All Running Containers
```bash
docker ps
```

### View Logs
```bash
# All infrastructure logs
npm run infra:logs

# All application logs
npm run app:logs

# CTF automation logs
npm run ctf:logs

# Specific service logs
docker logs ctf-automation-new -f
docker logs ctf-guacamole-db-new -f
docker logs ctf-postgres-new -f
```

### Restart Services
```bash
# Restart infrastructure
npm run infra:down
npm run infra:up

# Restart applications
npm run app:restart

# Restart CTF automation
npm run ctf:restart
```

### Stop All Services
```bash
npm run dev:docker:down
```

## 🎯 Quick Start (All-in-One)

For a complete fresh start:

```bash
# 1. Stop everything
npm run dev:docker:down

# 2. Remove volumes (if needed - WARNING: deletes data)
docker volume rm ai-ctf-challenge-platform-copy_guacamole_db_new_data
docker volume rm ai-ctf-challenge-platform-copy_postgres_new_data

# 3. Start everything
npm run infra:up
# Wait 60 seconds for databases to initialize

npm run app:up
npm run ctf:up

# 4. Verify
npm run health
```

## 🌐 Access Points

Once everything is running:

- **Frontend UI**: http://localhost:4000
- **Backend API**: http://localhost:4002/api
- **CTF Automation API**: http://localhost:4003/api/chat
- **Guacamole Web UI**: http://localhost:8081
  - Default login: `guacadmin` / `guacadmin`

## 📝 Next Steps

1. **Test the platform**: Open http://localhost:4000
2. **Create a challenge**: Use the chat interface to request a CTF challenge
3. **Deploy a challenge**: Confirm deployment when prompted
4. **Access via Guacamole**: Use the provided Guacamole credentials to SSH into challenge containers

## 🔄 Daily Workflow

**Starting the platform:**
```bash
npm run infra:up    # Start databases (if not running)
npm run app:up      # Start frontend/backend
npm run ctf:up      # Start CTF automation
```

**Stopping the platform:**
```bash
npm run dev:docker:down
```

**Viewing logs:**
```bash
npm run dev:docker:logs
```

## ⚠️ Important Notes

1. **Infrastructure services** (PostgreSQL, Guacamole) should stay running
2. **Application services** can be restarted frequently during development
3. **Guacamole DB** takes 30-60 seconds to initialize on first start
4. **API keys** must be set in `.env` file in the project root
5. **Docker Desktop** must be running before starting services

## 🆘 Still Having Issues?

1. Check Docker Desktop is running
2. Verify all ports are available (4000, 4002, 4003, 5433, 3307, 8081)
3. Check `.env` file exists and has correct API keys
4. Review service logs: `docker logs <container-name>`
5. Try a complete reset (see Quick Start section)

---

**Last Updated**: 2025-12-30
**Platform Version**: 1.0.0
