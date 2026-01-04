# 🖥️ Complete Local Development Setup Guide

This guide will help you run **ALL services locally** (without Docker containers for the application services). Only infrastructure services (PostgreSQL, Guacamole) will run in Docker.

---

## 📋 **Prerequisites Checklist**

Before starting, verify you have:

- ✅ **Node.js** 18+ (You have: v24.12.0 ✅)
- ✅ **npm** 9+ (You have: 11.6.2 ✅)
- ✅ **Docker Desktop** installed and running ✅
- ✅ **Git** installed
- ✅ **PostgreSQL Docker container** running (Port 5433) ✅
- ✅ **Guacamole Docker containers** running (Ports 8081, 3307) ✅

---

## 🔧 **Step 1: Create .env File**

Create a `.env` file in the project root with all required configuration:

```env
# ============================================
# API KEYS (REQUIRED)
# ============================================
ANTHROPIC_API_KEY=sk-ant-api03-YOUR_KEY_HERE
ANTHROPIC_MODEL=claude-sonnet-4-20250514

OPENAI_API_KEY=sk-proj-YOUR_KEY_HERE
OPENAI_MODEL=gpt-4o

GITHUB_TOKEN=ghp_YOUR_TOKEN_HERE
GITHUB_OWNER=Ahmed-CYB
GITHUB_REPO=mcp-test

# ============================================
# DATABASE CONFIGURATION (PostgreSQL)
# ============================================
# For LOCAL development (connecting to Docker PostgreSQL)
DATABASE_URL=postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform

# Individual database parameters (alternative to DATABASE_URL)
DB_HOST=localhost
DB_PORT=5433
DB_NAME=ctf_platform
DB_USER=ctf_user
DB_PASSWORD=ctf_password_123

# ============================================
# GUACAMOLE CONFIGURATION
# ============================================
# Guacamole MySQL Database (running in Docker)
GUAC_CONTAINER_NAME=ctf-guacamole-db-new
GUAC_DB_USER=guacamole_user
GUAC_DB_PASSWORD=guacamole_password_123
GUAC_DB_NAME=guacamole_db

# Guacamole Server URL (for local development)
GUACAMOLE_URL=http://localhost:8081/guacamole
GUACAMOLE_BASE_URL=http://localhost:8081/guacamole
GUACAMOLE_ADMIN_USER=guacadmin
GUACAMOLE_ADMIN_PASS=guacadmin

# ============================================
# SERVICE PORTS
# ============================================
FRONTEND_PORT=4000
BACKEND_PORT=4002
CTF_API_PORT=4003

# ============================================
# FRONTEND CONFIGURATION
# ============================================
FRONTEND_URL=http://localhost:4000
VITE_API_BASE_URL=http://localhost:4002/api

# ============================================
# JWT SECRET (Change in production!)
# ============================================
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long-change-this

# ============================================
# CTF AUTOMATION CONFIGURATION
# ============================================
# Challenge repository path (local)
CLONE_PATH=./challenges-repo
REPO_URL=https://github.com/Ahmed-CYB/mcp-test.git

# Docker socket (for Windows, use named pipe)
DOCKER_SOCKET=\\.\pipe\docker_engine

# Node environment
NODE_ENV=development
LOG_LEVEL=info
```

---

## 🗄️ **Step 2: Verify Infrastructure Services**

Make sure PostgreSQL and Guacamole are running in Docker:

```powershell
# Check PostgreSQL
docker ps --filter "name=postgres-new"

# Check Guacamole
docker ps --filter "name=guacamole"

# Expected output:
# ctf-postgres-new: Up (healthy)
# ctf-guacamole-db-new: Up (healthy)
# ctf-guacamole-new: Up
# ctf-guacd-new: Up
```

If not running, start them:

```powershell
npm run infra:up
```

**Wait 30-60 seconds** for services to be healthy.

---

## 📦 **Step 3: Install Dependencies**

Install all dependencies for all packages:

```powershell
npm run install:all
```

This will install dependencies for:
- Root package
- Frontend package
- Backend package
- CTF Automation package
- Shared package

---

## 🗄️ **Step 4: Setup Database Schema**

Run database migrations to create tables:

```powershell
npm run db:migrate
```

This will:
- Connect to PostgreSQL (localhost:5433)
- Create all required tables
- Set up indexes and constraints

---

## 🚀 **Step 5: Start Services Locally**

### **Option A: Start All Services at Once**

```powershell
npm run dev
```

This starts:
- Frontend (Port 4000) - http://localhost:4000
- Backend (Port 4002) - http://localhost:4002
- CTF Automation (Port 4003) - http://localhost:4003

### **Option B: Start Services Individually (Recommended for Debugging)**

**Terminal 1 - Frontend:**
```powershell
npm run dev:frontend
```

**Terminal 2 - Backend:**
```powershell
npm run dev:backend
```

**Terminal 3 - CTF Automation:**
```powershell
npm run dev:ctf
```

---

## ✅ **Step 6: Verify Everything Works**

### **Check Health Endpoints:**

```powershell
# Frontend
curl http://localhost:4000

# Backend
curl http://localhost:4002/api/health

# CTF Automation
curl http://localhost:4003/health
```

**Expected responses:**
- Frontend: HTML page loads
- Backend: `{"status":"ok","message":"Backend API server is running"}`
- CTF Automation: `{"status":"ok","message":"CTF Automation Service (NEW) is running"}`

### **Check Database Connection:**

The backend should log:
```
✅ Connected to PostgreSQL database
📊 Database connection configured: localhost:5433/ctf_platform
```

The CTF automation should log:
```
📊 Database connection configured: localhost:5433/ctf_platform
```

### **Check Guacamole Connection:**

The CTF automation should log:
```
💻 Running locally - using localhost:8081
🔗 Guacamole API URL: http://localhost:8081/guacamole
```

---

## 🔍 **Troubleshooting**

### **Issue 1: Database Connection Failed**

**Error:** `ECONNREFUSED 127.0.0.1:5433`

**Solution:**
1. Verify PostgreSQL is running: `docker ps --filter "name=postgres-new"`
2. Check port mapping: `docker port ctf-postgres-new`
3. Verify `.env` has correct `DATABASE_URL`:
   ```env
   DATABASE_URL=postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform
   ```

### **Issue 2: Guacamole Connection Failed**

**Error:** `Cannot connect to Guacamole MySQL`

**Solution:**
1. Verify Guacamole DB is running: `docker ps --filter "name=guacamole-db-new"`
2. Check `.env` has correct Guacamole settings:
   ```env
   GUAC_CONTAINER_NAME=ctf-guacamole-db-new
   GUAC_DB_USER=guacamole_user
   GUAC_DB_PASSWORD=guacamole_password_123
   GUAC_DB_NAME=guacamole_db
   ```

### **Issue 3: Docker Socket Access Failed (Windows)**

**Error:** `Cannot connect to Docker daemon`

**Solution:**
1. Make sure Docker Desktop is running
2. For Windows, Docker socket is automatically handled by Dockerode
3. Verify Docker is accessible: `docker ps`

### **Issue 4: Port Already in Use**

**Error:** `EADDRINUSE: address already in use :::4003`

**Solution:**
```powershell
# Find process using port 4003
netstat -ano | findstr :4003

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F
```

### **Issue 5: Missing API Keys**

**Error:** `Could not resolve authentication method`

**Solution:**
1. Verify `.env` file exists in project root
2. Check `ANTHROPIC_API_KEY` is set
3. Restart the service after adding keys

---

## 📊 **Service Configuration Summary**

| Service | Port | Local URL | Docker Required? |
|---------|------|-----------|------------------|
| Frontend | 4000 | http://localhost:4000 | ❌ No |
| Backend | 4002 | http://localhost:4002/api | ❌ No |
| CTF Automation | 4003 | http://localhost:4003 | ❌ No |
| PostgreSQL | 5433 | localhost:5433 | ✅ Yes (Docker) |
| Guacamole | 8081 | http://localhost:8081/guacamole | ✅ Yes (Docker) |
| Guacamole MySQL | 3307 | localhost:3307 | ✅ Yes (Docker) |

---

## 🎯 **Quick Start Commands**

```powershell
# 1. Create .env file (see Step 1 above)
# 2. Start infrastructure (PostgreSQL, Guacamole)
npm run infra:up

# 3. Install dependencies
npm run install:all

# 4. Setup database
npm run db:migrate

# 5. Start all services locally
npm run dev
```

---

## 🔄 **Development Workflow**

### **Making Code Changes:**

1. **Frontend changes**: Auto-reloads (Vite hot reload)
2. **Backend changes**: Auto-reloads (nodemon)
3. **CTF Automation changes**: Restart manually:
   ```powershell
   # Stop: Ctrl+C
   # Start: npm run dev:ctf
   ```

### **Viewing Logs:**

Each service logs to its own terminal. For detailed logs:

```powershell
# Backend logs
# (Already visible in terminal running npm run dev:backend)

# CTF Automation logs
# (Already visible in terminal running npm run dev:ctf)
```

---

## 🧪 **Testing the Setup**

### **Test 1: Health Checks**

```powershell
# Test all health endpoints
curl http://localhost:4000
curl http://localhost:4002/api/health
curl http://localhost:4003/health
```

### **Test 2: Database Connection**

```powershell
# Test PostgreSQL connection
docker exec ctf-postgres-new psql -U ctf_user -d ctf_platform -c "SELECT version();"
```

### **Test 3: Guacamole Connection**

```powershell
# Test Guacamole MySQL connection
docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "SELECT COUNT(*) FROM guacamole_entity;"
```

### **Test 4: Create a Test Challenge**

1. Open http://localhost:4000
2. Send message: "create ftp ctf challenge"
3. Wait for challenge creation
4. Check logs for any errors

---

## 📝 **Environment Variables Reference**

### **Required Variables:**

| Variable | Purpose | Example |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | **REQUIRED** - AI challenge generation | `sk-ant-api03-...` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@localhost:5433/db` |
| `GUAC_CONTAINER_NAME` | Guacamole MySQL container name | `ctf-guacamole-db-new` |
| `GUAC_DB_PASSWORD` | Guacamole MySQL password | `guacamole_password_123` |

### **Optional Variables:**

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENAI_API_KEY` | (none) | Alternative AI provider |
| `GITHUB_TOKEN` | (none) | Challenge repository access |
| `JWT_SECRET` | `your-secret-key...` | JWT token signing |
| `FRONTEND_PORT` | `4000` | Frontend server port |
| `BACKEND_PORT` | `4002` | Backend server port |
| `CTF_API_PORT` | `4003` | CTF automation port |

---

## ✅ **Success Indicators**

When everything is working correctly, you should see:

1. ✅ All three services start without errors
2. ✅ Database connection logs show successful connection
3. ✅ Health endpoints return 200 OK
4. ✅ Frontend loads at http://localhost:4000
5. ✅ No connection errors in logs
6. ✅ CTF automation service shows: `"CTF Automation Service (NEW) is running"`

---

## 🎉 **You're Ready!**

Once all services are running:
- **Frontend**: http://localhost:4000
- **Backend API**: http://localhost:4002/api
- **CTF Automation**: http://localhost:4003/health
- **Guacamole**: http://localhost:8081/guacamole

**Start creating challenges!** 🚀


