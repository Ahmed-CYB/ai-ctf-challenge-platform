# 🚀 How to Run the CTF Platform

## 📋 **Quick Start (3 Options)**

### **Option 1: Run Everything with Docker (Recommended) ⭐**

This is the easiest way to run all services:

```powershell
# 1. Make sure you're in the project root
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy"

# 2. Start infrastructure (PostgreSQL, Guacamole, MySQL)
npm run infra:up

# 3. Start all application services (Frontend, Backend, CTF Automation)
npm run dev:docker
```

**Or use the all-in-one command:**
```powershell
npm run dev:docker
```

This will start:
- ✅ PostgreSQL database (Port 5433)
- ✅ Backend API (Port 4002)
- ✅ Frontend (Port 4000)
- ✅ CTF Automation Service (Port 4003) - **NEW ORCHESTRATOR SYSTEM**
- ✅ Guacamole Server (Port 8081)

**Access the platform at:** http://localhost:4000

---

### **Option 2: Run Locally (Development)**

If you prefer to run services locally without Docker:

```powershell
# 1. Install dependencies (if not already done)
npm run install:all

# 2. Make sure infrastructure is running (PostgreSQL, Guacamole)
npm run infra:up

# 3. Start all services locally
npm run dev
```

**Or start services individually:**
```powershell
# Terminal 1: Frontend
npm run dev:frontend    # Port 4000

# Terminal 2: Backend
npm run dev:backend     # Port 4002

# Terminal 3: CTF Automation (NEW ORCHESTRATOR SYSTEM)
npm run dev:ctf         # Port 4003
```

---

### **Option 3: Run Only CTF Automation Service**

If you only want to run the CTF automation service (with new orchestrator):

```powershell
# 1. Make sure infrastructure is running
npm run infra:up

# 2. Run CTF automation in Docker
npm run ctf:up

# Or run locally
cd packages/ctf-automation
npm start
```

---

## 🔧 **Prerequisites**

Before running, make sure you have:

1. **Environment Variables** - Create `.env` file with:
   ```env
   ANTHROPIC_API_KEY=your_key_here
   OPENAI_API_KEY=your_key_here
   GITHUB_TOKEN=your_token_here
   DB_PASSWORD=your_db_password
   GUACAMOLE_DB_PASSWORD=your_guac_password
   ```

2. **Docker** - Make sure Docker Desktop is running

3. **Node.js** - Version 18+ installed

---

## 📊 **Service Ports**

| Service | Port | URL |
|---------|------|-----|
| Frontend | 4000 | http://localhost:4000 |
| Backend API | 4002 | http://localhost:4002 |
| CTF Automation | 4003 | http://localhost:4003 |
| PostgreSQL | 5433 | localhost:5433 |
| Guacamole | 8081 | http://localhost:8081/guacamole |

---

## ✅ **Verify Services Are Running**

### **Check Health Endpoints:**

```powershell
# Frontend
curl http://localhost:4000

# Backend
curl http://localhost:4002/health

# CTF Automation (NEW SYSTEM)
curl http://localhost:4003/health
```

### **Check Docker Containers:**

```powershell
docker ps
```

You should see:
- `frontend-new`
- `backend-new`
- `ctf-automation-new`
- `ctf-postgres-new`
- `ctf-guacamole-new`
- `ctf-guacamole-db-new`
- `ctf-guacd-new`

---

## 🔄 **Restart Services**

### **Restart All Services:**

```powershell
# Stop all
npm run dev:docker:down

# Start all
npm run dev:docker
```

### **Restart Only CTF Automation (After Code Changes):**

```powershell
# Stop CTF automation
npm run ctf:down

# Rebuild and start (with new orchestrator system)
npm run ctf:up
```

### **Restart Individual Container:**

```powershell
# Restart CTF automation container
docker restart ctf-automation-new

# View logs
docker logs -f ctf-automation-new
```

---

## 📝 **View Logs**

### **View All Logs:**

```powershell
npm run dev:docker:logs
```

### **View CTF Automation Logs:**

```powershell
npm run ctf:logs

# Or directly
docker logs -f ctf-automation-new
```

---

## 🆕 **What's New: Orchestrator System**

The CTF automation service now uses a **new orchestrator-based architecture**:

- ✅ Cleaner data flow
- ✅ Better error handling
- ✅ Centralized logging
- ✅ Improved validation
- ✅ Auto-fix capabilities

**The new system is automatically active** when you start the service!

---

## 🐛 **Troubleshooting**

### **Port Already in Use:**

```powershell
# Find process using port 4003
netstat -ano | findstr :4003

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F
```

### **Docker Containers Not Starting:**

```powershell
# Check Docker is running
docker ps

# Restart Docker Desktop if needed
# Then try again
npm run infra:up
```

### **Database Connection Issues:**

```powershell
# Check PostgreSQL is running
docker ps | findstr postgres

# Check logs
docker logs ctf-postgres-new
```

### **CTF Automation Service Not Responding:**

```powershell
# Check health endpoint
curl http://localhost:4003/health

# Check logs for errors
docker logs ctf-automation-new

# Restart the service
docker restart ctf-automation-new
```

---

## 📚 **Additional Commands**

```powershell
# Install all dependencies
npm run install:all

# Run database migrations
npm run db:migrate

# Check health of all services
npm run health

# Build all services
npm run build

# Clean everything
npm run clean
```

---

## 🎯 **Quick Reference**

| Task | Command |
|------|---------|
| Start everything | `npm run dev:docker` |
| Stop everything | `npm run dev:docker:down` |
| Restart CTF service | `npm run ctf:restart` |
| View logs | `npm run ctf:logs` |
| Check health | `curl http://localhost:4003/health` |
| Run locally | `npm run dev` |

---

## ✅ **Success Indicators**

When everything is running correctly, you should see:

1. ✅ All Docker containers running (`docker ps`)
2. ✅ Health endpoints responding (200 OK)
3. ✅ Frontend accessible at http://localhost:4000
4. ✅ No errors in logs
5. ✅ CTF automation service shows: `"CTF Automation Service (NEW) is running"`

---

**Need Help?** Check the logs first: `npm run ctf:logs`


