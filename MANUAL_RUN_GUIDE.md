# Manual Run Guide

This guide shows you how to run each service manually in separate terminal windows, giving you full control over starting and stopping each component.

## 📋 Prerequisites

1. **PostgreSQL Database** must be running (via Docker or locally)
2. **Guacamole** must be running (if using remote access features)
3. **Docker** must be running (for CTF challenge deployment)

---

## 🚀 Step-by-Step Manual Startup

### **Terminal 1: Backend API Server**

```powershell
# Navigate to project root
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy"

# Start Backend Server
cd packages/backend
npm run dev
```

**Expected Output:**
```
✅ JWT_SECRET configured and validated
   Secret length: 128 characters
   🔐 JWT authentication is automated and ready
🚀 Backend API server running on http://localhost:4002
📊 Health check: http://localhost:4002/api/health
🔐 Authentication endpoints ready
🔑 JWT token creation/verification: AUTOMATED
💾 Database integration active
```

**Port:** `4002`  
**Health Check:** http://localhost:4002/api/health

---

### **Terminal 2: CTF Automation Service**

```powershell
# Navigate to project root
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy"

# Start CTF Automation Service
cd packages/ctf-automation
npm start
```

**Expected Output:**
```
📊 Database connection configured: localhost:5433/ctf_platform
💻 Running locally - using localhost:8081
🔗 Guacamole API URL: http://localhost:8081/guacamole
[INFO] [Server] CTF Automation Service (NEW) started successfully
[INFO] [Server] Server running on port 4003
[INFO] [Server] API endpoint: http://localhost:4003/api/chat
```

**Port:** `4003`  
**Health Check:** http://localhost:4003/health

---

### **Terminal 3: Frontend Application**

```powershell
# Navigate to project root
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy"

# Start Frontend
cd packages/frontend
npm run dev
```

**Expected Output:**
```
VITE v6.3.5  ready in 226 ms
➜  Local:   http://localhost:4000/
➜  Network: use --host to expose
```

**Port:** `4000`  
**URL:** http://localhost:4000

---

## 📊 Service Summary

| Service | Port | Terminal | Command | Status Check |
|---------|------|----------|---------|--------------|
| **Backend** | 4002 | Terminal 1 | `cd packages/backend && npm run dev` | http://localhost:4002/api/health |
| **CTF Automation** | 4003 | Terminal 2 | `cd packages/ctf-automation && npm start` | http://localhost:4003/health |
| **Frontend** | 4000 | Terminal 3 | `cd packages/frontend && npm run dev` | http://localhost:4000 |

---

## 🔄 Quick Start Commands (Copy & Paste)

### **Option 1: PowerShell (3 separate windows)**

**Window 1 - Backend:**
```powershell
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\packages\backend"; npm run dev
```

**Window 2 - CTF Automation:**
```powershell
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\packages\ctf-automation"; npm start
```

**Window 3 - Frontend:**
```powershell
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\packages\frontend"; npm run dev
```

---

## ✅ Verification Steps

### 1. Check Backend
```powershell
curl http://localhost:4002/api/health
# Or open in browser: http://localhost:4002/api/health
```

### 2. Check CTF Automation
```powershell
curl http://localhost:4003/health
# Or open in browser: http://localhost:4003/health
```

### 3. Check Frontend
Open browser: http://localhost:4000

---

## 🛑 Stopping Services

To stop each service:
- **Press `Ctrl + C`** in each terminal window
- Services will stop gracefully

---

## 🔧 Troubleshooting

### Backend won't start
- Check if PostgreSQL is running on port `5433`
- Verify `.env` file has correct `DATABASE_URL`
- Check if port `4002` is already in use

### CTF Automation won't start
- Check if Docker is running
- Verify Guacamole is accessible on port `8081`
- Check `.env` file for API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY)

### Frontend won't start
- Check if port `4000` is already in use
- Verify `VITE_API_BASE_URL` in `.env` points to `http://localhost:4002/api`

### Port already in use
```powershell
# Find process using port (example for port 4002)
netstat -ano | findstr :4002

# Kill process (replace PID with actual process ID)
taskkill /PID <PID> /F
```

---

## 📝 Service Dependencies

```
PostgreSQL (Port 5433)
    ↓
Backend (Port 4002) ──→ Frontend (Port 4000)
    ↓
CTF Automation (Port 4003)
    ↓
Docker + Guacamole (Port 8081)
```

**Start Order:**
1. PostgreSQL (Docker)
2. Backend
3. CTF Automation
4. Frontend (can start anytime)

---

## 🎯 Alternative: Run in Background (PowerShell)

If you want to run services in background:

```powershell
# Backend (background)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\packages\backend'; npm run dev"

# CTF Automation (background)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\packages\ctf-automation'; npm start"

# Frontend (background)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd 'C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\packages\frontend'; npm run dev"
```

---

## 📌 Notes

- Each service runs independently
- You can restart individual services without affecting others
- Logs are visible in each terminal window
- Use `Ctrl + C` to stop any service
- Services will auto-reload on code changes (if using `dev` mode)

---

## 🔍 Monitoring Services

### Check all ports
```powershell
netstat -ano | findstr ":4000 :4002 :4003"
```

### View service logs
Each terminal window shows real-time logs for that service.

---

**Happy Coding! 🚀**

