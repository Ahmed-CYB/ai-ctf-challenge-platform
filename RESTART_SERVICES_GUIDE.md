# How to Restart All Services

## 🚀 **Quick Restart Commands**

### **Option 1: Restart All Services (Recommended)**

```powershell
# Stop all services
docker compose -f docker/docker-compose.app.yml down
docker compose -f docker/docker-compose.ctf.yml down

# Start all services
docker compose -f docker/docker-compose.app.yml up -d
docker compose -f docker/docker-compose.ctf.yml up -d
```

### **Option 2: Restart with Rebuild (If Code Changed)**

```powershell
# Stop all services
docker compose -f docker/docker-compose.app.yml down
docker compose -f docker/docker-compose.ctf.yml down

# Rebuild and start (rebuilds images with latest code)
docker compose -f docker/docker-compose.app.yml up -d --build
docker compose -f docker/docker-compose.ctf.yml up -d --build
```

### **Option 3: Restart Individual Services**

```powershell
# Restart backend only
docker restart backend-new

# Restart frontend only
docker restart frontend-new

# Restart CTF automation only
docker restart ctf-automation-new

# Restart database only
docker restart ctf-postgres-new

# Restart Guacamole only
docker restart ctf-guacamole-new
docker restart ctf-guacamole-db-new
docker restart ctf-guacd-new
```

---

## 📋 **Step-by-Step Restart Process**

### **1. Stop All Services**

```powershell
# Navigate to project root
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy"

# Stop application services (backend, frontend)
docker compose -f docker/docker-compose.app.yml down

# Stop CTF automation service
docker compose -f docker/docker-compose.ctf.yml down
```

### **2. Verify Services Are Stopped**

```powershell
# Check running containers
docker ps

# Should show no containers (or only unrelated containers)
```

### **3. Start All Services**

```powershell
# Start application services
docker compose -f docker/docker-compose.app.yml up -d

# Start CTF automation service
docker compose -f docker/docker-compose.ctf.yml up -d
```

### **4. Verify Services Are Running**

```powershell
# Check all containers are running
docker ps

# Should show:
# - backend-new
# - frontend-new
# - ctf-automation-new
# - ctf-postgres-new (if using Docker PostgreSQL)
# - ctf-guacamole-new
# - ctf-guacamole-db-new
# - ctf-guacd-new
```

### **5. Check Service Logs**

```powershell
# Check backend logs
docker logs backend-new --tail 50

# Check frontend logs
docker logs frontend-new --tail 50

# Check CTF automation logs (most important after fixes)
docker logs ctf-automation-new --tail 50

# Check database logs
docker logs ctf-postgres-new --tail 50
```

---

## 🔍 **Verify Services Are Working**

### **1. Check Service Health**

```powershell
# Backend health check
curl http://localhost:4002/api/health

# Frontend (should be accessible)
# Open browser: http://localhost:4000

# CTF automation (check if running)
curl http://localhost:4003/api/health
```

### **2. Test Database Connections**

```powershell
# Test PostgreSQL connection
docker exec ctf-postgres-new psql -U ctf_user -d ctf_platform -c "SELECT NOW();"

# Test MySQL connection (Guacamole)
docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "SELECT 1;"
```

### **3. Verify New Fixes Are Active**

```powershell
# Check CTF automation logs for new initialization messages
docker logs ctf-automation-new | Select-String "Database connection configured"
docker logs ctf-automation-new | Select-String "Session cleanup scheduled"
docker logs ctf-automation-new | Select-String "Guacamole API URL"
```

---

## 🔄 **Complete Restart Script**

Create a PowerShell script for easy restart:

```powershell
# restart-services.ps1
Write-Host "🛑 Stopping all services..." -ForegroundColor Yellow
docker compose -f docker/docker-compose.app.yml down
docker compose -f docker/docker-compose.ctf.yml down

Write-Host "⏳ Waiting 5 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "🚀 Starting all services..." -ForegroundColor Green
docker compose -f docker/docker-compose.app.yml up -d
docker compose -f docker/docker-compose.ctf.yml up -d

Write-Host "⏳ Waiting 10 seconds for services to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host "✅ Checking service status..." -ForegroundColor Cyan
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

Write-Host "`n📋 Service URLs:" -ForegroundColor Cyan
Write-Host "   Frontend: http://localhost:4000" -ForegroundColor Green
Write-Host "   Backend:  http://localhost:4002" -ForegroundColor Green
Write-Host "   CTF API:  http://localhost:4003" -ForegroundColor Green
Write-Host "   Guacamole: http://localhost:8081/guacamole" -ForegroundColor Green
```

---

## 🐛 **Troubleshooting**

### **If Services Don't Start**

```powershell
# Check for port conflicts
netstat -ano | findstr ":4000"
netstat -ano | findstr ":4002"
netstat -ano | findstr ":4003"
netstat -ano | findstr ":8081"

# Check Docker logs for errors
docker logs backend-new
docker logs frontend-new
docker logs ctf-automation-new
```

### **If Database Connection Fails**

```powershell
# Check if database container is running
docker ps | Select-String "postgres"

# Check database logs
docker logs ctf-postgres-new --tail 100

# Try restarting database
docker restart ctf-postgres-new
```

### **If CTF Automation Has Errors**

```powershell
# Check detailed logs
docker logs ctf-automation-new --tail 200

# Check if all environment variables are set
docker exec ctf-automation-new env | Select-String "DB_|GUAC_"
```

---

## 📊 **Service Ports Reference**

| Service | Port | URL |
|---------|------|-----|
| Frontend | 4000 | http://localhost:4000 |
| Backend | 4002 | http://localhost:4002 |
| CTF Automation | 4003 | http://localhost:4003 |
| Guacamole | 8081 | http://localhost:8081/guacamole |
| PostgreSQL | 5433 | localhost:5433 |
| MySQL (Guacamole) | 3307 | localhost:3307 |

---

## ✅ **After Restart Checklist**

- [ ] All containers are running (`docker ps`)
- [ ] Backend is accessible (http://localhost:4002/api/health)
- [ ] Frontend is accessible (http://localhost:4000)
- [ ] CTF automation is accessible (http://localhost:4003/api/health)
- [ ] Database connections work
- [ ] No errors in logs
- [ ] New fixes are active (check logs for new messages)

---

## 🎯 **Quick Commands Reference**

```powershell
# Restart everything
docker compose -f docker/docker-compose.app.yml restart
docker compose -f docker/docker-compose.ctf.yml restart

# View logs (follow mode)
docker logs -f ctf-automation-new

# Stop everything
docker compose -f docker/docker-compose.app.yml down
docker compose -f docker/docker-compose.ctf.yml down

# Start everything
docker compose -f docker/docker-compose.app.yml up -d
docker compose -f docker/docker-compose.ctf.yml up -d
```


