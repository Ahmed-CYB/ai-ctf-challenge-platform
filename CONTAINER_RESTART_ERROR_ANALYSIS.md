# Container Restart Error Analysis

## ❌ **Error: Container Restarting with Exit Code 255**

### **Problem:**
The victim container (`ctf-corporate-file-breach-samba-server`) is in a restart loop with exit code 255.

**From logs:**
```
status: 'Restarting (255) 1 second ago'
ip: 'NO IP'
running: false
```

---

## 🔍 **Root Cause Analysis**

### **1. Exit Code 255**
- Exit code 255 typically indicates a fatal error
- Usually means the startup script failed
- Container restarts due to `restart: unless-stopped` policy

### **2. Startup Script Issue**
The Dockerfile uses:
```bash
set -e  # Exit immediately if a command exits with a non-zero status
```

**Problem:** If any command fails (smbd, nmbd, sshd), the script exits immediately.

### **3. Possible Causes:**
1. **Missing smb.conf file** - Script tries to copy `/challenge/smb.conf` but file might not exist
2. **Samba service failure** - `smbd` or `nmbd` might fail to start
3. **Permission issues** - Services might not have proper permissions
4. **Network timing** - Container might be trying to start services before network is ready

---

## 🔧 **Fixes Applied**

### **1. Enhanced Log Checking**
Updated `deployer.js` to check logs for **both "Exited" and "Restarting"** containers:

```javascript
// Now checks for both Exited and Restarting status
if (!victim.running || victim.status.includes('Restarting')) {
  // Get logs and show detailed error information
  const logs = await container.logs({ stdout: true, stderr: true, tail: 50 });
  // Log full error details including restart count
}
```

### **2. Improved Error Visibility**
- Shows last 50 lines of logs (instead of 30)
- Displays restart count
- Shows full error details in console

---

## 🛠️ **Recommended Fixes**

### **Fix 1: Improve Startup Script**

**Current script (problematic):**
```bash
#!/bin/bash
set -e  # ❌ Exits on any error

# Samba Service Setup
if [ -f /challenge/smb.conf ]; then
  cp /challenge/smb.conf /etc/samba/smb.conf
fi
/usr/sbin/smbd -D &  # ❌ If this fails, script exits
/usr/sbin/nmbd -D &
/usr/sbin/sshd -D &
wait
```

**Improved script (recommended):**
```bash
#!/bin/bash
# Remove set -e or make it more selective

# Samba Service Setup
if [ -f /challenge/smb.conf ]; then
  cp /challenge/smb.conf /etc/samba/smb.conf || echo "Warning: Could not copy smb.conf"
fi

# Start services with error handling
/usr/sbin/smbd -D || echo "Warning: smbd failed to start" &
/usr/sbin/nmbd -D || echo "Warning: nmbd failed to start" &
/usr/sbin/sshd -D || echo "Warning: sshd failed to start" &

# Keep container running even if services fail
tail -f /dev/null
```

### **Fix 2: Ensure smb.conf Exists**

The Dockerfile copies files with `COPY . /challenge/`, but if `smb.conf` doesn't exist, the script should handle it gracefully.

**Add to Dockerfile generation:**
- Always create a default `smb.conf` if not provided
- Or make the script handle missing config file

### **Fix 3: Add Health Checks**

Add health check to docker-compose.yml:
```yaml
healthcheck:
  test: ["CMD", "smbclient", "-L", "localhost", "-N"]
  interval: 10s
  timeout: 5s
  retries: 3
```

---

## 📋 **How to Debug**

### **1. Check Container Logs Manually:**
```bash
docker logs ctf-corporate-file-breach-samba-server --tail 50
```

### **2. Inspect Container:**
```bash
docker inspect ctf-corporate-file-breach-samba-server
```

### **3. Execute into Container:**
```bash
docker exec -it ctf-corporate-file-breach-samba-server /bin/bash
```

### **4. Check if Services are Running:**
```bash
docker exec ctf-corporate-file-breach-samba-server ps aux
docker exec ctf-corporate-file-breach-samba-server netstat -tuln
```

---

## ✅ **Next Steps**

1. **Check the actual logs** - The deployer now shows full logs for restarting containers
2. **Fix the startup script** - Remove `set -e` or add proper error handling
3. **Ensure smb.conf exists** - Make sure the config file is created during build
4. **Test the fix** - Redeploy and verify container starts correctly

---

## 🎯 **Expected Behavior After Fix**

- Container should start and stay running
- Services (smbd, nmbd, sshd) should start in background
- Container should get IP address assigned
- No restart loops

---

**Last Updated**: 2025-01-03

