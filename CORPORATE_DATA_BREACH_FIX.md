# Corporate Data Breach Challenge Fix

## ❌ **Issues Identified**

### **1. Dockerfiles Using Old Heredoc Method**
- `techcorp-ftp-server/Dockerfile` - Using `cat > /start-services.sh << 'EOFSCRIPT'` (unreliable)
- `ftp-server/Dockerfile` - Using `cat > /start-services.sh << 'EOFSCRIPT'` (unreliable)
- `techcorp-portal/Dockerfile` - Has duplicate `#!/bin/bash` line

### **2. Orphaned Containers from Previous Challenges**
Multiple containers from old challenges are still running:
- `ctf-corporate-data-breach-techcorp-ftp-server` (not in current docker-compose.yml)
- `ctf-corporate-data-breach-ftp-server` (not in current docker-compose.yml)
- `ctf-corporate-data-breach-via-smb-attacker` (from old challenge)
- `ctf-corporate-data-breach-assessment-corporate-fileserver` (from old challenge)
- `ctf-corporate-data-breach-via-smb-corporate-fileserver` (from old challenge)

### **3. Container Naming Confusion**
The current `docker-compose.yml` only defines:
- `techcorp-portal` (running ✅)
- `attacker` (should be running)

But there are containers with names that don't match the compose file.

---

## 🔧 **Fixes Applied**

### **1. Updated Dockerfiles to Use Echo Method**

**Fixed Files:**
- ✅ `techcorp-ftp-server/Dockerfile` - Changed from heredoc to echo method
- ✅ `ftp-server/Dockerfile` - Changed from heredoc to echo method
- ✅ `techcorp-portal/Dockerfile` - Removed duplicate `#!/bin/bash` line

**New Method:**
```dockerfile
# Create startup script using echo (most reliable method, avoids heredoc issues)
RUN echo '#!/bin/bash' > /start-services.sh && \
    echo 'set -e' >> /start-services.sh && \
    echo '' >> /start-services.sh && \
    echo '# FTP Service Setup' >> /start-services.sh && \
    # ... rest of script ...
    chmod +x /start-services.sh && \
    test -f /start-services.sh || (echo "ERROR: Failed to create /start-services.sh" && exit 1)
```

---

## 📋 **Next Steps**

### **1. Clean Up Orphaned Containers**
```powershell
# Stop and remove orphaned containers
docker stop ctf-corporate-data-breach-techcorp-ftp-server
docker stop ctf-corporate-data-breach-ftp-server
docker stop ctf-corporate-data-breach-via-smb-attacker
docker stop ctf-corporate-data-breach-assessment-corporate-fileserver
docker stop ctf-corporate-data-breach-via-smb-corporate-fileserver

docker rm ctf-corporate-data-breach-techcorp-ftp-server
docker rm ctf-corporate-data-breach-ftp-server
docker rm ctf-corporate-data-breach-via-smb-attacker
docker rm ctf-corporate-data-breach-assessment-corporate-fileserver
docker rm ctf-corporate-data-breach-via-smb-corporate-fileserver
```

### **2. Rebuild and Redeploy**
```powershell
cd packages/ctf-automation/challenges-repo/challenges/corporate-data-breach
docker compose down
docker compose build --no-cache
docker compose up -d
```

### **3. Verify Containers**
```powershell
docker ps --filter "name=corporate-data-breach"
```

---

## 🎯 **Root Cause**

**The Issue Was NOT the Challenge Name**

The problem was:
1. ✅ **Dockerfiles using unreliable heredoc method** - Fixed
2. ✅ **Orphaned containers from previous deployments** - Need manual cleanup
3. ✅ **Duplicate bash shebang line** - Fixed

The challenge name `corporate-data-breach` is fine. The issue was that:
- Old Dockerfiles were generated before we fixed the automation
- Previous challenge deployments left containers running
- The automation fix only applies to NEW challenges, not existing ones

---

## ✅ **Status**

- ✅ Dockerfiles fixed (echo method)
- ⚠️ Orphaned containers need manual cleanup
- ✅ Duplicate line removed
- ⚠️ Need to rebuild containers

**After cleanup and rebuild, the challenge should deploy successfully.**

