# Manual Fix Complete ✅

## **Fixed Challenge: `corporate-file-share-breach`**

### **Problem:**
The startup script `/start-services.sh` was not being created in the container, causing:
- Exit code 255
- Container restart loop
- Error: `exec /start-services.sh: no such file or directory`

---

## **Fix Applied:**

### **Changed Dockerfile Script Creation Method**

**Before (heredoc - unreliable):**
```dockerfile
RUN cat > /start-services.sh << 'EOFSCRIPT'
#!/bin/bash
set -e
...
EOFSCRIPT
RUN chmod +x /start-services.sh
```

**After (echo method - reliable):**
```dockerfile
RUN echo '#!/bin/bash' > /start-services.sh && \
    echo 'set -e' >> /start-services.sh && \
    echo '' >> /start-services.sh && \
    echo '# Samba Service Setup' >> /start-services.sh && \
    echo 'if [ -f /challenge/smb.conf ]; then' >> /start-services.sh && \
    echo '  cp /challenge/smb.conf /etc/samba/smb.conf || true' >> /start-services.sh && \
    echo 'fi' >> /start-services.sh && \
    echo '/usr/sbin/smbd -D &' >> /start-services.sh && \
    echo '/usr/sbin/nmbd -D &' >> /start-services.sh && \
    echo '' >> /start-services.sh && \
    echo '# SSH Service Setup' >> /start-services.sh && \
    echo 'mkdir -p /var/run/sshd' >> /start-services.sh && \
    echo '/usr/sbin/sshd -D &' >> /start-services.sh && \
    echo '' >> /start-services.sh && \
    echo '# Keep container running' >> /start-services.sh && \
    echo 'wait' >> /start-services.sh && \
    chmod +x /start-services.sh && \
    test -f /start-services.sh || (echo "ERROR: Failed to create /start-services.sh" && exit 1)
```

---

## **Improvements:**

1. **Reliable Method:** Using `echo` instead of heredoc ensures the script is always created
2. **Error Handling:** Added `|| true` to config copy to prevent failures
3. **Validation:** Added test to ensure file exists after creation
4. **Single RUN Command:** All operations in one RUN command for better layer caching

---

## **Next Steps:**

1. **Rebuild the container:**
   ```bash
   cd packages/ctf-automation/challenges-repo/challenges/corporate-file-share-breach
   docker compose build
   ```

2. **Redeploy:**
   ```bash
   docker compose up -d
   ```

3. **Verify:**
   ```bash
   docker exec ctf-corporate-file-share-breach-samba-server ls -la /start-services.sh
   docker exec ctf-corporate-file-share-breach-samba-server /start-services.sh &
   ```

---

## **Expected Result:**

- ✅ Script file exists at `/start-services.sh`
- ✅ Script is executable
- ✅ Container starts successfully
- ✅ Services (smbd, nmbd, sshd) start in background
- ✅ Container stays running

---

**Fix Applied**: 2025-01-03
**Status**: ✅ Ready for testing

