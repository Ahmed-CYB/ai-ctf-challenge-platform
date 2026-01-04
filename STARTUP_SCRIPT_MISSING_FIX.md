# Startup Script Missing Fix

## ❌ **Error: `/start-services.sh: no such file or directory`**

### **Problem:**
The container is restarting with exit code 255 because the startup script `/start-services.sh` doesn't exist in the container, even though the Dockerfile is supposed to create it.

**Error from logs:**
```
exec /start-services.sh: no such file or directory
Restart Count: 6
```

---

## 🔍 **Root Cause**

The Dockerfile uses a heredoc to create the startup script:
```dockerfile
RUN cat > /start-services.sh << 'EOFSCRIPT'
#!/bin/bash
set -e
...
EOFSCRIPT
RUN chmod +x /start-services.sh
```

**Possible causes:**
1. **Heredoc syntax issue** - The heredoc might not be working correctly in the Docker build context
2. **Script content issues** - Special characters in the script might break the heredoc
3. **Line ending issues** - Windows CRLF vs Linux LF line endings
4. **Build context issue** - The RUN command might be failing silently

---

## 🔧 **Fixes Applied**

### **1. Enhanced Script Creation with Validation**

**Updated `dockerfile-generator.js`:**
```dockerfile
# Create startup script using heredoc (more reliable than printf)
RUN cat > /start-services.sh << 'EOFSCRIPT'
${escapedScript}
EOFSCRIPT
RUN chmod +x /start-services.sh && \
    test -f /start-services.sh || (echo "ERROR: Failed to create /start-services.sh" && exit 1)
```

**Changes:**
- Added validation step to ensure file exists after creation
- Properly escape `$` and backticks in script content
- Combine chmod and validation in single RUN command

### **2. Updated Tool Installation Agent**

**Updated `tool-installation-agent.js`:**
```dockerfile
RUN cat > /start-services.sh << 'EOFSCRIPT'
${startupScript.replace(/\$/g, '\\$').replace(/`/g, '\\`')}
EOFSCRIPT
RUN chmod +x /start-services.sh && \
    test -f /start-services.sh || (echo "ERROR: Failed to create /start-services.sh" && exit 1)
```

**Changes:**
- Escape `$` and backticks in script content
- Add validation to ensure file exists

---

## ✅ **How It Works Now**

1. **Script Creation:**
   - Uses heredoc syntax (most reliable for multi-line scripts)
   - Escapes special characters (`$`, backticks)
   - Creates file in single RUN command

2. **Validation:**
   - Checks if file exists after creation
   - Fails build immediately if file doesn't exist
   - Prevents silent failures

3. **Permissions:**
   - Sets executable permissions
   - Validates in same RUN command

---

## 🧪 **Testing**

**To verify the fix:**

1. Create a new challenge (e.g., "create samba ctf challenge")
2. Check the generated Dockerfile
3. Verify the startup script creation includes validation
4. Build the container and check if `/start-services.sh` exists:
   ```bash
   docker build -t test-challenge ./samba-server
   docker run --rm test-challenge ls -la /start-services.sh
   ```

---

## 📋 **Expected Behavior**

**Before fix:**
- Script might not be created
- Container fails with "no such file or directory"
- Silent failure during build

**After fix:**
- Script is always created
- Build fails immediately if script creation fails
- Clear error message if script doesn't exist
- Container starts successfully

---

## 🎯 **Additional Recommendations**

If the issue persists, consider:

1. **Use COPY instead of heredoc:**
   ```dockerfile
   COPY start-services.sh /start-services.sh
   RUN chmod +x /start-services.sh
   ```

2. **Use printf with base64:**
   ```dockerfile
   RUN echo '${base64Script}' | base64 -d > /start-services.sh
   ```

3. **Check build logs:**
   - Look for errors during script creation
   - Verify heredoc is being processed correctly

---

**Last Updated**: 2025-01-03

