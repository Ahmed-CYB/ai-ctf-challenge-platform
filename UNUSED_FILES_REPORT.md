# Unused Files and Folders Report

## 🔴 Definitely Unused (Safe to Delete)

### Standalone Utility Scripts (Not Imported Anywhere)
These are one-time utility scripts that are not imported or used by the automation:

1. **`packages/ctf-automation/delete-invalid-file.js`**
   - Purpose: One-time script to delete invalid filename from GitHub
   - Status: ✅ Not imported anywhere
   - Safe to delete: ✅ YES

2. **`packages/ctf-automation/diagnose-kali.js`**
   - Purpose: Diagnostic tool for Kali containers
   - Status: ✅ Not imported anywhere
   - Safe to delete: ✅ YES (manual diagnostic tool)

3. **`packages/ctf-automation/calc-password-hash.js`**
   - Purpose: Utility to calculate Guacamole password hash
   - Status: ✅ Not imported anywhere
   - Safe to delete: ✅ YES (one-time utility)

4. **`packages/ctf-automation/fix-victim.js`**
   - Purpose: Diagnostic/repair tool for victim containers
   - Status: ✅ Not imported anywhere
   - Safe to delete: ✅ YES (manual diagnostic tool)

### Test Directories (No Longer Needed)

5. **`test-terminal-access/`** (entire directory)
   - Purpose: Was created to test alternatives to Guacamole (ttyd, Wetty, Shellinabox)
   - Status: ✅ User confirmed they want to continue with Guacamole
   - Contains:
     - `docker-compose.test.yml`
     - `README.md`
     - `test-script.ps1`
     - `test-script.sh`
   - Safe to delete: ✅ YES

### Test Files (Manual Testing Only)

6. **`packages/ctf-automation/test-*.js`** files:
   - `test-api.ps1` - Manual API testing
   - `test-claude-sql-validator.js` - Manual validator testing
   - `test-create-user.js` - Manual user creation testing
   - `test-deployment.ps1` - Manual deployment testing
   - `test-guacamole-agent.js` - Manual Guacamole testing
   - `test-guacamole-automation.js` - Manual automation testing
   - `test-guacamole-docker-exec.js` - Manual Docker exec testing
   - `test-mysql.js` - Manual MySQL testing
   - `test-os-images.js` - Manual OS image testing
   - Status: ✅ Not imported, manual testing only
   - Safe to delete: ⚠️ MAYBE (keep if you want manual testing scripts)

### PowerShell Utility Scripts (Manual Use Only)

7. **Root-level PowerShell scripts:**
   - `fix-attacker-container.ps1` - Manual fix script
   - `fix-container-manual.ps1` - Manual fix script
   - `verify-challenge-creation.ps1` - Manual verification
   - `test-guacamole-connection.ps1` - Manual testing
   - `start-guacamole.ps1` - Manual startup script
   - Status: ✅ Not imported, manual use only
   - Safe to delete: ⚠️ MAYBE (keep if you use them manually)

8. **`packages/ctf-automation/*.ps1` scripts:**
   - `create-guacamole-user.ps1` - Manual user creation
   - `recreate-guacadmin.ps1` - Manual admin recreation
   - `fix-terminal-prompt.ps1` - Manual fix script
   - Status: ✅ Not imported, manual use only
   - Safe to delete: ⚠️ MAYBE (keep if you use them manually)

### Test Results Files (Old Data)

9. **JSON result files:**
   - `os-image-test-results.json` - Old test results
   - `windows-image-test-results.json` - Old test results
   - `packages/ctf-automation/os-images-test-report.json` - Old test results
   - Status: ✅ Not imported, just old data
   - Safe to delete: ✅ YES (can regenerate if needed)

### Test Challenges Directory

10. **`test-challenges/`** directory
    - Contains: `insecure-ftp-server/` (test challenge)
    - Status: ✅ Only referenced in old troubleshooting docs
    - Safe to delete: ⚠️ MAYBE (keep if you use it for manual testing)

---

## 🟡 Possibly Unused (Review Before Deleting)

### Documentation Files (Many MD files)
- **Status**: Documentation is useful, but many might be outdated
- **Recommendation**: Review and consolidate into main docs
- **Count**: ~80+ MD files in root and packages/ctf-automation

### Examples Directory

11. **`packages/ctf-automation/examples/`**
    - Status: ⚠️ Unknown contents
    - Safe to delete: ⚠️ CHECK FIRST

---

## ✅ Files That ARE Used (DO NOT DELETE)

1. **`packages/ctf-automation/base-test.Dockerfile`**
   - ✅ Used by: `tool-learning-service.js`
   - Purpose: Base image for tool testing
   - **KEEP THIS**

2. **`packages/ctf-automation/delete-all-challenges-git.js`**
   - ✅ Used: Manual script (you just used it)
   - **KEEP THIS**

3. **`packages/ctf-automation/delete-all-challenges.js`**
   - ✅ Used: Alternative deletion script
   - **KEEP THIS**

4. **`packages/ctf-automation/initialize-challenge-repo.js`**
   - ✅ Used: Repository initialization (you just used it)
   - **KEEP THIS**

---

## 📊 Summary

### Safe to Delete Immediately:
- ✅ `delete-invalid-file.js`
- ✅ `diagnose-kali.js`
- ✅ `calc-password-hash.js`
- ✅ `fix-victim.js`
- ✅ `test-terminal-access/` (entire directory)
- ✅ `os-image-test-results.json`
- ✅ `windows-image-test-results.json`
- ✅ `packages/ctf-automation/os-images-test-report.json`

### Review Before Deleting:
- ⚠️ Test files (`test-*.js`, `test-*.ps1`)
- ⚠️ PowerShell utility scripts
- ⚠️ `test-challenges/` directory
- ⚠️ `packages/ctf-automation/examples/` directory
- ⚠️ Documentation files (consolidate instead of delete)

### Total Estimated Space Saved:
- ~5-10 MB (mostly test files and old results)

---

## 🗑️ Recommended Cleanup Command

```powershell
# Delete definitely unused files
Remove-Item "packages\ctf-automation\delete-invalid-file.js" -Force
Remove-Item "packages\ctf-automation\diagnose-kali.js" -Force
Remove-Item "packages\ctf-automation\calc-password-hash.js" -Force
Remove-Item "packages\ctf-automation\fix-victim.js" -Force
Remove-Item "test-terminal-access" -Recurse -Force
Remove-Item "os-image-test-results.json" -Force
Remove-Item "windows-image-test-results.json" -Force
Remove-Item "packages\ctf-automation\os-images-test-report.json" -Force
```


