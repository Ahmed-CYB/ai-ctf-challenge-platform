# Repository Location & Deployment Fix

## 📁 **Repository Location**

### **Where Repository is Cloned**

**Location:**
```
C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\challenges-repo\
```

**How it's determined:**
- Calculated from project root: `packages/ctf-automation/` → go up 3 levels → project root
- Default: `{project-root}/challenges-repo`
- Can be overridden with `CLONE_PATH` in `.env`

### **GitHub Repository**

- **URL**: `https://github.com/Ahmed-CYB/mcp-test.git`
- **Branch**: `main` (or `master`)
- **Challenges Path**: `challenges/` (inside the repo)

---

## 🔍 **Current Issue**

### **Problem:**
- Files are successfully pushed to GitHub ✅
- But challenge directory not found locally ❌
- Deployment fails: "The system cannot find the path specified"

### **Root Cause:**
1. Files are written and pushed to GitHub
2. Local repository might be out of sync
3. `git pull` might overwrite local changes before commit
4. Or local repo needs to pull after push to sync

---

## ✅ **Fixes Applied**

### **Fix 1: Pull Before Deployment**
- Deployer now pulls latest changes from GitHub before deployment
- Ensures local repo has the files that were just pushed

### **Fix 2: Better Path Handling**
- Added file existence check before docker compose
- Better error messages if file not found
- Windows path quoting for docker compose command

### **Fix 3: Path Normalization**
- Use absolute paths in docker compose command
- Properly quote paths for Windows
- Use forward slashes in quoted paths

---

## 🔄 **How It Works Now**

### **Challenge Creation:**
1. Files written to: `challenges-repo/challenges/{name}/`
2. Files committed and pushed to GitHub
3. Files exist in GitHub ✅

### **Challenge Deployment:**
1. **Pull latest changes** from GitHub (ensures local sync)
2. Verify `docker-compose.yml` exists
3. Run docker compose with proper path quoting
4. Deploy containers

---

## 📝 **Verification**

### **Check Repository Location:**

```powershell
# From project root
$repoPath = "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\challenges-repo"
Test-Path $repoPath

# Check challenges
Test-Path "$repoPath\challenges"

# List challenges
Get-ChildItem "$repoPath\challenges" -Directory
```

### **Check on GitHub:**

Visit: `https://github.com/Ahmed-CYB/mcp-test/tree/main/challenges`

You should see your challenges there.

---

## 🚀 **Next Steps**

1. **Create a new challenge** - Files will be pushed to GitHub
2. **Deploy it** - System will pull latest changes first, then deploy
3. **Files should be found** - Local repo will be in sync with GitHub

---

**Last Updated**: 2025-01-03

