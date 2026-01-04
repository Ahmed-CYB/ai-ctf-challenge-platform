# Repository Location Information

## 📁 **Where the Repository is Cloned**

### **Default Location**

The repository is cloned to:
```
C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\challenges-repo\
```

This is the **project root directory**.

### **How It's Determined**

1. **Environment Variable** (if set):
   - `CLONE_PATH` in `.env` file
   - Example: `CLONE_PATH=./challenges-repo`

2. **Default Calculation**:
   - Project root: `packages/ctf-automation/` → go up 3 levels
   - Default: `{project-root}/challenges-repo`

### **Repository Structure**

```
challenges-repo/                    ← Cloned from GitHub
├── .git/                          ← Git repository
├── challenges/                    ← Challenge directories
│   ├── corporate-ftp-breach/
│   │   ├── README.md
│   │   ├── docker-compose.yml
│   │   └── ftp-server/
│   │       └── Dockerfile
│   └── [other challenges]/
└── [other repo files]/
```

### **GitHub Repository**

- **Repository**: `https://github.com/Ahmed-CYB/mcp-test.git`
- **Branch**: `main` (or `master`)
- **Challenges Path**: `challenges/` (inside the repo)

---

## 🔍 **Verification**

### **Check if Repository Exists**

```powershell
# From project root
Test-Path "challenges-repo"

# Check challenges directory
Test-Path "challenges-repo\challenges"

# List challenges
Get-ChildItem "challenges-repo\challenges" -Directory
```

### **Check Challenge Files**

```powershell
# Check specific challenge
Test-Path "challenges-repo\challenges\corporate-ftp-breach\docker-compose.yml"

# View challenge structure
Get-ChildItem "challenges-repo\challenges\corporate-ftp-breach" -Recurse
```

---

## ⚠️ **Current Issue**

### **Problem:**
- Deployment fails with: "The system cannot find the path specified"
- Docker compose command can't find the docker-compose.yml file

### **Possible Causes:**

1. **Repository Not Cloned**
   - Repository doesn't exist at expected location
   - Need to clone it first

2. **Path Issues on Windows**
   - Backslashes in paths need proper escaping
   - Docker compose command needs quoted paths

3. **Challenge Not Saved**
   - Files weren't written to disk
   - Git commit succeeded but files not in local repo

---

## 🔧 **Fixes Applied**

### **Fix 1: Path Verification**
- Added file existence check before docker compose
- Better error message if file not found

### **Fix 2: Windows Path Handling**
- Quote paths for Windows compatibility
- Use absolute paths in docker compose command

---

## 📝 **To Verify Repository Location**

Run this in PowerShell from project root:

```powershell
$projectRoot = Get-Location
$repoPath = Join-Path $projectRoot "challenges-repo"
Write-Host "Expected repo path: $repoPath"
Write-Host "Exists: $(Test-Path $repoPath)"
```

---

**Last Updated**: 2025-01-03

