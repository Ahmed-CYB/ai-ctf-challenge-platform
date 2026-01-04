# Challenge Deployment Guide

## 📁 **Where Challenges Are Saved**

### **Storage Location**

Challenges are saved to a Git repository on your local machine:

**Default Path:**
```
C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy\challenges-repo\challenges\
```

**Environment Variable:**
- `CLONE_PATH` in `.env` file (defaults to `./challenges-repo`)

### **Challenge Structure**

Each challenge is saved in its own directory:

```
challenges-repo/
└── challenges/
    ├── corporate-ftp-breach/
    │   ├── README.md
    │   ├── docker-compose.yml
    │   ├── victim/
    │   │   ├── Dockerfile
    │   │   ├── setup.sh
    │   │   └── [challenge files]
    │   └── attacker/
    │       └── Dockerfile
    └── ancient-cipher-vault/
        └── ...
```

### **What Gets Saved**

1. **README.md** - Challenge description and instructions
2. **docker-compose.yml** - Docker Compose configuration
3. **Dockerfiles** - For each machine (victim, attacker)
4. **Setup scripts** - Service startup commands
5. **Challenge files** - Flags, configs, vulnerable code, etc.

### **Git Repository**

- Challenges are automatically committed to Git
- Repository URL: Set in `REPO_URL` in `.env` (default: `https://github.com/Ahmed-CYB/mcp-test.git`)
- Changes are pushed automatically after creation

---

## 🚀 **How to Deploy Challenges**

### **Method 1: Deploy by Name (Recommended)**

Specify the exact challenge name:

```
deploy corporate-ftp-breach
```

or

```
deploy ancient-cipher-vault
```

### **Method 2: Deploy Last Created Challenge**

If you just created a challenge, you can reference it:

```
deploy the last challenge
```

or

```
deploy corporate-ftp-breach
```

### **Method 3: List and Deploy**

First, list available challenges, then deploy:

```
list challenges
deploy [challenge-name]
```

---

## ⚠️ **Current Issue: "deploy it" Not Working**

When you say **"deploy it"**, the system is treating it as a **create** request instead of **deploy**.

**Why?**
- The classifier doesn't recognize "deploy it" as a deployment command
- It needs the challenge name to be specified

**Solution:**
Use the challenge name explicitly:
```
deploy corporate-ftp-breach
```

---

## 📋 **Deployment Workflow**

When you deploy a challenge, the system:

1. **Pre-Deployment Validation**
   - Validates all files exist
   - Checks Dockerfile syntax
   - Verifies docker-compose.yml
   - Ensures all required files are present

2. **Deployment**
   - Builds Docker images
   - Creates Docker networks
   - Starts containers
   - Assigns IP addresses
   - Configures networking

3. **Post-Deployment Validation**
   - Checks containers are running
   - Verifies services are accessible
   - Tests connectivity
   - Validates Guacamole access

4. **Guacamole Setup**
   - Creates Guacamole user
   - Sets up SSH connection
   - Provides access URL

---

## 🔍 **Finding Your Challenges**

### **Check Local Repository**

```powershell
# Navigate to challenges directory
cd challenges-repo\challenges

# List all challenges
Get-ChildItem -Directory

# View a specific challenge
cd corporate-ftp-breach
Get-ChildItem -Recurse
```

### **Check Git Repository**

If challenges are pushed to GitHub:
- Go to: `https://github.com/Ahmed-CYB/mcp-test/tree/main/challenges`
- All challenges are in the `challenges/` directory

---

## 📝 **Example: Complete Workflow**

### **Step 1: Create Challenge**
```
User: "create ftp ctf challenge"
System: ✅ Challenge "corporate-ftp-breach" created successfully!
```

### **Step 2: Deploy Challenge**
```
User: "deploy corporate-ftp-breach"
System: ✅ Challenge "corporate-ftp-breach" deployed successfully!
```

### **Step 3: Access Challenge**
- Guacamole URL provided in response
- SSH access configured
- Containers running and accessible

---

## 🛠️ **Manual Deployment (Alternative)**

If you want to deploy manually using Docker Compose:

```powershell
# Navigate to challenge directory
cd challenges-repo\challenges\corporate-ftp-breach

# Deploy using docker-compose
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop deployment
docker-compose down
```

---

## 📊 **Deployment Status**

After deployment, you'll receive:

```json
{
  "success": true,
  "deployment": {
    "challengeName": "corporate-ftp-breach",
    "containers": {
      "victim": { "name": "...", "ip": "172.23.208.57", "running": true },
      "attacker": { "name": "...", "ip": "172.23.208.3", "running": true }
    },
    "networks": { ... },
    "guacamole": {
      "url": "http://localhost:8081/guacamole/...",
      "username": "...",
      "password": "..."
    }
  },
  "message": "✅ Challenge deployed successfully!"
}
```

---

## 🔧 **Troubleshooting**

### **Challenge Not Found**
```
Error: Challenge "xyz" not found
```
**Solution:** Check challenge name spelling, or list available challenges

### **Deployment Fails**
```
Error: Deployment failed
```
**Solution:** 
- Check Docker is running
- Verify challenge files are complete
- Check logs for specific errors

### **"deploy it" Creates New Challenge**
**Solution:** Always specify the challenge name:
```
deploy corporate-ftp-breach
```

---

## 📌 **Quick Reference**

| Action | Command |
|--------|---------|
| Create challenge | `create ftp ctf challenge` |
| Deploy challenge | `deploy corporate-ftp-breach` |
| List challenges | `list challenges` |
| View challenge files | `cd challenges-repo\challenges\[name]` |
| Manual deploy | `docker-compose up -d` (in challenge dir) |

---

**Last Updated**: 2025-01-03

