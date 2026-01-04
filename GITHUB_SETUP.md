# Linking Your Project to GitHub

This guide will help you connect your AI CTF Challenge Platform to GitHub.

## Step 1: Initialize Git Repository

Open PowerShell in your project directory and run:

```powershell
# Navigate to project directory
cd "C:\Users\hmo0d\Desktop\fyp\AI CTF Challenge Platform - Copy - Copy (2)"

# Initialize git repository
git init

# Add all files to staging
git add .

# Create initial commit
git commit -m "Initial commit: AI CTF Challenge Platform"
```

## Step 2: Create GitHub Repository

1. Go to [GitHub.com](https://github.com) and sign in
2. Click the **"+"** icon in the top right → **"New repository"**
3. Fill in the details:
   - **Repository name**: `ai-ctf-challenge-platform` (or your preferred name)
   - **Description**: "AI-Powered CTF Challenge Platform with automated challenge generation and deployment"
   - **Visibility**: Choose **Private** (recommended) or **Public**
   - **DO NOT** initialize with README, .gitignore, or license (we already have these)
4. Click **"Create repository"**

## Step 3: Link Local Repository to GitHub

After creating the repository, GitHub will show you commands. Use these:

```powershell
# Add GitHub as remote origin (replace YOUR_USERNAME and REPO_NAME)
git remote add origin https://github.com/YOUR_USERNAME/ai-ctf-challenge-platform.git

# Verify the remote was added
git remote -v

# Push to GitHub (main branch)
git branch -M main
git push -u origin main
```

## Step 4: Important Notes

### ⚠️ Security: Environment Variables

Your `.gitignore` already excludes `.env` files, which is **critical** for security. Never commit:
- `.env` files
- API keys
- Database credentials
- Secrets

### What Gets Committed:
✅ Source code
✅ Configuration files (without secrets)
✅ Documentation
✅ Package files

### What Gets Ignored (from .gitignore):
❌ `node_modules/`
❌ `.env` files
❌ Build outputs
❌ Log files
❌ IDE settings

## Step 5: Future Updates

After making changes, push updates with:

```powershell
# Check what changed
git status

# Add changes
git add .

# Commit with descriptive message
git commit -m "Description of your changes"

# Push to GitHub
git push
```

## Alternative: Using GitHub Desktop

If you prefer a GUI:

1. Download [GitHub Desktop](https://desktop.github.com/)
2. Install and sign in
3. Click **"File"** → **"Add Local Repository"**
4. Select your project folder
5. Click **"Publish repository"** to create and push to GitHub

## Troubleshooting

### If you get authentication errors:
- Use a [Personal Access Token](https://github.com/settings/tokens) instead of password
- Or use SSH: `git remote set-url origin git@github.com:YOUR_USERNAME/REPO_NAME.git`

### If you need to update .gitignore:
- Edit `.gitignore` file
- Run: `git rm -r --cached .` then `git add .` to re-apply ignore rules

---

**Need help?** Check the [GitHub Documentation](https://docs.github.com/en/get-started/importing-your-projects-to-github/importing-source-code-to-github/adding-locally-hosted-code-to-github)

