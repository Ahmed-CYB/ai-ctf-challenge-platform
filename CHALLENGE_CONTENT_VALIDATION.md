# Challenge Content Validation System

## Overview

The CTF Challenge Platform uses a **multi-layered validation system** to ensure challenge content is correct, complete, and ready for deployment. Validation occurs at multiple stages throughout the challenge creation and deployment process.

---

## Validation Stages

### Stage 1: Content Generation Validation (During AI Content Creation)

**Location**: `packages/ctf-automation/src/agents/content/*-content-agent.js`

**When**: Immediately after AI generates challenge content (files, flag, configuration)

**Validators Used**:
1. **Content Schema Validator** (`content-schema.js`)
   - Validates structure matches expected format
   - Checks required fields: `files`, `flag`, `configuration`
   - Validates file objects have `name` and `content`
   - Validates configuration has `difficulty`, `exploitPath`, `tools`

2. **Content Quality Validator** (`content-quality-validator.js`)
   - **Structure Validation**: Ensures files array exists and has content
   - **Flag Validation**: 
     - Format: `CTF{...}` with 10+ characters
     - No placeholder text (`flag_here`, `placeholder`)
     - Minimum 15 characters total
   - **Placeholder Detection**: 
     - Detects: `[PLACEHOLDER]`, `[INSERT]`, `TODO:`, `FIXME:`, `XXX:`, `...`, etc.
     - Scans all file contents for incomplete sections
   - **Educational Value**: 
     - Checks for learning objectives
     - Validates hints quality (2+ hints, not too revealing)
     - Verifies exploit path description
   - **Category-Specific Validation**:
     - **Web**: Requires vulnerability type, exploit path, web files (.php, .html, .js)
     - **Network**: Requires service type, service port, misconfiguration description
     - **Crypto**: Requires crypto type, solving method, ciphertext files

**Result**: Content is rejected and regenerated if validation fails

---

### Stage 2: Challenge Quality Scoring (After Docker Files Generated)

**Location**: `packages/ctf-automation/src/agents/universal-structure-agent.js` (lines 500-545)

**When**: After Dockerfiles and docker-compose.yml are generated, before writing to disk

**Validators Used**:
1. **Challenge Quality Scorer** (`challenge-quality-scorer.js`)
   - **Metadata Quality** (20 points):
     - Description length (50+ chars = 5pts, 100+ chars = 10pts)
     - Hints count (3+ hints = 5pts)
     - Learning objectives (5pts)
   - **Dockerfile Quality** (20 points):
     - EXPOSE directive (5pts)
     - HEALTHCHECK (5pts)
     - Non-root user (5pts)
     - apt-get cleanup (5pts)
   - **Content Quality** (20 points):
     - Additional files present (10pts)
     - Valid flag format (5pts)
     - Difficulty specified (5pts)
   - **Educational Value** (20 points):
     - Description mentions "learn" or "practice" (10pts)
     - Learning objectives (10pts)
   - **Security Best Practices** (20 points):
     - Strong passwords or no hardcoded passwords (5pts)
     - Non-interactive mode (5pts)
     - Proper file permissions (5pts)
     - Cleanup in same layer (5pts)

2. **Difficulty Validator** (`challenge-quality-scorer.js`)
   - Validates difficulty matches description complexity
   - Checks hint count matches difficulty level
   - Warns if difficulty seems mismatched

**Result**: Quality score (0-100) and grade (A/B/C/D) are calculated and logged

---

### Stage 3: Pre-Deployment Validation (Before GitHub Push)

**Location**: `packages/ctf-automation/src/agents/pre-deploy-validator-agent.js`

**When**: After all files are written to disk, before committing to GitHub

**Validators Used**:

#### 3.1 YAML Syntax Validation
- Parses `docker-compose.yml` to catch syntax errors
- Detects `[object Object]` serialization errors
- Validates YAML structure

#### 3.2 Dockerfile Validation
- **COPY Syntax**: Detects invalid COPY commands with shell syntax
  - Example: `COPY file.txt /path/ 2>/dev/null` → Fixed to `RUN cp file.txt /path/ 2>/dev/null`
- **Package Name Validation**: 
  - Checks for invalid package names (netbios, netbios-ns, etc.)
  - Validates package names match OS package manager
- **Service vs Package**: Ensures services (netbios, cifs) aren't installed as packages

#### 3.3 AI-Powered Analysis (Claude Sonnet 4.5)
Analyzes all challenge files and detects:
- **Critical Issues**:
  - Missing Dockerfiles
  - Missing service installations
  - Missing file copying
  - Missing service startup
  - Missing user creation
  - Port mappings (not allowed - must use private IPs)
  - External network connections (security issue)
  
- **Package Issues**:
  - Invalid package names for OS
  - Service names used as packages
  - Username conflicts (backup, admin, etc.)
  
- **Dockerfile Issues**:
  - Permission errors (chmod/chown before mkdir)
  - User existence in chown commands
  - Missing directories before operations

**Auto-Fixes Applied**:
- Creates missing Dockerfiles with complete content
- Fixes package names (mysql → mariadb, etc.)
- Removes invalid service names from package lists
- Adds missing service installations
- Fixes permission errors
- Removes port mappings
- Fixes username conflicts

**Result**: Files are automatically fixed, then validation retries

---

### Stage 4: Post-Deployment Validation (After Containers Start)

**Location**: `packages/ctf-automation/src/agents/post-deploy-validator.js`

**When**: After `docker compose up` completes successfully

**Validators Used**:

#### 4.1 Container Health Checks
- Verifies all containers are running
- Checks container status (Up/Running)
- Lists all containers for the challenge

#### 4.2 Network Connectivity Tests
- Tests ping from attacker to victim
- Verifies containers are on same network
- Checks network isolation

#### 4.3 Service Port Tests
- Scans expected ports based on challenge type:
  - FTP challenges: Port 21
  - SSH challenges: Port 22
  - Web challenges: Ports 80, 443
  - SMB challenges: Ports 445, 139
  - Database challenges: 3306 (MySQL), 5432 (PostgreSQL)
- Uses nmap from attacker container to verify ports are open

#### 4.4 Challenge-Specific Validation
- **FTP Challenges**: Tests FTP connection, anonymous login
- **SMB Challenges**: Tests SMB share enumeration
- **SSH Challenges**: Tests SSH port accessibility
- **Web Challenges**: Tests HTTP response codes

**Result**: Validation report with pass/fail status for each test

---

### Stage 5: AI-Powered Final Validation (Optional)

**Location**: `packages/ctf-automation/src/agents/validator-agent.js`

**When**: Optional - can be called manually to validate deployed challenges

**Validators Used**:
- **AI Analysis** (OpenAI GPT-4):
  - Analyzes container status
  - Verifies network connectivity
  - **CRITICAL**: Verifies flag is found and matches expected value
  - Assesses exploitability
  - Provides recommendations

**Validation Criteria**:
- ✅ **MUST PASS**:
  - Victim container running
  - Attacker container running
  - **Flag found and matches expected value**
  - Containers on same network

- ⚠️ **NICE TO HAVE** (not critical):
  - HTTP service responding
  - Ping connectivity
  - VNC service

**Result**: PASS/FAIL verdict with detailed explanation

---

## Validation Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ 1. AI Content Generation                                      │
│    ↓                                                          │
│    Content Schema Validation                                  │
│    Content Quality Validation                                 │
│    ↓                                                          │
│    [If fails → Regenerate]                                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Docker Files Generated                                    │
│    ↓                                                          │
│    Challenge Quality Scoring                                 │
│    Difficulty Validation                                     │
│    ↓                                                          │
│    [Logs score, continues]                                    │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Files Written to Disk                                     │
│    ↓                                                          │
│    Pre-Deployment Validation:                                │
│    - YAML Syntax Check                                       │
│    - Dockerfile Validation                                   │
│    - AI Analysis (Claude)                                    │
│    - Auto-Fix Issues                                         │
│    ↓                                                          │
│    [If fixes applied → Retry validation]                     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. GitHub Commit & Push                                      │
│    ↓                                                          │
│    [Challenge ready for deployment]                          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. Deployment (docker compose up)                           │
│    ↓                                                          │
│    Post-Deployment Validation:                               │
│    - Container Health                                        │
│    - Network Connectivity                                    │
│    - Service Port Tests                                      │
│    - Challenge-Specific Tests                                │
│    ↓                                                          │
│    [Validation report generated]                             │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. Optional: AI Final Validation                             │
│    - Flag Verification (CRITICAL)                           │
│    - Exploitability Assessment                               │
│    - Final PASS/FAIL verdict                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Validation Rules

### 1. Flag Validation
- **Format**: Must match `CTF{[a-zA-Z0-9_\-]{10,}}`
- **Length**: Minimum 15 characters total
- **No Placeholders**: Cannot contain `placeholder`, `flag_here`, etc.
- **Post-Deployment**: Flag must be found and match expected value

### 2. Placeholder Detection
**Patterns Detected**:
- `[PLACEHOLDER]`, `[INSERT]`, `[REPLACE]`, `[FILL IN]`, `[ADD HERE]`
- `TODO:`, `FIXME:`, `XXX:` (followed by capital letter)
- `<REPLACE>`, `<!-- more code -->`, `// rest of the code`
- `...` at end of line or `[...]`

**Action**: Content is rejected and regenerated

### 3. Package Name Validation
**Invalid Package Names** (must be removed):
- `netbios`, `netbios-ns`, `netbios-ssn`, `netbios-dgm` (service names, not packages)
- `cifs`, `smb2`, `smb3` (protocols, not packages)
- `mysql-server` → `mariadb-server` (Kali Linux)
- `mysql-client` → `mariadb-client`

**Action**: Auto-fixed before deployment

### 4. Dockerfile Validation
**Checks**:
- No invalid COPY commands with shell syntax
- Directories exist before chmod/chown
- Users exist before chown commands
- No broken multi-stage patterns

**Action**: Auto-fixed before deployment

### 5. Network & Security Validation
**Rules**:
- **NO port mappings** allowed (must use private IPs)
- **NO external network connections** (security isolation)
- All services must use static private IPs
- Attacker container on challenge network only

**Action**: Auto-fixed before deployment

### 6. Username Conflict Validation
**Forbidden Usernames** (already exist in base images):
- `backup`, `admin`, `daemon`, `bin`, `sys`, `www-data`, `nobody`, etc.

**Action**: Auto-fixed (replaced with challenge-specific usernames)

---

## Validation Results

### Content Quality Validation Result
```javascript
{
  valid: true/false,
  scores: {
    structure: 0.0-1.0,
    flag: 0.0-1.0,
    noPlaceholders: 0.0-1.0,
    educational: 0.0-1.0,
    hints: 0.0-1.0,
    categorySpecific: 0.0-1.0
  },
  overallScore: 0.0-1.0,
  issues: ["list of critical issues"],
  warnings: ["list of warnings"]
}
```

### Challenge Quality Score
```javascript
{
  score: 0-100,
  maxScore: 100,
  percentage: "50.0",
  grade: "A|B|C|D",
  breakdown: {
    metadata: 0-20,
    dockerfile: 0-20,
    content: 0-20,
    educational: 0-20,
    security: 0-20
  },
  recommendations: ["list of improvement suggestions"]
}
```

### Pre-Deployment Validation Result
```javascript
{
  success: true/false,
  issues: [
    {
      file: "docker-compose.yml",
      issue: "Port mapping not allowed",
      severity: "critical",
      fixed: true
    }
  ],
  fixesApplied: 2,
  shouldRetry: true/false
}
```

### Post-Deployment Validation Result
```javascript
{
  success: true/false,
  tests: [
    {
      name: "Container Health",
      passed: true,
      details: ["✅ Container running", ...]
    },
    {
      name: "Network Connectivity",
      passed: true,
      details: ["✅ Attacker can reach victim", ...]
    },
    {
      name: "Service Port Checks",
      passed: true,
      details: ["✅ Port 21 is open", ...]
    },
    {
      name: "Challenge Objectives",
      passed: true,
      details: ["✅ FTP service is responding", ...]
    }
  ],
  errors: [],
  warnings: []
}
```

---

## Auto-Fix System

The platform automatically fixes common issues during pre-deployment validation:

### Fixes Applied Automatically

1. **Package Name Fixes**:
   - `mysql-server` → `mariadb-server`
   - `iputils-ping` → `iputils` (Rocky Linux)
   - Removes invalid service names (netbios, cifs, etc.)

2. **OS-Specific Fixes**:
   - Alpine: `telnet` → `busybox-extras`
   - Rocky Linux: Adds `--allowerasing` for curl conflicts
   - Removes `xinetd` (deprecated)

3. **Dockerfile Fixes**:
   - Invalid COPY commands → RUN cp commands
   - Adds `mkdir -p` before chmod/chown
   - Creates users before chown commands
   - Fixes username conflicts

4. **Docker Compose Fixes**:
   - Removes port mappings
   - Removes external network connections
   - Removes obsolete `version` attribute
   - Adds missing services

5. **CentOS EOL Fixes**:
   - `FROM centos` → `FROM rockylinux:9`
   - `yum` → `dnf`

**Location**: `packages/ctf-automation/src/agents/pre-deploy-validator-agent.js` and `auto-error-fixer.js`

---

## Validation Failure Handling

### Content Generation Failures
- **Action**: Content is regenerated (up to 3 attempts)
- **Reason**: Placeholders detected, invalid structure, missing flag

### Pre-Deployment Failures
- **Action**: Issues are auto-fixed, validation retries
- **Reason**: Invalid Dockerfiles, missing files, YAML errors
- **Retries**: Up to 3 attempts with fixes applied

### Post-Deployment Failures
- **Action**: Validation report generated, challenge may still be deployed
- **Reason**: Services not responding, network issues, flag not found
- **Impact**: Challenge marked with warnings, may need manual review

---

## Best Practices

### For Challenge Content
1. ✅ Always provide complete file contents (no placeholders)
2. ✅ Use valid flag format: `CTF{...}`
3. ✅ Include learning objectives and hints
4. ✅ Specify category-specific requirements (service type, vulnerability, etc.)

### For Dockerfiles
1. ✅ Create directories before chmod/chown
2. ✅ Create users before using in chown
3. ✅ Use valid package names for OS
4. ✅ Clean up apt cache in same RUN command
5. ✅ Use non-root users when possible

### For Docker Compose
1. ✅ Use private IPs only (no port mappings)
2. ✅ Remove obsolete `version` attribute
3. ✅ Ensure all referenced files exist
4. ✅ Use correct network configuration

---

## Summary

The platform validates challenge content through **5 distinct stages**:

1. **Content Generation**: Schema and quality validation
2. **Quality Scoring**: Overall challenge quality assessment
3. **Pre-Deployment**: File validation and auto-fixing
4. **Post-Deployment**: Container and service validation
5. **AI Final Validation**: Flag verification and exploitability check

**Key Features**:
- ✅ Automatic placeholder detection
- ✅ Auto-fixing of common issues
- ✅ Multi-layer validation (structure, quality, deployment)
- ✅ Category-specific validation rules
- ✅ Flag verification (critical)
- ✅ Educational value assessment

This comprehensive validation system ensures challenges are **correct, complete, and ready for users** before deployment.

