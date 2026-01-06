# Post-Deployment Validation Workflow

## Overview

The validation system runs **automatically after deployment** to ensure all services are working correctly. It performs comprehensive testing of all services, not just FTP.

## Validation Flow

```
Deployment Complete
    ↓
Phase 3: Post-Deployment Validation
    ↓
┌─────────────────────────────────────┐
│ 1. Health Check                    │
│    - Container status              │
│    - IP assignment                 │
│    - Basic service detection       │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ 2. Connectivity Test               │
│    - Attacker → Victim connectivity│
│    - Network reachability          │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ 3. Service Discovery & Testing     │
│    - Port scanning (nmap/netcat)  │
│    - Service identification         │
│    - Service-specific tests         │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│ 4. Challenge Requirements Check    │
│    - Verify challenge-specific reqs │
│    - Test anonymous FTP if needed   │
└─────────────────────────────────────┘
    ↓
Validation Complete
```

## Step-by-Step Process

### Step 1: Health Check (`HealthChecker.checkAll()`)

**What it does:**
- Checks if containers are running
- Verifies IP addresses are assigned
- Checks if services are listening on ports (using `netstat`/`ss`)

**Ports checked:** 21, 22, 80, 443, 445

**Result:** Basic health status

---

### Step 2: Connectivity Test (`testConnectivity()`)

**What it does:**
- Verifies attacker container is running
- Checks each victim has an IP address
- Calls `testVictimServices()` for each victim

**Result:** Connectivity status

---

### Step 3: Service Discovery & Testing (`testVictimServices()`)

This is the **main validation step** that tests all services:

#### 3.1 Port Scanning (`scanOpenPorts()`)

**Method 1: Nmap (preferred)**
```bash
docker exec attacker nmap -p 21,22,23,25,53,80,135,139,443,445,1433,3306,5432,6379,8080,8443 --open -n victim-ip
```

**Method 2: Netcat (fallback)**
```bash
docker exec attacker nc -zv victim-ip 21
docker exec attacker nc -zv victim-ip 22
# ... tests each port individually
```

**Ports scanned:**
- Network: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS)
- Web: 80 (HTTP), 443 (HTTPS), 8080 (HTTP-alt), 8443 (HTTPS-alt)
- SMB: 135 (MSRPC), 139 (NetBIOS), 445 (Samba)
- Database: 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis)

**Result:** List of open ports

---

#### 3.2 Service Identification (`identifyServices()`)

Maps ports to services:
```javascript
21 → FTP
22 → SSH
23 → Telnet
80 → HTTP
443 → HTTPS
445 → Samba/SMB
3306 → MySQL
5432 → PostgreSQL
// etc.
```

**Result:** List of detected services

---

#### 3.3 Service-Specific Testing (`testService()`)

Tests each detected service:

**FTP (Port 21):**
- If challenge mentions "anonymous" → Tests anonymous login
- Otherwise → Just verifies port is open
- **Test:** `ftp -n victim-ip` with `user anonymous\npass\nls\nquit`

**Samba/SMB (Port 445):**
- Tests SMB port accessibility
- **Test:** `nc -zv victim-ip 445`

**SSH (Port 22):**
- Tests SSH connectivity
- **Test:** `nc -zv victim-ip 22`

**HTTP/HTTPS (Port 80/443):**
- Tests web server response
- **Test:** `curl -s -o /dev/null -w "%{http_code}" http://victim-ip`
- Checks for HTTP status codes (200-499)

**Telnet (Port 23):**
- Tests telnet connectivity
- **Test:** `nc -zv victim-ip 23`

**Databases (MySQL, PostgreSQL, etc.):**
- Verifies port is open
- **Test:** `nc -zv victim-ip 3306`

**Result:** Test results for each service

---

### Step 4: Challenge Requirements Check (`checkChallengeRequirements()`)

Analyzes challenge name/description and verifies requirements:

**Anonymous FTP Challenge:**
- Checks if FTP service (port 21) is accessible
- Tests anonymous login
- **Error if:** Anonymous login fails

**Samba/SMB Challenge:**
- Checks if SMB service (port 445) is accessible
- **Error if:** Port 445 not open

**Web Challenge:**
- Checks if HTTP/HTTPS service is accessible
- **Error if:** Port 80/443 not open

**Result:** Challenge-specific validation

---

## Error Handling

### Critical Errors (Block Deployment)
- No open ports detected
- Required service not accessible (e.g., FTP for FTP challenge)
- Anonymous login fails for anonymous FTP challenge

### Warnings (Don't Block Deployment)
- Service detected but specific test couldn't verify
- Optional services not accessible

---

## Example Validation Flow

### FTP Anonymous Challenge

```
1. Health Check
   ✅ Containers running
   ✅ IPs assigned
   ✅ Port 21 detected

2. Port Scanning
   ✅ Port 21 open (FTP)
   ✅ Port 22 open (SSH)

3. Service Testing
   ✅ FTP: Testing anonymous login...
      → user anonymous
      → pass (empty)
      → ls
      → Response: 230 Login successful ✅
   
4. Challenge Requirements
   ✅ Challenge mentions "anonymous FTP"
   ✅ FTP service accessible
   ✅ Anonymous login works

Result: ✅ Validation Passed
```

### Samba Challenge

```
1. Health Check
   ✅ Containers running
   ✅ IPs assigned

2. Port Scanning
   ✅ Port 445 open (Samba)
   ✅ Port 22 open (SSH)

3. Service Testing
   ✅ Samba: Port 445 accessible ✅
   ✅ SSH: Port 22 accessible ✅

4. Challenge Requirements
   ✅ Challenge mentions "samba"
   ✅ SMB service (port 445) accessible

Result: ✅ Validation Passed
```

---

## Current Implementation

**File:** `packages/ctf-automation/src/validation/post-deploy-validator.js`

**Key Methods:**
- `validate()` - Main entry point
- `testConnectivity()` - Tests attacker→victim connectivity
- `testVictimServices()` - Comprehensive service testing
- `scanOpenPorts()` - Port discovery
- `identifyServices()` - Port→service mapping
- `testService()` - Service-specific tests
- `checkChallengeRequirements()` - Challenge-specific validation

**When it runs:**
- Automatically after deployment (Phase 3 in orchestrator)
- Called from `orchestrator.js` line 506

---

## Improvements Made

1. ✅ **Comprehensive port scanning** - Scans all common ports, not just FTP
2. ✅ **Service identification** - Automatically identifies services from ports
3. ✅ **Service-specific tests** - Tests each service appropriately
4. ✅ **Challenge requirements** - Validates based on challenge description
5. ✅ **Error categorization** - Critical errors vs warnings

---

## Future Enhancements

- Add more service-specific tests (MySQL connection, PostgreSQL queries, etc.)
- Test service functionality beyond just port accessibility
- Validate service configurations (e.g., check vsftpd.conf for anonymous_enable)
- Test exploit paths (e.g., verify flag is accessible via FTP)

