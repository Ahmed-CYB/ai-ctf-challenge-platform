# CTF Challenge Platform - System Architecture

## Overview

This document provides a comprehensive overview of how the CTF Challenge Platform works, including all automation logic, network architecture, deployment flow, and error handling mechanisms.

---

## Table of Contents

1. [System Components](#system-components)
2. [Network Architecture](#network-architecture)
3. [Challenge Deployment Flow](#challenge-deployment-flow)
4. [Guacamole Integration](#guacamole-integration)
5. [Error Handling & Auto-Fixing](#error-handling--auto-fixing)
6. [IP Address Management](#ip-address-management)
7. [Docker Container Management](#docker-container-management)
8. [File Structure](#file-structure)

---

## System Components

### 1. **Frontend** (`packages/frontend`)
- React-based web interface
- Communicates with backend via REST API
- Real-time chat interface for CTF challenge interaction

### 2. **Backend API** (`packages/backend`)
- Express.js REST API server
- Handles user authentication, sessions, and message storage
- Routes CTF requests to CTF Automation service

### 3. **CTF Automation Service** (`packages/ctf-automation`)
- Main orchestration service for challenge creation and deployment
- Contains multiple specialized agents:
  - **Classifier Agent**: Categorizes user requests (Create/Deploy/Question/ChallengeInfo)
  - **Create Agent**: Generates new CTF challenges
  - **Deploy Agent**: Deploys existing challenges
  - **Questions Agent**: Answers general CTF questions
  - **Guacamole Agent**: Manages Guacamole connections
  - **Tool Installation Agent**: Generates Dockerfiles with required tools
  - **Universal Structure Agent**: Creates multi-machine challenge structures
  - **Auto Error Fixer**: Automatically fixes common deployment errors
  - **Pre-Deploy Validator**: Validates and fixes Dockerfiles before deployment

### 4. **Guacamole Service** (`docker/docker-compose.guacamole.yml`)
- Apache Guacamole for browser-based SSH access
- `guacd` daemon handles SSH connections
- MySQL database stores connection configurations

### 5. **Docker Infrastructure**
- Docker Compose for multi-container orchestration
- Isolated networks per challenge
- Shared `ctf-instances-network` for Guacamole access

---

## Network Architecture

### Network Types

#### 1. **Challenge-Specific Networks** (`ctf-{challenge-name}-net`)
- **Purpose**: Isolated network for each challenge instance
- **Subnet Range**: `172.{20-30}.{userId}.0/24`
- **IP Allocation**:
  - `.1` - Gateway
  - `.2` - Reserved
  - `.3` - Attacker machine (fixed)
  - `.4-253` - Victim machines (randomized)
  - `.254` - Database (if needed)
  - `.255` - Broadcast

#### 2. **Shared Network** (`ctf-instances-network`)
- **Purpose**: Allows Guacamole to discover and connect to challenge networks
- **Type**: External bridge network
- **Usage**: Attacker containers connect to both challenge network AND this network

### Network Connection Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Challenge Network                          │
│              (172.23.156.0/24 - Isolated)                     │
│                                                                │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Attacker    │    │   Victim 1   │    │   Victim 2   │   │
│  │  172.23.156.3│    │ 172.23.156.4 │    │ 172.23.156.5 │   │
│  └──────┬───────┘    └──────────────┘    └──────────────┘   │
│         │                                                      │
│         │ (also connected to)                                  │
└─────────┼────────────────────────────────────────────────────┘
          │
          │
┌─────────┼────────────────────────────────────────────────────┐
│         │         ctf-instances-network                       │
│         │         (Shared Network)                            │
│         │                                                      │
│  ┌──────▼───────┐    ┌──────────────────┐                   │
│  │  Attacker    │    │  ctf-guacd-new    │                   │
│  │  (dual-homed)│    │  (Guacamole)      │                   │
│  └──────────────┘    └──────────────────┘                   │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Guacamole Web UI (port 8081)                       │   │
│  │  Connects via guacd to attacker at 172.23.156.3     │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

### Key Network Fixes

1. **Guacd Connection to Challenge Networks**
   - Before deployment: Disconnect guacd from old challenge networks
   - After deployment: Connect guacd to new challenge network
   - This allows Guacamole to reach attacker at `.3` IP

2. **Network Removal Error Handling**
   - Problem: Docker Compose tries to remove network while guacd is connected
   - Solution: Disconnect guacd before deployment, handle removal errors gracefully
   - Result: Deployment succeeds even if network removal fails (containers are running)

---

## Challenge Deployment Flow

### Step-by-Step Process

```
1. User Request
   ↓
2. Classifier Agent (categorizes request)
   ↓
3. Route to appropriate agent:
   ├─ Create Agent → Generate challenge
   ├─ Deploy Agent → Deploy challenge
   ├─ Questions Agent → Answer question
   └─ ChallengeInfo Agent → Get challenge info
   ↓
4. For Deploy Agent:
   ├─ Validate challenge exists
   ├─ Allocate subnet/IPs
   ├─ Pre-deploy validation (fix Dockerfiles)
   ├─ Deploy containers (docker compose up)
   │  ├─ Disconnect guacd from old networks
   │  ├─ Build containers
   │  ├─ Start containers
   │  └─ Handle network removal errors gracefully
   ├─ Connect guacd to challenge network
   ├─ Get container IPs
   ├─ Create Guacamole user (session-based)
   ├─ Create Guacamole connection
   └─ Grant access to user
   ↓
5. Return deployment info to user
```

### Deployment Error Handling

#### Pre-Deployment Fixes
- **CentOS → Rocky Linux**: Replaces EOL CentOS with Rocky Linux 9
- **Alpine telnet**: Replaces `telnet` with `busybox-extras`
- **Rocky Linux packages**: Fixes `iputils-ping` → `iputils`, removes `xinetd`
- **Curl conflicts**: Adds `--allowerasing` for curl on Rocky Linux
- **Version attribute**: Removes obsolete `version: '3.8'` from docker-compose.yml

#### During Deployment
- **Network removal errors**: Handled gracefully (not fatal)
- **Auto-error fixer**: Analyzes errors and applies fixes automatically
- **Retry logic**: Up to 3 deployment attempts with fixes

#### Post-Deployment
- **Connection validation**: Verifies containers are running
- **IP verification**: Confirms IP addresses are correct
- **Guacamole setup**: Creates user and connection automatically

---

## Guacamole Integration

### User Management

#### Session-Based Users
- **Naming**: `ctf_{sessionId}` (e.g., `ctf_qweyolnczg`)
- **Password**: Randomly generated, hashed with SHA-256 + salt
- **Permissions**: READ access only (no admin)
- **Lifecycle**: Persists across sessions (reused if exists)

#### Password Hashing
```javascript
// Generate 32-byte random salt
const salt = crypto.randomBytes(32).toString('hex');

// Hash: SHA256(password + salt)
const hash = crypto.createHash('sha256')
  .update(password, 'utf8')
  .update(salt, 'hex')
  .digest('hex');
```

### Connection Management

#### Connection Creation
1. **Connection Name**: `{challengeName}_{sessionId}` (unique per session)
2. **Hostname**: Attacker IP on challenge network (e.g., `172.23.156.3`)
3. **Port**: 22 (SSH)
4. **Username**: `kali`
5. **Password**: `kali`
6. **Protocol**: SSH

#### Connection Flow
```
User → Guacamole Web UI → guacd → SSH → Attacker Container
                                      (172.23.156.3:22)
```

### Network Requirements

1. **Guacd must be connected to challenge network**
   - Allows guacd to reach attacker at `.3` IP
   - Connection happens automatically after deployment

2. **Attacker container is dual-homed**
   - Connected to challenge network (`.3` IP)
   - Connected to `ctf-instances-network` (for discovery)

---

## Error Handling & Auto-Fixing

### Auto-Error Fixer (`auto-error-fixer.js`)

#### Common Fixes

1. **CentOS EOL Repository Error**
   - **Pattern**: `Cannot find a valid baseurl for repo: base/7/x86_64`
   - **Fix**: Replace `FROM centos` with `FROM rockylinux:9`, update `yum` to `dnf`

2. **Alpine Telnet Package Error**
   - **Pattern**: `telnet (no such package)`
   - **Fix**: Replace `telnet` with `busybox-extras` in Dockerfiles

3. **Rocky Linux Package Name Errors**
   - **Pattern**: `No match for argument: iputils-ping`
   - **Fix**: Replace `iputils-ping` with `iputils`
   - **Pattern**: `No match for argument: xinetd`
   - **Fix**: Remove `xinetd` from package list

4. **Curl-Minimal Conflict**
   - **Pattern**: `curl-minimal conflicts with curl`
   - **Fix**: Add `--allowerasing` to `dnf install` commands

5. **Network Removal Errors**
   - **Pattern**: `network has active endpoints`
   - **Fix**: Disconnect guacd before deployment, handle gracefully

### Pre-Deploy Validator (`pre-deploy-validator-agent.js`)

- Scans all Dockerfiles before deployment
- Applies fixes proactively
- Commits changes to Git repository

---

## IP Address Management

### Subnet Allocation (`subnet-allocator.js`)

#### Allocation Algorithm
1. **Deterministic Hashing**: Uses `challengeName + userId` to generate subnet
2. **Subnet Range**: `172.{20-30}.{userId}.0/24`
3. **Conflict Detection**: Checks existing allocations
4. **IP Assignment**:
   - Attacker: Always `.3` (fixed)
   - Victims: Randomized from `.4-253` (no duplicates)
   - Database: `.254` (if needed)

#### Validation
- **Duplicate IP Prevention**: Validates no duplicate IPs in victim allocation
- **Cross-Service Validation**: Ensures no conflicts between victims, database, API

### IP Usage

#### Challenge Network IP (`.3`)
- **Primary IP**: Used for Guacamole connections
- **Direct Access**: Guacd connects directly to this IP
- **Isolation**: Each challenge has its own network

#### ctf-instances-network IP
- **Legacy**: Previously used for Guacamole (deprecated)
- **Current**: Only used for network discovery
- **Note**: Guacamole now uses challenge network IP directly

---

## Docker Container Management

### Container Types

#### 1. **Attacker Container**
- **Base Image**: `kalilinux/kali-rolling:latest`
- **Capabilities**: `NET_RAW`, `NET_ADMIN` (for nmap)
- **Networks**: Challenge network + `ctf-instances-network`
- **IP**: Always `.3` on challenge network
- **Tools**: Pre-installed with nmap, wireshark, etc.
- **Nmap Configuration**: Wrapper script forces `--unprivileged` mode

#### 2. **Victim Containers**
- **Base Images**: Ubuntu, Rocky Linux, Alpine (varies)
- **Services**: FTP, SMB, HTTP, SSH, etc.
- **Networks**: Challenge network only
- **IPs**: Randomized from `.4-253`

#### 3. **Database Containers** (if needed)
- **Base Image**: `postgres:15-alpine` or `mariadb`
- **Network**: Challenge network only
- **IP**: `.254`

### Docker Compose Structure

```yaml
services:
  attacker:
    build:
      context: ./attacker
      dockerfile: Dockerfile.attacker
    container_name: ctf-{challenge}-attacker
    cap_add:
      - NET_RAW
      - NET_ADMIN
    networks:
      ctf-{challenge}-net:
        ipv4_address: 172.23.156.3
      ctf-instances-network: {}
  
  victim:
    build:
      context: ./victim
      dockerfile: Dockerfile
    container_name: ctf-{challenge}-victim
    networks:
      ctf-{challenge}-net:
        ipv4_address: 172.23.156.4

networks:
  ctf-{challenge}-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.23.156.0/24
          gateway: 172.23.156.1
  ctf-instances-network:
    external: true
```

### Deployment Process

1. **Pre-Deployment**
   - Disconnect guacd from old challenge networks
   - Validate and fix Dockerfiles
   - Allocate subnet and IPs

2. **Deployment**
   - Run `docker compose up --build -d`
   - Handle network removal errors gracefully
   - Build and start containers

3. **Post-Deployment**
   - Connect guacd to challenge network
   - Get container IPs
   - Create Guacamole user and connection
   - Grant access

---

## File Structure

### Key Files

```
packages/ctf-automation/src/
├── index.js                          # Main API endpoint
├── classifier.js                      # Request classification
├── docker-manager.js                  # Docker operations
├── subnet-allocator.js                # IP/subnet management
├── git-manager.js                     # Git operations
├── agents/
│   ├── create-agent.js                # Challenge creation
│   ├── deploy-agent.js                 # Challenge deployment
│   ├── questions-agent.js              # Q&A handling
│   ├── guacamole-agent.js              # Guacamole management
│   ├── tool-installation-agent.js      # Dockerfile generation
│   ├── universal-structure-agent.js     # Multi-machine structure
│   ├── auto-error-fixer.js             # Error auto-fixing
│   └── pre-deploy-validator-agent.js   # Pre-deployment validation
├── session-guacamole-manager.js        # Session-based Guacamole users
└── guacamole-postgresql-manager.js     # Guacamole database operations
```

### Challenge Repository Structure

```
challenges/
└── {challenge-name}/
    ├── docker-compose.yml              # Container orchestration
    ├── README.md                        # Challenge description
    ├── attacker/
    │   └── Dockerfile.attacker          # Attacker container
    ├── victim/
    │   ├── Dockerfile                   # Victim container
    │   └── {service-files}              # Service configurations
    └── {other-machines}/                # Additional machines
```

---

## Key Fixes Applied

### 1. Network Removal Error
- **Problem**: Docker Compose fails when removing network with active endpoints
- **Solution**: Disconnect guacd before deployment, handle errors gracefully
- **Location**: `docker-manager.js:472-550`

### 2. Nmap Permission Error
- **Problem**: `nmap: Operation not permitted`
- **Solution**: Added `cap_add: [NET_RAW, NET_ADMIN]` to attacker service
- **Location**: `attacker-image-generator.js:506-509`, `universal-structure-agent.js:1167-1169`

### 3. Obsolete Version Attribute
- **Problem**: Docker Compose v2 warns about `version: '3.8'`
- **Solution**: Removed version attribute from generated docker-compose.yml
- **Location**: `universal-structure-agent.js:1128`, `attacker-image-generator.js:565`

### 4. Guacamole Connection IP
- **Problem**: Guacamole connected to wrong IP (ctf-instances-network)
- **Solution**: Use challenge network IP (`.3`) directly, connect guacd to challenge network
- **Location**: `docker-manager.js:625-680`, `index.js:545`

### 5. Challenge Name Uniqueness
- **Problem**: System reused existing challenge names
- **Solution**: Enhanced `generateUniqueChallengeName()` with similarity detection
- **Location**: `git-manager.js:generateUniqueChallengeName()`

### 6. OS-Specific Package Issues
- **Problem**: Package name mismatches (telnet, iputils-ping, xinetd)
- **Solution**: Package mapping database + pre-deployment fixes
- **Location**: `package-mapping-db-manager.js`, `pre-deploy-validator-agent.js`

---

## Best Practices

### 1. **Network Isolation**
- Each challenge gets its own isolated network
- No cross-challenge communication
- Gateway at `.1`, attacker at `.3` (consistent)

### 2. **Error Handling**
- Always handle network removal errors gracefully
- Pre-validate Dockerfiles before deployment
- Auto-fix common errors automatically

### 3. **Guacamole Integration**
- Use session-based users (reusable)
- Connect guacd to challenge network after deployment
- Use challenge network IP (`.3`) for connections

### 4. **Container Capabilities**
- Attacker containers need `NET_RAW` and `NET_ADMIN` for nmap
- Use unprivileged mode wrapper for nmap (security)
- Capabilities allow binary execution, wrapper handles permissions

### 5. **IP Management**
- Always validate for duplicate IPs
- Use deterministic hashing for subnet allocation
- Fixed IP for attacker (`.3`), randomized for victims

---

## Troubleshooting

### Deployment Fails with Network Error
1. Check if guacd is connected to old network
2. Disconnect guacd manually: `docker network disconnect {network} ctf-guacd-new`
3. Retry deployment

### Nmap Not Working
1. Check `cap_add` in docker-compose.yml
2. Verify nmap wrapper script exists
3. Rebuild container: `docker compose up --build`

### Guacamole Connection Fails
1. Verify guacd is connected to challenge network
2. Check attacker IP is correct (`.3` on challenge network)
3. Verify SSH is running in attacker container

### Challenge Name Conflicts
1. System automatically generates unique names
2. Check existing challenges: `git-manager.listChallenges()`
3. Manual override: Use specific challenge name in request

---

## Summary

The CTF Challenge Platform is a comprehensive automation system that:

1. **Creates** CTF challenges with AI-generated content
2. **Deploys** challenges in isolated Docker networks
3. **Manages** Guacamole access for browser-based SSH
4. **Handles** errors automatically with intelligent fixes
5. **Validates** all configurations before deployment

The system is designed to be robust, automated, and user-friendly, with extensive error handling and auto-fixing capabilities.

