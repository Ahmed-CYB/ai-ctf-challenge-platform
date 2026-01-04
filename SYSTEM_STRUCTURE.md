# System Structure - AI CTF Challenge Platform

## 📋 **Table of Contents**
1. [Overall Architecture](#overall-architecture)
2. [Directory Structure](#directory-structure)
3. [Service Components](#service-components)
4. [Agent System](#agent-system)
5. [Data Flow](#data-flow)
6. [Database Structure](#database-structure)
7. [Docker Services](#docker-services)
8. [Key Files and Their Purposes](#key-files-and-their-purposes)

---

## 🏗️ **Overall Architecture**

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                           │
│                    (Frontend - React + TypeScript)               │
│                         Port: 4000                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ HTTP/WebSocket
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                    BACKEND API SERVICE                           │
│                    (Express.js + PostgreSQL)                     │
│                         Port: 4002                               │
│  - User Authentication & Authorization                           │
│  - Session Management                                            │
│  - Challenge Metadata Storage                                    │
│  - Chat History Management                                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ HTTP API Calls
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                 CTF AUTOMATION SERVICE                           │
│              (Express.js + AI Agents + Docker)                   │
│                         Port: 4003                               │
│  - Challenge Creation (AI-powered)                               │
│  - Challenge Deployment (Docker Compose)                        │
│  - Guacamole Connection Management                               │
│  - Victim Machine Validation                                    │
│  - Tool Learning System                                         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                ┌────────────┼────────────┐
                │            │            │
                ▼            ▼            ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │  Docker  │  │Guacamole │  │PostgreSQL│
        │  Engine  │  │   MySQL  │  │  (Main)  │
        └──────────┘  └──────────┘  └──────────┘
```

---

## 📁 **Directory Structure**

```
AI CTF Challenge Platform/
│
├── packages/                          # Monorepo packages
│   ├── frontend/                      # React + TypeScript frontend
│   │   ├── src/
│   │   │   ├── components/           # React components
│   │   │   │   ├── CTFChatInterface.tsx
│   │   │   │   └── ...
│   │   │   ├── services/              # API service clients
│   │   │   └── types/                 # TypeScript type definitions
│   │   └── package.json
│   │
│   ├── backend/                       # Express.js backend API
│   │   ├── server.js                  # Main server file
│   │   ├── secure-session-manager.js  # Session management
│   │   └── package.json
│   │
│   ├── ctf-automation/                # CTF automation service (main logic)
│   │   ├── src/
│   │   │   ├── index.js               # Main API endpoint (/api/chat)
│   │   │   ├── classifier.js          # Request classification
│   │   │   ├── agents/                # AI agent system
│   │   │   │   ├── create-agent.js    # Challenge creation
│   │   │   │   ├── deploy-agent.js    # Challenge deployment
│   │   │   │   ├── universal-structure-agent.js  # Multi-machine challenge structure
│   │   │   │   ├── tool-installation-agent.js    # Dockerfile generation
│   │   │   │   ├── content/          # Content generation agents
│   │   │   │   │   ├── network-content-agent.js
│   │   │   │   │   ├── web-content-agent.js
│   │   │   │   │   └── crypto-content-agent.js
│   │   │   │   ├── pre-deploy-validator-agent.js
│   │   │   │   │   ├── post-deploy-validator.js
│   │   │   │   │   ├── victim-validation-agent.js  # NEW: Auto-fix victim machines
│   │   │   │   │   └── auto-error-fixer.js
│   │   │   │   ├── questions-agent.js
│   │   │   │   └── ...
│   │   │   ├── docker-manager.js      # Docker operations
│   │   │   ├── git-manager.js         # Git repository management
│   │   │   ├── subnet-allocator.js    # IP subnet allocation
│   │   │   ├── guacamole-postgresql-manager.js  # Guacamole DB operations
│   │   │   ├── session-guacamole-manager.js     # Session-based Guacamole users
│   │   │   ├── db-manager.js          # PostgreSQL operations
│   │   │   ├── tool-learning-service.js          # Tool installation learning
│   │   │   └── ...
│   │   └── package.json
│   │
│   └── shared/                        # Shared TypeScript types/config
│       └── src/
│           └── config.ts
│
├── docker/                            # Docker Compose configurations
│   ├── docker-compose.app.yml        # Frontend + Backend
│   ├── docker-compose.ctf.yml        # CTF Automation Service
│   ├── docker-compose.infrastructure.yml  # PostgreSQL, MySQL, etc.
│   └── docker-compose.dev.yml
│
├── database/                          # Database migrations
│   └── migrations/
│       ├── 001_add_session_columns.sql
│       ├── 008_session_improvements.sql
│       └── ...
│
├── challenges-repo/                   # Git repository for challenges
│   └── challenges/                    # Individual challenge directories
│       └── <challenge-name>/
│           ├── docker-compose.yml
│           ├── README.md
│           ├── <machine-name>/
│           │   ├── Dockerfile
│           │   └── <service-config-files>
│           └── ...
│
├── .env                               # Environment variables
├── package.json                       # Root package.json
└── README.md
```

---

## 🔧 **Service Components**

### 1. **Frontend Service** (Port 4000)
- **Technology**: React + TypeScript + Vite
- **Purpose**: User interface for interacting with the platform
- **Key Features**:
  - Chat interface for challenge creation/deployment
  - Challenge browsing and management
  - User authentication UI
  - Guacamole connection links
- **Main Files**:
  - `packages/frontend/src/components/CTFChatInterface.tsx`

### 2. **Backend API Service** (Port 4002)
- **Technology**: Express.js + PostgreSQL
- **Purpose**: Main API server for user management and data storage
- **Key Features**:
  - User authentication & authorization (JWT)
  - Session management
  - Challenge metadata storage
  - Chat history persistence
  - Database operations
- **Main Files**:
  - `packages/backend/server.js`

### 3. **CTF Automation Service** (Port 4003)
- **Technology**: Express.js + OpenAI/Anthropic + Docker API
- **Purpose**: AI-powered challenge creation and deployment
- **Key Features**:
  - Challenge creation using AI
  - Docker container deployment
  - Guacamole connection setup
  - Victim machine validation & auto-fix
  - Tool learning system
- **Main Files**:
  - `packages/ctf-automation/src/index.js` (main API endpoint)

---

## 🤖 **Agent System**

The CTF automation service uses a multi-agent architecture:

### **Core Agents**

1. **Classifier** (`classifier.js`)
   - Classifies user requests (Create, Deploy, Question, etc.)
   - Routes to appropriate agent

2. **Create Agent** (`create-agent.js`)
   - Handles challenge creation requests
   - Generates challenge names
   - Coordinates with universal-structure-agent

3. **Universal Structure Agent** (`universal-structure-agent.js`)
   - Generates multi-machine challenge structures
   - Creates docker-compose.yml
   - Coordinates with content agents

4. **Content Agents** (`agents/content/`)
   - **Network Content Agent**: Generates network service challenge content
   - **Web Content Agent**: Generates web application challenge content
   - **Crypto Content Agent**: Generates cryptography challenge content

5. **Tool Installation Agent** (`tool-installation-agent.js`)
   - Generates Dockerfiles for machines
   - Handles package installation
   - Creates startup scripts

6. **Deploy Agent** (`deploy-agent.js`)
   - Orchestrates challenge deployment
   - Sets up Guacamole connections
   - Returns deployment results

7. **Pre-Deploy Validator Agent** (`pre-deploy-validator-agent.js`)
   - Validates challenge files before deployment
   - Applies automatic fixes
   - Checks for common errors

8. **Post-Deploy Validator Agent** (`post-deploy-validator.js`)
   - Validates deployed challenges
   - Tests functionality
   - AI-powered validation

9. **Victim Validation Agent** (`victim-validation-agent.js`) ⭐ **NEW**
   - Validates victim machine accessibility
   - Automatically fixes startup script errors
   - Ensures containers are running
   - Verifies IP assignment and services

10. **Auto-Error Fixer** (`auto-error-fixer.js`)
    - Detects deployment errors
    - Applies automatic fixes
    - Retries deployment

11. **Questions Agent** (`questions-agent.js`)
    - Answers CTF-related questions
    - Provides challenge-specific commands

12. **Retriever Agent** (`retriever-agent.js`)
    - Lists available challenges
    - Retrieves challenge information

---

## 🔄 **Data Flow**

### **Challenge Creation Flow**

```
User Request
    │
    ▼
Frontend (Port 4000)
    │
    ▼
Backend API (Port 4002) ──┐
    │                      │ (Optional: Save to DB)
    ▼                      │
CTF Automation (Port 4003) │
    │                      │
    ├─► Classifier ──► Create Agent
    │                      │
    │                      ├─► Universal Structure Agent
    │                      │       │
    │                      │       ├─► Network/Web/Crypto Content Agent
    │                      │       │
    │                      │       └─► Tool Installation Agent
    │                      │
    │                      └─► Git Manager (Save to challenges-repo)
    │
    └─► Response ──► Backend ──► Frontend ──► User
```

### **Challenge Deployment Flow**

```
User: "deploy <challenge-name>"
    │
    ▼
CTF Automation Service
    │
    ├─► Deploy Agent
    │       │
    │       ├─► Git Manager (Clone/Pull challenge)
    │       │
    │       ├─► Docker Manager
    │       │       │
    │       │       ├─► docker compose up --build
    │       │       │
    │       │       └─► Get container IPs
    │       │
    │       ├─► Victim Validation Agent ⭐
    │       │       │
    │       │       ├─► Check container status
    │       │       ├─► Fix startup script (if needed)
    │       │       ├─► Start container (if stopped)
    │       │       ├─► Verify IP assignment
    │       │       └─► Verify services running
    │       │
    │       └─► Guacamole Manager
    │               │
    │               ├─► Create session user
    │               ├─► Create connection
    │               └─► Grant access
    │
    └─► Return deployment result
```

---

## 🗄️ **Database Structure**

### **PostgreSQL (Main Database)**
- **Purpose**: Platform data storage
- **Connection**: `postgresql://ctf_user@postgres-new:5432/ctf_platform`
- **Key Tables**:
  - `users` - User accounts
  - `sessions` - User sessions
  - `session_guacamole_users` - Session-to-Guacamole user mapping
  - `session_activity` - Session activity tracking
  - `chat_messages` - Chat history
  - `challenges` - Challenge metadata
  - `os_images` - Validated OS images
  - `tool_installations` - Tool installation methods (L2 cache)
  - `package_mappings` - Package name mappings

### **MySQL (Guacamole Database)**
- **Purpose**: Guacamole connection management
- **Connection**: `mysql://guacamole_user@ctf-guacamole-db-new:3306/guacamole_db`
- **Key Tables**:
  - `guacamole_user` - Guacamole users
  - `guacamole_connection` - SSH/RDP connections
  - `guacamole_connection_parameter` - Connection parameters (hostname, port, etc.)

---

## 🐳 **Docker Services**

### **Application Services** (`docker-compose.app.yml`)
- `ctf-backend-new` (Port 4002) - Backend API
- `ctf-frontend-new` (Port 4000) - Frontend UI

### **CTF Automation Service** (`docker-compose.ctf.yml`)
- `ctf-automation-new` (Port 4003) - CTF automation service

### **Infrastructure Services** (`docker-compose.infrastructure.yml`)
- `postgres-new` (Port 5432) - PostgreSQL database
- `ctf-guacamole-db-new` (Port 3306) - MySQL for Guacamole
- `ctf-guacd-new` - Guacamole daemon
- `ctf-guacamole-new` (Port 8081) - Guacamole web interface

### **Challenge Containers** (Dynamically Created)
- Each challenge creates its own Docker network
- Attacker container (Kali Linux with tools)
- Victim container(s) (vulnerable services)
- Connected to challenge-specific network (e.g., `172.23.x.x/24`)

---

## 📄 **Key Files and Their Purposes**

### **Core Service Files**

| File | Purpose |
|------|---------|
| `packages/frontend/src/components/CTFChatInterface.tsx` | Main chat UI component |
| `packages/backend/server.js` | Backend API server |
| `packages/ctf-automation/src/index.js` | CTF automation API endpoint (`/api/chat`) |

### **Agent Files**

| File | Purpose |
|------|---------|
| `packages/ctf-automation/src/classifier.js` | Request classification |
| `packages/ctf-automation/src/agents/create-agent.js` | Challenge creation |
| `packages/ctf-automation/src/agents/deploy-agent.js` | Challenge deployment |
| `packages/ctf-automation/src/agents/universal-structure-agent.js` | Multi-machine structure generation |
| `packages/ctf-automation/src/agents/tool-installation-agent.js` | Dockerfile generation |
| `packages/ctf-automation/src/agents/victim-validation-agent.js` | Victim machine validation & auto-fix |

### **Manager Files**

| File | Purpose |
|------|---------|
| `packages/ctf-automation/src/docker-manager.js` | Docker operations (deploy, inspect, etc.) |
| `packages/ctf-automation/src/git-manager.js` | Git repository management |
| `packages/ctf-automation/src/subnet-allocator.js` | IP subnet allocation |
| `packages/ctf-automation/src/guacamole-postgresql-manager.js` | Guacamole DB operations |
| `packages/ctf-automation/src/session-guacamole-manager.js` | Session-based Guacamole users |
| `packages/ctf-automation/src/db-manager.js` | PostgreSQL operations |

### **Configuration Files**

| File | Purpose |
|------|---------|
| `.env` | Environment variables (API keys, DB credentials, etc.) |
| `docker/docker-compose.app.yml` | Frontend + Backend services |
| `docker/docker-compose.ctf.yml` | CTF automation service |
| `docker/docker-compose.infrastructure.yml` | Database services |

---

## 🔐 **Security & Session Management**

### **Session System**
- **Frontend**: Generates cryptographically secure session IDs
- **Backend**: Validates and stores sessions in PostgreSQL
- **CTF Automation**: Uses session ID for Guacamole user creation
- **Guacamole**: One user per session (isolated access)

### **Session Flow**
```
1. Frontend generates session ID → localStorage
2. Frontend sends request with session ID
3. Backend validates session ID
4. CTF Automation receives session ID
5. Session Guacamole Manager creates/retrieves Guacamole user
6. Guacamole connection created with session-specific user
```

---

## 🌐 **Network Architecture**

### **Docker Networks**

1. **ctf-network** (External)
   - Connects all services (frontend, backend, CTF automation, databases)
   - Used for inter-service communication

2. **ctf-instances-network** (External)
   - Connects Guacamole daemon (`ctf-guacd-new`) to challenge networks
   - Allows Guacamole to access attacker containers

3. **Challenge-Specific Networks** (Dynamically Created)
   - One network per challenge (e.g., `challenge-name_net`)
   - IP range: `172.23.{userId}.0/24`
   - Attacker IP: `.3` (fixed)
   - Victim IPs: `.4+` (randomized, no duplicates)

---

## 🔄 **Challenge Lifecycle**

1. **Creation**
   - User requests challenge creation
   - AI generates challenge structure
   - Files saved to `challenges-repo`
   - Committed and pushed to GitHub

2. **Deployment**
   - User requests deployment
   - Challenge cloned from repository
   - Docker Compose builds and starts containers
   - Victim validation agent ensures containers are running
   - Guacamole connection created
   - User receives access URL

3. **Usage**
   - User accesses attacker machine via Guacamole
   - User exploits victim machine
   - User retrieves flag

4. **Cleanup**
   - Containers stopped/removed
   - Networks removed
   - Guacamole connections cleaned up

---

## 📊 **Key Features**

### **AI-Powered Challenge Creation**
- Uses OpenAI GPT-4 / Anthropic Claude
- Generates realistic scenarios
- Creates working Docker configurations
- References Vulhub for correct configurations

### **Automatic Error Fixing**
- Pre-deployment validation and fixes
- Post-deployment error detection
- Auto-error-fixer for common issues
- Victim validation agent for container issues

### **Tool Learning System**
- Discovers tool installation methods
- Tests installations in Docker
- Caches successful methods (L1: memory, L2: database)
- Reuses methods for similar OS images

### **Session-Based Isolation**
- Each user session gets isolated Guacamole user
- Prevents cross-session access
- Automatic cleanup of expired sessions

---

## 🚀 **Quick Start**

1. **Start Infrastructure**:
   ```bash
   docker-compose -f docker/docker-compose.infrastructure.yml up -d
   ```

2. **Start Application**:
   ```bash
   docker-compose -f docker/docker-compose.app.yml up -d
   ```

3. **Start CTF Automation**:
   ```bash
   docker-compose -f docker/docker-compose.ctf.yml up -d
   ```

4. **Access**:
   - Frontend: http://localhost:4000
   - Backend API: http://localhost:4002
   - CTF Automation: http://localhost:4003
   - Guacamole: http://localhost:8081

---

## 📝 **Notes**

- All services use new ports (4000, 4002, 4003) with old ports (3000, 3002, 3003) as backup
- Challenges are stored in `challenges-repo/` directory (Git repository)
- Each challenge gets its own isolated Docker network
- Victim validation agent ensures containers are always accessible
- Session system provides secure, isolated access per user

---

**Last Updated**: 2025-01-03
**Version**: 2.0 (with Victim Validation Agent)


