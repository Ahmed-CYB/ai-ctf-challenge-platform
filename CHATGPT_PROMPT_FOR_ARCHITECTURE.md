# ChatGPT Prompt for Architecture Diagram

## Quick Summary:
- **Frontend (4000)** → **Backend (4002)** for auth/data
- **Frontend (4000)** → **CTF Automation (4003)** DIRECTLY for chat
- **Backend** → **PostgreSQL** only
- **CTF Automation** → **PostgreSQL** + **MySQL** + **Docker** + **External APIs**

---

Copy and paste the prompt below to ChatGPT:

---

**PROMPT:**

Create a Mermaid graph TB (top to bottom) system architecture diagram for an AI CTF Challenge Platform. Make it simple and clear, not too complicated.

## Components:

1. **User Layer**: User Browser

2. **Frontend Layer** (Port 4000):
   - React + TypeScript (Vite)
   - Dashboard UI, Chat Interface, Challenge Management

3. **Backend Layer** (Port 4002):
   - Express.js REST API Server
   - JWT Authentication (jsonwebtoken)
   - Password Hashing (bcryptjs)
   - Handles: Authentication, Sessions, Chat History, User Management

4. **CTF Automation Layer** (Port 4003):
   - Node.js Service
   - Classifier Agent
   - Create Agent
   - Deploy Agent
   - Validator Agent
   - Questions Agent

5. **Database Layer**:
   - PostgreSQL 15 (Port 5433) - Main application database
   - MySQL 8.0 (Port 3307) - Guacamole database only

6. **Container Infrastructure**:
   - Docker Engine (Docker API)
   - Apache Guacamole (Port 8081)
   - Challenge Containers (Attacker & Victim machines)

7. **External Services**:
   - GitHub Repository
   - OpenAI API (GPT-4)
   - Anthropic API (Claude)

## Required Connections (Draw arrows with labels):

**User Flow:**
- User → Frontend: "HTTP Requests"
- Frontend → Backend: "REST API: POST /api/auth/login, GET /api/challenges"
- Frontend → CTF Automation: "REST API: POST /api/chat" (DIRECT connection, port 4003)

**Backend Internal:**
- Backend → JWT: "Generate/Verify Tokens"
- Backend → Bcrypt: "Hash/Compare Passwords"
- Backend → PostgreSQL: "SQL: INSERT, SELECT, UPDATE"

**CTF Automation Flow:**
- CTF Automation → Classifier: "Route Request"
- Classifier → Create Agent: "Intent: CREATE"
- Classifier → Deploy Agent: "Intent: DEPLOY"
- Classifier → Questions Agent: "Intent: QUESTION"
- Deploy Agent → Validator Agent: "Validate Challenge"

**Data Storage:**
- CTF Automation → PostgreSQL: "SQL: SELECT, INSERT, UPDATE"
- CTF Automation → MySQL: "SQL: Create Guacamole Users"
- Guacamole → MySQL: "SQL: Read Connection Configs"

**Container Management:**
- CTF Automation → Docker Engine: "Docker API: docker compose up"
- Docker Engine → Challenge Containers: "Create Containers"
- CTF Automation → Guacamole: "Create Connections"
- Guacamole → Challenge Containers: "SSH/RDP via WebSocket"

**External Services:**
- Create Agent → GitHub: "Git Push/Commit"
- Deploy Agent → GitHub: "Git Clone"
- Create Agent → OpenAI: "API: Generate Content"
- Create Agent → Anthropic: "API: Validate Structure"
- Deploy Agent → OpenAI: "API: Error Analysis"
- Deploy Agent → Anthropic: "API: Deployment Validation"

## Critical Rules:

1. Frontend connects DIRECTLY to CTF Automation (port 4003) - NOT through Backend
2. Backend only connects to PostgreSQL (not CTF Automation)
3. JWT and Bcrypt are INSIDE Backend layer (not separate boxes)
4. Use subgraphs to group related components
5. Use different colors for each layer
6. Keep it simple - don't overcomplicate
7. Show bidirectional arrows where data flows both ways
8. Use clear, short labels on arrows

Format: Use Mermaid graph TB syntax with proper styling. Make it professional and easy to read.

---

