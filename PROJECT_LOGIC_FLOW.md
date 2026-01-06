# AI CTF Challenge Platform - Project Logic Flow

## Overview

This document describes the complete user flow and logic for the AI CTF Challenge Platform based on the actual implementation.

---

## User Flow

### 1. Challenge Creation Flow

```
User Request → Chat Interface → AI Processing → Challenge Created → User Confirmation
```

**Steps:**
1. User asks for challenge creation via chat (e.g., "create an FTP challenge")
2. System processes request through AI agents:
   - **OpenAI GPT-4o**: Generates challenge structure and content
   - **Anthropic Claude Sonnet 4**: Validates and designs challenge
3. Challenge files are generated:
   - Dockerfiles (victim, attacker)
   - docker-compose.yml
   - README.md
   - Setup scripts
4. Challenge is saved to local Git repository
5. User receives confirmation: "Challenge [name] has been created successfully!"

**Important:** 
- Challenge is **automatically associated with user_id** when saved to database
- Challenge is stored in Git repository (not yet in database until user saves it)

---

### 2. Post-Creation Options

After challenge creation, user has two options:

#### Option A: Save Challenge (Private)
- User can save the challenge to database
- Challenge is saved as **private** with `user_id` association
- Challenge is stored in PostgreSQL `challenges` table
- Only this user can see their saved challenges

#### Option B: Deploy Challenge
- User can deploy the challenge immediately
- Deployment process:
  1. Pulls challenge from Git repository
  2. Validates Dockerfiles and configuration
  3. Builds and starts Docker containers
  4. Creates isolated network for challenge
  5. Assigns IP addresses (attacker + victims)
  6. Creates Guacamole connection

---

### 3. Deployment Flow

```
Deploy Request → Validation → Docker Build → Container Start → Guacamole Setup → Access Credentials
```

**Steps:**
1. User requests deployment: "deploy [challenge-name]"
2. System validates challenge files (pre-deployment validation using Anthropic Claude)
3. Docker containers are built and started
4. Guacamole user account is created for this session
5. Guacamole connection is created with Kali Linux access
6. User receives:
   - **Guacamole URL**: Browser-based SSH access
   - **Username**: Session-specific username
   - **Password**: Session-specific password
   - **Connection Instructions**: How to access the challenge

**Important:**
- Each deployment creates a **session-based Guacamole user**
- User accesses challenge via **Kali Linux connection** from Guacamole
- Challenge environment is isolated in its own Docker network

---

### 4. Challenge Access & Solving Flow

```
Access Challenge → Explore Environment → Ask for Hints → Find Flag → Submit Flag → Verification
```

**Steps:**
1. User accesses challenge via Guacamole (Kali Linux connection)
2. User explores the challenge environment
3. User can ask chatbot for:
   - **Questions**: General questions about the challenge
   - **Hints**: Specific hints to help solve the challenge
4. User finds the flag
5. User submits flag:
   - **Option A**: Via chatbot: "verify flag CTF{...}" or "check flag CTF{...}" (⚠️ **TO BE IMPLEMENTED**)
   - **Option B**: Via API: `POST /api/challenges/:challengeId/submit` (✅ **CURRENTLY AVAILABLE**)
6. System verifies flag:
   - Checks flag against stored flag in database
   - Returns success/failure message
7. If correct:
   - Challenge is marked as solved
   - User stats are updated
   - User can save the challenge (if not already saved)

**Important:**
- Flag verification via chatbot is planned but not yet implemented
- Currently, flag verification is available via direct API call
- If challenge was saved before deployment, saving after verification won't create a duplicate (same challenge_id)

---

### 5. Challenge Listing Flow

```
List Request → Filter by User ID → Return User's Challenges Only
```

**Steps:**
1. User requests to list challenges: "list my challenges" or "show my challenges"
2. System queries database filtering by `user_id`
3. Returns only challenges where `challenge.user_id = current_user.user_id`
4. User sees their private challenges

**Important:**
- Challenges are **private** - each user only sees their own challenges
- Filtering is done by `user_id` in the database query

---

## Database Schema

### Challenges Table
```sql
CREATE TABLE challenges (
  challenge_id SERIAL PRIMARY KEY,
  challenge_name VARCHAR(255) NOT NULL,
  slug VARCHAR(255) UNIQUE NOT NULL,
  user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,  -- User association
  category VARCHAR(50) NOT NULL,
  difficulty VARCHAR(20),
  description TEXT,
  hints TEXT[],
  flag VARCHAR(255) NOT NULL,
  -- ... other fields
  is_active BOOLEAN DEFAULT TRUE,
  is_deployed BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Key Points:**
- `user_id` field associates challenge with creator
- Challenges are private to the user who created them
- `is_deployed` tracks deployment status

---

## API Endpoints

### Challenge Creation
- **Endpoint**: `POST /api/chat`
- **Flow**: User message → AI processing → Challenge created in Git → Confirmation

### Save Challenge
- **Endpoint**: `POST /api/challenges` (requires authentication)
- **Body**: Challenge details
- **Result**: Challenge saved to database with `user_id` from JWT token

### Deploy Challenge
- **Endpoint**: `POST /api/chat` (with deploy request)
- **Flow**: Validation → Docker build → Guacamole setup → Credentials returned

### List Challenges
- **Endpoint**: `GET /api/challenges` (requires authentication)
- **Filter**: Only returns challenges where `user_id = authenticated_user.user_id`

### Submit Flag
- **Endpoint**: `POST /api/challenges/:challengeId/submit` (requires authentication)
- **Flow**: Flag verification → Success/failure response

### Flag Verification via Chat
- **Endpoint**: `POST /api/chat` (with flag submission)
- **Flow**: Chatbot processes flag → Verifies against database → Returns result
- **Status**: ⚠️ **TO BE IMPLEMENTED** - Currently flag verification is only available via direct API call
- **Note**: Users can currently verify flags via `/api/challenges/:challengeId/submit` endpoint, but chatbot flag verification needs to be added

---

## Key Implementation Details

### 1. User Association
- Challenges are **always** associated with `user_id` when saved
- `user_id` comes from JWT token in authenticated requests
- Session-based operations use `sessionId` but link to `user_id` when saving

### 2. Challenge Privacy
- All challenges are **private** by default
- Users can only see their own challenges
- No public challenge sharing

### 3. Save vs Deploy
- **Save**: Stores challenge in database (private, associated with user_id)
- **Deploy**: Builds and runs challenge containers, creates Guacamole access
- User can save before or after deployment
- Saving after deployment won't create duplicate if already saved

### 4. Flag Verification
- Flags can be verified through:
  1. **Chatbot**: User submits flag in chat, chatbot verifies
  2. **API**: Direct API call to `/api/challenges/:challengeId/submit`
- Both methods check flag against database

### 5. Guacamole Access
- Each deployment creates a **session-based Guacamole user**
- User gets unique credentials per session
- Access is via **Kali Linux connection** in Guacamole
- Credentials are temporary and session-specific

---

## State Diagram

```
[Challenge Created]
    ↓
    ├─→ [Save to Database] → [Private Challenge Stored]
    │
    └─→ [Deploy] → [Docker Containers Running]
                    ↓
                    [Guacamole Access Created]
                    ↓
                    [User Accesses via Kali Linux]
                    ↓
                    [User Asks for Hints/Questions]
                    ↓
                    [User Finds Flag]
                    ↓
                    [User Submits Flag]
                    ↓
                    [Flag Verified]
                    ↓
                    [Challenge Solved]
                    ↓
                    [User Can Save (if not already saved)]
```

---

## Important Notes

1. **Challenge Ownership**: Every challenge is tied to a `user_id` - no anonymous challenges
2. **Privacy**: Challenges are private - users only see their own
3. **Save Timing**: User can save before or after deployment - same challenge, no duplicates
4. **Guacamole**: Session-based access - each session gets unique credentials
5. **Flag Verification**: Can be done through chatbot or direct API call
6. **Hints/Questions**: Chatbot provides hints and answers questions about challenges

---

**Last Updated**: 2025-01-27  
**Version**: 1.0

