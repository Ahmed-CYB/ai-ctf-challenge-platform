# Session ID Logic - Complete Explanation

## Overview

Session IDs are used throughout the platform to:
1. **Track conversations** - Link messages to specific chat sessions
2. **Isolate Guacamole users** - Create unique Guacamole accounts per session
3. **Manage resources** - Clean up connections and users when sessions end
4. **Maintain context** - Retrieve conversation history for AI responses

---

## 🔄 Session ID Flow

### 1. **Frontend Generation** (Client-Side)

**Location**: `packages/frontend/src/components/CTFChatInterface.tsx`

```typescript
const [sessionId] = useState<string>(() => 
  `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
);
```

**Format**: `session-{timestamp}-{randomString}`
- **Example**: `session-1767364378363-irodao1nt`
- **Generated once** when the chat component mounts
- **Persists** for the entire browser session (until page refresh)

**Why this format?**
- `session-` prefix: Identifies it as a chat session
- `Date.now()`: Timestamp ensures uniqueness
- Random string: Additional uniqueness for concurrent users

---

### 2. **Backend Session Creation** (Database)

**Location**: `packages/backend/server.js`

**Endpoint**: `POST /api/sessions`

```javascript
app.post('/api/sessions', async (req, res) => {
  const { sessionId, userId } = req.body;
  
  // Create session in database with 24-hour expiration
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 24);
  
  await pool.query(
    `INSERT INTO sessions (session_id, user_id, created_at, last_activity, expires_at, ip_address, user_agent)
     VALUES ($1, $2, NOW(), NOW(), $3, $4, $5)`,
    [sessionId, userId, expiresAt, req.ip, req.headers['user-agent']]
  );
});
```

**What it stores:**
- `session_id`: The unique session identifier
- `user_id`: Optional - links to authenticated user (null for anonymous)
- `created_at`: When session was created
- `last_activity`: Last time session was used (updated on each request)
- `expires_at`: 24 hours from creation
- `ip_address`: Client IP address
- `user_agent`: Browser information

---

### 3. **CTF Automation Service** (Message Handling)

**Location**: `packages/ctf-automation/src/index.js`

**Endpoint**: `POST /api/chat`

```javascript
app.post('/api/chat', async (req, res) => {
  const { message, sessionId } = req.body;
  
  // Fallback: Generate session ID if not provided
  const session = sessionId || `session-${Date.now()}`;
  
  // Get conversation history for this session
  const conversationHistory = await dbManager.getConversationHistory(session);
  
  // Save user message
  await dbManager.saveMessage(session, 'user', message);
  
  // Process message and save assistant response
  await dbManager.saveMessage(session, 'assistant', responseText, metadata);
});
```

**Key Points:**
- ✅ **Accepts sessionId from frontend** (preferred)
- ✅ **Falls back to auto-generated** if not provided: `session-{timestamp}`
- ✅ **Uses session ID for**:
  - Retrieving conversation history
  - Saving messages to database
  - Creating Guacamole users
  - Tracking challenge deployments

---

### 4. **Guacamole User Creation** (Session-Based)

**Location**: `packages/ctf-automation/src/session-guacamole-manager.js`

```javascript
async getOrCreateSessionUser(sessionId) {
  // Check if user already exists for this session
  if (this.sessionUsers.has(sessionId)) {
    return this.sessionUsers.get(sessionId);
  }
  
  // Create new Guacamole user with random username
  const username = `ctf_${randomString(10)}`; // e.g., "ctf_qweyolnczg"
  const password = generatePassword(16);
  
  // Store in memory: sessionId -> { username, password, entityId }
  this.sessionUsers.set(sessionId, { username, password, ... });
  
  return { username, password };
}
```

**How Session ID is Used:**
1. **In-Memory Mapping**: `sessionId` → Guacamole user credentials
2. **Connection Naming**: Connection names include session ID suffix
   - Format: `{challengeName}-{sessionId.substring(0, 8)}-ssh`
   - Example: `corporate-data-breach-investigation-17673643-ssh`
3. **User Isolation**: Each session gets its own Guacamole account
4. **Cleanup**: When session ends, user and connections are deleted

---

### 5. **Database Message Storage**

**Location**: `packages/ctf-automation/src/db-manager.js`

```javascript
async saveMessage(sessionId, role, messageText, metadata = null) {
  await this.pool.query(
    `INSERT INTO chat_messages (session_id, role, message_text, metadata)
     VALUES ($1, $2, $3, $4)`,
    [sessionId, role, messageText, JSON.stringify(metadata)]
  );
}

async getConversationHistory(sessionId, limit = 20) {
  const result = await this.pool.query(
    `SELECT role, message_text, timestamp, metadata
     FROM chat_messages
     WHERE session_id = $1
     ORDER BY timestamp ASC
     LIMIT $2`,
    [sessionId, limit]
  );
  return result.rows;
}
```

**What's Stored:**
- `session_id`: Links message to session
- `role`: 'user' or 'assistant'
- `message_text`: The actual message content
- `metadata`: JSON object with additional info (deployment details, challenge info, etc.)

---

## 🎯 Session ID Usage Throughout System

### **1. Conversation History**
```javascript
// Retrieve all messages for a session
const history = await dbManager.getConversationHistory(sessionId);
// Used by AI to maintain context across messages
```

### **2. Guacamole User Management**
```javascript
// Create unique Guacamole user per session
const userAccount = await sessionGuacManager.getOrCreateSessionUser(sessionId);
// Returns: { username: "ctf_qweyolnczg", password: "971314db8d6b38f6" }
```

### **3. Connection Naming**
```javascript
// Connection name includes session ID for uniqueness
const connectionName = `${challengeName}-${sessionId.substring(0, 8)}-ssh`;
// Example: "corporate-data-breach-investigation-17673643-ssh"
```

### **4. Deployment Tracking**
```javascript
// Session ID passed to deployment agent
await deployChallenge(userMessage, conversationHistory, sessionId);
// Used to create Guacamole connections with session-specific names
```

### **5. Cleanup Operations**
```javascript
// Delete session and associated resources
app.delete('/api/sessions/:sessionId', async (req, res) => {
  await sessionGuacManager.deleteSessionUser(sessionId);
  // Removes Guacamole user, connections, and database entries
});
```

---

## 🔐 Security & Isolation

### **Session Isolation**
- ✅ Each session gets **unique Guacamole account**
- ✅ Connections are **session-specific** (can't access other sessions)
- ✅ Conversation history is **isolated per session**
- ✅ No cross-session data leakage

### **Session Expiration**
- ✅ **24-hour expiration** for chat sessions
- ✅ **Automatic cleanup** of expired sessions (runs every hour)
- ✅ **Guacamole users deleted** when session expires

### **Session Storage**
- ✅ **In-memory Map**: Fast lookup for active sessions
- ✅ **Database**: Persistent storage for conversation history
- ✅ **Guacamole DB**: User accounts and connections

---

## 📊 Session Lifecycle

```
1. Frontend generates session ID
   └─> session-1767364378363-irodao1nt

2. Frontend sends to backend
   └─> POST /api/sessions { sessionId, userId }

3. Backend creates session record
   └─> INSERT INTO sessions (session_id, expires_at, ...)

4. User sends chat message
   └─> POST /api/chat { message, sessionId }

5. CTF automation retrieves history
   └─> SELECT * FROM chat_messages WHERE session_id = ?

6. Challenge deployment
   └─> Creates Guacamole user: ctf_qweyolnczg
   └─> Creates connection: challengeName-17673643-ssh
   └─> Stores in memory: sessionId -> { username, password }

7. Session cleanup (on expiration or manual delete)
   └─> DELETE Guacamole user
   └─> DELETE Guacamole connections
   └─> DELETE from memory cache
```

---

## 🔍 Key Components

### **1. Frontend (React)**
- **Generates**: Session ID on component mount
- **Sends**: Session ID with every chat message
- **Stores**: Session ID in component state (not localStorage)

### **2. Backend API**
- **Stores**: Session records in PostgreSQL
- **Tracks**: Last activity, expiration, user association
- **Manages**: Session lifecycle (create, update, delete)

### **3. CTF Automation Service**
- **Uses**: Session ID for conversation history
- **Creates**: Guacamole users per session
- **Tracks**: Challenge deployments per session

### **4. Session Guacamole Manager**
- **Maps**: Session ID → Guacamole credentials
- **Manages**: User creation and deletion
- **Isolates**: Each session has separate Guacamole account

---

## 💡 Important Notes

### **Session ID Format**
- **Frontend-generated**: `session-{timestamp}-{random}`
- **Backend fallback**: `session-{timestamp}` (if not provided)
- **Length**: Typically 25-35 characters

### **Session Persistence**
- **Frontend**: Lost on page refresh (new session ID generated)
- **Backend**: Stored in database, persists across server restarts
- **Guacamole**: Users persist until session expires or is deleted

### **Session Cleanup**
- **Automatic**: Runs every hour, deletes expired sessions (>24 hours)
- **Manual**: `DELETE /api/sessions/:sessionId` endpoint
- **On cleanup**: Removes Guacamole user, connections, and database entries

### **Multiple Sessions**
- ✅ **Same user** can have **multiple sessions** (different browser tabs)
- ✅ Each session gets **separate Guacamole account**
- ✅ **No conflicts** between sessions

---

## 🎯 Summary

**Session ID is the primary identifier that:**
1. ✅ Links all messages in a conversation
2. ✅ Creates isolated Guacamole accounts per chat session
3. ✅ Enables conversation history retrieval
4. ✅ Tracks challenge deployments per session
5. ✅ Allows cleanup of resources when session ends

**Key Flow:**
```
Frontend → Generates session ID
    ↓
Backend → Stores session in database
    ↓
CTF Service → Uses session ID for history & Guacamole
    ↓
Guacamole → Creates user account linked to session
    ↓
Cleanup → Deletes everything when session expires
```


