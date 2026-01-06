# Login System & Database Configuration

## 🔐 How Login Works

### **Login Flow**

1. **Frontend Request** (`packages/frontend/src/services/auth.ts`)
   - User enters email and password
   - Frontend sends POST request to `/api/auth/login`
   - Request includes: `{ email, password }`

2. **Backend Processing** (`packages/backend/server.js` - Line 347)
   - Receives login request at `POST /api/auth/login`
   - Validates email and password are provided
   - Queries PostgreSQL database for user by email

3. **Database Query**
   ```sql
   SELECT user_id, username, email, password_hash, name, avatar_animal_id, role, 
          is_active, account_locked_until, failed_login_attempts
   FROM users 
   WHERE email = $1
   ```

4. **Security Checks**
   - ✅ User exists
   - ✅ Account is not locked (`account_locked_until`)
   - ✅ Account is active (`is_active = true`)
   - ✅ Password matches (using `bcrypt.compare()`)

5. **Failed Login Protection**
   - After 5 failed attempts, account is locked for 15 minutes
   - Failed attempts counter is incremented
   - Lock expires automatically

6. **Successful Login**
   - Reset failed login attempts to 0
   - Update `last_login` timestamp
   - Create JWT token (expires in 7 days)
   - Create secure session (prevents session fixation)
   - Set secure session cookie
   - Log activity to `user_activity_log` table

7. **Response**
   ```json
   {
     "success": true,
     "token": "jwt_token_here",
     "sessionId": "session_id_here",
     "user": {
       "user_id": 1,
       "username": "user123",
       "email": "user@example.com",
       "name": "User Name",
       "avatar": "cat",
       "role": "user"
     }
   }
   ```

---

## 📊 Database Configuration

### **Database Type**
- **PostgreSQL** (Relational Database)

### **Connection Details**

**Location**: `packages/backend/server.js` (Lines 79-91)

**Default Configuration**:
```javascript
const DATABASE_URL = process.env.DATABASE_URL || 
  `postgresql://ctf_user:ctf_password_123@localhost:5433/ctf_platform`;
```

**Connection Parameters**:
- **Host**: `localhost`
- **Port**: `5433` (default, can be changed via `DATABASE_URL`)
- **Database**: `ctf_platform`
- **User**: `ctf_user`
- **Password**: `ctf_password_123` (default, should be changed in production)

**Environment Variable**:
- Set `DATABASE_URL` in `.env` file to override defaults
- Format: `postgresql://username:password@host:port/database`

### **Database Schema**

**Schema File**: `database/schema.sql`

**Main Tables**:

1. **`users`** - User accounts and authentication
   - `user_id` (Primary Key)
   - `username` (Unique)
   - `email` (Unique)
   - `password_hash` (bcrypt hashed)
   - `role` (user/admin/moderator)
   - `is_active` (account status)
   - `account_locked_until` (temporary lock)
   - `failed_login_attempts` (security counter)
   - `last_login` (timestamp)
   - And more profile fields...

2. **`sessions`** - Active user sessions
   - `session_id` (Primary Key)
   - `user_id` (Foreign Key → users)
   - `ip_address`
   - `user_agent`
   - `expires_at`
   - `created_at`

3. **`user_activity_log`** - Login and activity tracking
   - `log_id` (Primary Key)
   - `user_id` (Foreign Key → users)
   - `activity_type` (login, logout, etc.)
   - `ip_address`
   - `created_at`

4. **`challenges`** - CTF challenges
5. **`challenge_submissions`** - Flag submissions
6. **`chat_messages`** - Chat history
7. And more...

---

## 🔒 Security Features

### **Password Security**
- Passwords are hashed using **bcrypt** (one-way hashing)
- Never stored in plain text
- Uses `bcrypt.compare()` to verify passwords

### **Account Lockout**
- After **5 failed login attempts**, account is locked
- Lock duration: **15 minutes**
- Automatically unlocks after timeout

### **Session Management**
- **JWT tokens** for stateless authentication (7-day expiry)
- **Secure session cookies** (HTTP-only, secure flags)
- **Session regeneration** (prevents session fixation attacks)
- Sessions stored in `sessions` table

### **Security Headers** (Helmet.js)
- HSTS (HTTP Strict Transport Security)
- XSS Protection
- Frame Guard (prevents clickjacking)
- Content Security Policy
- And more...

---

## 📁 File Locations

### **Backend Login Code**
- **File**: `packages/backend/server.js`
- **Login Endpoint**: Line 347 (`POST /api/auth/login`)
- **Database Connection**: Lines 79-91

### **Frontend Login Code**
- **File**: `packages/frontend/src/services/auth.ts`
- **Login Function**: `login(email, password)`

### **Database Schema**
- **File**: `database/schema.sql`
- **Users Table**: Lines 24-89

### **Session Management**
- **File**: `packages/backend/secure-session-manager.js`
- Handles session creation, validation, and cleanup

---

## 🚀 How to Access Database

### **Using psql (PostgreSQL CLI)**
```bash
psql -h localhost -p 5433 -U ctf_user -d ctf_platform
```

### **Using Docker (if running in container)**
```bash
docker exec -it <postgres_container_name> psql -U ctf_user -d ctf_platform
```

### **Connection String Format**
```
postgresql://username:password@host:port/database
```

### **Example Queries**

**View all users**:
```sql
SELECT user_id, username, email, role, is_active, last_login 
FROM users;
```

**View active sessions**:
```sql
SELECT s.session_id, u.username, s.ip_address, s.created_at, s.expires_at
FROM sessions s
JOIN users u ON s.user_id = u.user_id
WHERE s.expires_at > NOW();
```

**View login activity**:
```sql
SELECT u.username, a.activity_type, a.ip_address, a.created_at
FROM user_activity_log a
JOIN users u ON a.user_id = u.user_id
WHERE a.activity_type = 'login'
ORDER BY a.created_at DESC
LIMIT 10;
```

---

## ⚙️ Configuration

### **Environment Variables**

Create/update `.env` file in `packages/ctf-automation/`:

```env
# Database Configuration
DATABASE_URL=postgresql://ctf_user:your_password@localhost:5433/ctf_platform
DB_PASSWORD=your_password

# JWT Secret (minimum 32 characters)
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters-long

# Backend Port
BACKEND_PORT=4002

# Frontend URL
FRONTEND_URL=http://localhost:4000
```

### **Database Setup**

1. **Install PostgreSQL** (if not installed)
2. **Create database**:
   ```sql
   CREATE DATABASE ctf_platform;
   CREATE USER ctf_user WITH PASSWORD 'ctf_password_123';
   GRANT ALL PRIVILEGES ON DATABASE ctf_platform TO ctf_user;
   ```

3. **Run schema**:
   ```bash
   psql -h localhost -p 5433 -U ctf_user -d ctf_platform -f database/schema.sql
   ```

---

## 📝 Summary

- **Database**: PostgreSQL on `localhost:5433`
- **Database Name**: `ctf_platform`
- **Login Endpoint**: `POST /api/auth/login`
- **Authentication**: JWT tokens + secure sessions
- **Password Security**: bcrypt hashing
- **Account Protection**: 5 failed attempts = 15 min lockout
- **Session Storage**: PostgreSQL `sessions` table
- **User Storage**: PostgreSQL `users` table

