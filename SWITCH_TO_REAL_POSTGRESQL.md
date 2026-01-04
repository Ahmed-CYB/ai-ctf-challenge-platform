# Switching to Real PostgreSQL (Non-Docker)

This guide will help you switch from Docker-based PostgreSQL to a real PostgreSQL installation on your system.

---

## 📋 **Prerequisites**

1. **Install PostgreSQL** on your system:
   - **Windows**: Download from [PostgreSQL Official Site](https://www.postgresql.org/download/windows/)
   - **macOS**: `brew install postgresql@15` or download from official site
   - **Linux**: `sudo apt-get install postgresql-15` (Ubuntu/Debian) or `sudo yum install postgresql15` (RHEL/CentOS)

2. **Verify Installation**:
   ```bash
   psql --version
   # Should show: psql (PostgreSQL) 15.x
   ```

---

## 🔧 **Step 1: Create Database and User**

### **Windows (using pgAdmin or Command Prompt)**

1. **Open Command Prompt as Administrator**
2. **Navigate to PostgreSQL bin directory** (usually `C:\Program Files\PostgreSQL\15\bin`)
3. **Run PostgreSQL commands**:

```bash
# Connect to PostgreSQL as superuser
psql -U postgres

# Create database
CREATE DATABASE ctf_platform;

# Create user
CREATE USER ctf_user WITH PASSWORD 'your_secure_password_here';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ctf_platform TO ctf_user;

# Connect to the new database
\c ctf_platform

# Grant schema privileges
GRANT ALL ON SCHEMA public TO ctf_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ctf_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ctf_user;

# Exit
\q
```

### **macOS/Linux**

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database
CREATE DATABASE ctf_platform;

# Create user
CREATE USER ctf_user WITH PASSWORD 'your_secure_password_here';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ctf_platform TO ctf_user;

# Connect to the new database
\c ctf_platform

# Grant schema privileges
GRANT ALL ON SCHEMA public TO ctf_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ctf_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ctf_user;

# Exit
\q
```

---

## ⚙️ **Step 2: Update Environment Variables**

### **Option A: Update `.env` file** (Recommended)

Create or update `.env` file in the project root:

```env
# PostgreSQL Database Configuration (Real Installation)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=ctf_platform
DB_USER=ctf_user
DB_PASSWORD=your_secure_password_here

# Alternative: Use DATABASE_URL (for backend)
DATABASE_URL=postgresql://ctf_user:your_secure_password_here@localhost:5432/ctf_platform

# Keep other services in Docker (optional)
GUACAMOLE_DB_PASSWORD=guacamole_password_123
GUACAMOLE_ROOT_PASSWORD=root_password_123
```

### **Option B: Set Environment Variables Directly**

**Windows (PowerShell)**:
```powershell
$env:DB_HOST="localhost"
$env:DB_PORT="5432"
$env:DB_NAME="ctf_platform"
$env:DB_USER="ctf_user"
$env:DB_PASSWORD="your_secure_password_here"
$env:DATABASE_URL="postgresql://ctf_user:your_secure_password_here@localhost:5432/ctf_platform"
```

**macOS/Linux**:
```bash
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=ctf_platform
export DB_USER=ctf_user
export DB_PASSWORD=your_secure_password_here
export DATABASE_URL=postgresql://ctf_user:your_secure_password_here@localhost:5432/ctf_platform
```

---

## 🗄️ **Step 3: Initialize Database Schema**

### **Run Migrations**

```bash
# Make sure PostgreSQL is running
# Windows: Check Services, or run: net start postgresql-x64-15
# macOS: brew services start postgresql@15
# Linux: sudo systemctl start postgresql

# Run migrations
npm run db:migrate
```

This will:
- Create all tables
- Set up indexes
- Create triggers
- Seed initial data

---

## ✅ **Step 4: Verify Connection**

### **Test Connection from Node.js**

Create a test file `test-db-connection.js`:

```javascript
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'ctf_platform',
  user: process.env.DB_USER || 'ctf_user',
  password: process.env.DB_PASSWORD || 'your_secure_password_here',
});

pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Connection failed:', err);
  } else {
    console.log('✅ Connected to PostgreSQL!');
    console.log('Current time:', res.rows[0].now);
  }
  pool.end();
});
```

Run it:
```bash
node test-db-connection.js
```

---

## 🔄 **Step 5: Update Application Code (If Needed)**

The code already supports environment variables, but let's verify the configuration:

### **Backend (`packages/backend/server.js`)**
Already uses `DATABASE_URL` ✅

### **CTF Automation (`packages/ctf-automation/src/db-manager.js`)**
Already uses `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD` ✅

**No code changes needed!** Just update environment variables.

---

## 🐳 **Step 6: Optional - Keep Docker for Other Services**

You can keep Guacamole in Docker while using real PostgreSQL:

### **Option 1: Stop Only PostgreSQL Container**

```bash
# Stop PostgreSQL container
docker stop ctf-postgres-new

# Keep other services running
docker-compose -f docker/docker-compose.infrastructure.yml up -d guacamole-new guacd-new guacamole-db-new
```

### **Option 2: Update Docker Compose**

Edit `docker/docker-compose.infrastructure.yml` and comment out PostgreSQL:

```yaml
services:
  # PostgreSQL Database - DISABLED (using real PostgreSQL)
  # postgres-new:
  #   image: postgres:15-alpine
  #   ...

  # Keep other services
  guacamole-new:
    # ...
```

---

## 🔍 **Step 7: Verify Everything Works**

1. **Start your application**:
   ```bash
   # Backend
   cd packages/backend
   npm start

   # CTF Automation
   cd packages/ctf-automation
   npm start
   ```

2. **Check logs** for database connection:
   ```
   📊 Database connection configured: localhost:5432/ctf_platform
   ✅ Connected to PostgreSQL database
   ```

3. **Test API endpoints**:
   ```bash
   curl http://localhost:4002/api/health
   ```

---

## 🛠️ **Troubleshooting**

### **Connection Refused**

**Problem**: `ECONNREFUSED` or `Connection refused`

**Solutions**:
1. **Check PostgreSQL is running**:
   - Windows: Services → PostgreSQL
   - macOS: `brew services list`
   - Linux: `sudo systemctl status postgresql`

2. **Check port**:
   ```bash
   # Windows
   netstat -an | findstr 5432
   
   # macOS/Linux
   lsof -i :5432
   ```

3. **Check PostgreSQL config** (`postgresql.conf`):
   ```
   listen_addresses = 'localhost'  # or '*' for all interfaces
   port = 5432
   ```

4. **Check `pg_hba.conf`** (authentication):
   ```
   # Allow local connections
   host    all             all             127.0.0.1/32            md5
   host    all             all             ::1/128                 md5
   ```

### **Authentication Failed**

**Problem**: `password authentication failed`

**Solutions**:
1. **Reset password**:
   ```sql
   ALTER USER ctf_user WITH PASSWORD 'new_password';
   ```

2. **Check `.env` file** has correct password

3. **Verify user exists**:
   ```sql
   SELECT usename FROM pg_user WHERE usename = 'ctf_user';
   ```

### **Database Does Not Exist**

**Problem**: `database "ctf_platform" does not exist`

**Solution**:
```sql
CREATE DATABASE ctf_platform;
GRANT ALL PRIVILEGES ON DATABASE ctf_platform TO ctf_user;
```

### **Permission Denied**

**Problem**: `permission denied for table` or `permission denied for schema`

**Solution**:
```sql
\c ctf_platform
GRANT ALL ON SCHEMA public TO ctf_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ctf_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ctf_user;
```

---

## 📊 **Comparison: Docker vs Real PostgreSQL**

| Feature | Docker PostgreSQL | Real PostgreSQL |
|---------|------------------|-----------------|
| **Installation** | `docker-compose up` | Manual install |
| **Port** | 5433 (mapped) | 5432 (default) |
| **Data Persistence** | Docker volume | System directory |
| **Performance** | Slightly slower | Native speed |
| **Backup** | Docker volume backup | `pg_dump` |
| **Management** | Docker commands | PostgreSQL tools |
| **Production Ready** | Good for dev | Production standard |

---

## 🎯 **Benefits of Real PostgreSQL**

✅ **Better Performance** - Native speed, no Docker overhead  
✅ **Easier Management** - Use standard PostgreSQL tools  
✅ **Better Backup** - Direct `pg_dump` access  
✅ **Production Ready** - Standard setup  
✅ **Easier Debugging** - Direct database access  
✅ **No Port Conflicts** - Uses standard port 5432  

---

## 📝 **Quick Reference**

### **Common PostgreSQL Commands**

```bash
# Connect to database
psql -U ctf_user -d ctf_platform

# List databases
\l

# List tables
\dt

# Describe table
\d table_name

# Run SQL file
psql -U ctf_user -d ctf_platform -f schema.sql

# Backup database
pg_dump -U ctf_user -d ctf_platform > backup.sql

# Restore database
psql -U ctf_user -d ctf_platform < backup.sql
```

---

## ✅ **Summary**

1. ✅ Install PostgreSQL
2. ✅ Create database and user
3. ✅ Update `.env` file with connection details
4. ✅ Run migrations: `npm run db:migrate`
5. ✅ Test connection
6. ✅ Start application

**Your application will now use real PostgreSQL instead of Docker!**


