# MySQL to PostgreSQL Migration Guide

## Overview

This guide explains how to migrate the Guacamole MySQL database (`guacamole_db`) to PostgreSQL while keeping it **completely separate** from your main CTF platform database (`ctf_platform`).

## Important Notes

⚠️ **The databases will remain separate:**
- **CTF Platform Database**: `ctf_platform` (PostgreSQL) - Port 5433
- **Guacamole Database**: `guacamole_db` (PostgreSQL) - Port 5432 (or your PostgreSQL port)

These are **two different databases** on the same PostgreSQL server, not mixed together.

---

## Prerequisites

1. **PostgreSQL Server** installed and running
2. **pgAdmin** installed (for GUI management)
3. **Python 3.7+** with required packages:
   ```bash
   pip install mysql-connector-python psycopg2-binary
   ```
4. **Access to both databases:**
   - MySQL: `guacamole_db` (currently on port 3307)
   - PostgreSQL: Server access to create new database

---

## Step 1: Create PostgreSQL Database for Guacamole

### Option A: Using pgAdmin (GUI)

1. **Open pgAdmin** and connect to your PostgreSQL server

2. **Create New Database:**
   - Right-click on "Databases" → "Create" → "Database..."
   - **Name**: `guacamole_db`
   - **Owner**: `postgres` (or your PostgreSQL user)
   - Click "Save"

3. **Create Database User (Optional but Recommended):**
   - Right-click on "Login/Group Roles" → "Create" → "Login/Group Role..."
   - **Name**: `guacamole_user`
   - **Password**: `guacamole_password_123` (or your preferred password)
   - Go to "Privileges" tab:
     - ✅ Can login? → Yes
     - ✅ Create databases? → No
     - ✅ Create roles? → No
   - Click "Save"

4. **Grant Permissions:**
   - Right-click on `guacamole_db` → "Properties" → "Security"
   - Click "Add" → Select `guacamole_user`
   - Grant: **ALL** privileges
   - Click "Save"

### Option B: Using Command Line (psql)

```bash
# Connect to PostgreSQL
psql -U postgres -h localhost

# Create database
CREATE DATABASE guacamole_db;

# Create user (optional)
CREATE USER guacamole_user WITH PASSWORD 'guacamole_password_123';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE guacamole_db TO guacamole_user;

# Connect to the new database
\c guacamole_db

# Grant schema privileges
GRANT ALL ON SCHEMA public TO guacamole_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO guacamole_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO guacamole_user;

# Exit
\q
```

---

## Step 2: Create PostgreSQL Schema

### Option A: Using pgAdmin

1. **Open Query Tool:**
   - Right-click on `guacamole_db` → "Query Tool"

2. **Load Schema File:**
   - File → Open → Select `database/guacamole-postgresql-schema.sql`
   - Or copy-paste the contents

3. **Execute:**
   - Click "Execute" (F5) or press F5
   - Wait for completion
   - You should see "Success" message

### Option B: Using Command Line

```bash
# From project root directory
psql -U postgres -h localhost -d guacamole_db -f database/guacamole-postgresql-schema.sql
```

**Expected Output:**
```
CREATE TABLE
CREATE TABLE
...
✓ Schema created successfully
```

---

## Step 3: Migrate Data from MySQL to PostgreSQL

### Using the Python Migration Script

The migration script (`migrate_mysql_to_postgresql.py`) will:
1. Connect to both MySQL and PostgreSQL
2. Copy all data from MySQL tables to PostgreSQL
3. Handle binary data conversion (passwords, etc.)
4. Reset sequences to match migrated data
5. Verify row counts match

### Run Migration

```bash
# Basic usage (will prompt for PostgreSQL password)
python migrate_mysql_to_postgresql.py --pg-password YOUR_POSTGRES_PASSWORD

# Full options
python migrate_mysql_to_postgresql.py \
    --mysql-host localhost \
    --mysql-port 3307 \
    --mysql-user guacamole_user \
    --mysql-password guacamole_password_123 \
    --mysql-database guacamole_db \
    --pg-host localhost \
    --pg-port 5432 \
    --pg-user postgres \
    --pg-password YOUR_POSTGRES_PASSWORD \
    --pg-database guacamole_db \
    --batch-size 1000
```

**What to Expect:**
```
============================================================
MySQL to PostgreSQL Migration Tool
Guacamole Database Migration
============================================================

Source: MySQL localhost:3307/guacamole_db
Target: PostgreSQL localhost:5432/guacamole_db

⚠️  WARNING: This will migrate data to PostgreSQL.
   Make sure the PostgreSQL schema is already created!
   Use: database/guacamole-postgresql-schema.sql

Continue? (yes/no): yes

✓ Connected to MySQL: localhost:3307/guacamole_db
✓ Connected to PostgreSQL: localhost:5432/guacamole_db

============================================================
Starting Migration
============================================================

📦 Migrating table: guacamole_entity
   Found 47 rows
   ✓ Migrated 47/47 rows

📦 Migrating table: guacamole_connection_group
   Found 2 rows
   ✓ Migrated 2/2 rows

... (continues for all tables)

🔄 Resetting sequences...
   ✓ Reset 23 sequences

🔍 Verifying migration...
   ✓ guacamole_entity: 47 rows
   ✓ guacamole_connection_group: 2 rows
   ...

✅ Migration completed successfully!
```

---

## Step 4: Verify Migration in pgAdmin

1. **Open pgAdmin** → Connect to PostgreSQL server

2. **Check Tables:**
   - Expand `guacamole_db` → `Schemas` → `public` → `Tables`
   - You should see all 23 Guacamole tables

3. **Verify Data:**
   - Right-click on a table (e.g., `guacamole_user`) → "View/Edit Data" → "All Rows"
   - Verify data looks correct

4. **Check Row Counts:**
   ```sql
   SELECT 
       schemaname,
       tablename,
       n_live_tup as row_count
   FROM pg_stat_user_tables
   WHERE schemaname = 'public'
   ORDER BY tablename;
   ```

---

## Step 5: Update Guacamole Configuration

### Update Docker Compose (if using Docker)

Edit `docker/docker-compose.infrastructure.yml`:

```yaml
services:
  guacamole-new:
    image: guacamole/guacamole:latest
    container_name: ctf-guacamole-new
    ports:
      - "8081:8080"
    environment:
      GUACD_HOSTNAME: guacd-new
      GUACD_PORT: 4822
      # Change from MySQL to PostgreSQL
      POSTGRESQL_HOSTNAME: postgres-host  # Your PostgreSQL host
      POSTGRESQL_PORT: 5432
      POSTGRESQL_DATABASE: guacamole_db
      POSTGRESQL_USERNAME: guacamole_user
      POSTGRESQL_PASSWORD: guacamole_password_123
    depends_on:
      - guacd-new
    # Remove: guacamole-db-new dependency
    networks:
      - ctf-network
    restart: unless-stopped

  # Remove or comment out the MySQL database service
  # guacamole-db-new:
  #   ...
```

### Update Application Code

If your application code connects to Guacamole database, update connection strings:

**Before (MySQL):**
```javascript
const mysql = require('mysql2');
const connection = mysql.createConnection({
  host: 'localhost',
  port: 3307,
  user: 'guacamole_user',
  password: 'guacamole_password_123',
  database: 'guacamole_db'
});
```

**After (PostgreSQL):**
```javascript
const { Pool } = require('pg');
const pool = new Pool({
  host: 'localhost',
  port: 5432,
  user: 'guacamole_user',
  password: 'guacamole_password_123',
  database: 'guacamole_db'
});
```

---

## Step 6: Test Guacamole Service

1. **Restart Guacamole:**
   ```bash
   docker-compose -f docker/docker-compose.infrastructure.yml restart guacamole-new
   ```

2. **Check Logs:**
   ```bash
   docker logs ctf-guacamole-new
   ```

3. **Access Guacamole:**
   - Open browser: `http://localhost:8081`
   - Login with: `guacadmin` / `guacadmin`
   - Verify connections work

---

## Troubleshooting

### Issue: Migration Script Fails

**Error: "relation does not exist"**
- **Solution**: Make sure you ran the PostgreSQL schema script first
- Check: `database/guacamole-postgresql-schema.sql`

**Error: "permission denied"**
- **Solution**: Grant proper permissions to PostgreSQL user
  ```sql
  GRANT ALL PRIVILEGES ON DATABASE guacamole_db TO guacamole_user;
  GRANT ALL ON SCHEMA public TO guacamole_user;
  ```

**Error: "binary data conversion failed"**
- **Solution**: The script handles binary data automatically
- If issues persist, check that MySQL binary columns are being read correctly

### Issue: Guacamole Can't Connect to PostgreSQL

**Error: "Connection refused"**
- **Solution**: 
  1. Verify PostgreSQL is running: `pg_isready`
  2. Check PostgreSQL is listening: `netstat -an | grep 5432`
  3. Verify firewall rules allow connections

**Error: "authentication failed"**
- **Solution**: 
  1. Check `pg_hba.conf` allows connections
  2. Verify username/password in Guacamole config
  3. Test connection manually: `psql -U guacamole_user -d guacamole_db`

### Issue: Data Doesn't Match

**Row counts don't match:**
- **Solution**: 
  1. Check migration logs for errors
  2. Re-run migration (it's safe to re-run - will insert duplicates)
  3. Or manually verify specific tables

---

## Database Separation Verification

To verify databases are separate:

```sql
-- Connect to PostgreSQL
psql -U postgres -h localhost

-- List all databases
\l

-- You should see:
--  ctf_platform    (your main CTF platform database)
--  guacamole_db     (migrated Guacamole database)
--  postgres         (default PostgreSQL database)

-- Connect to guacamole_db
\c guacamole_db

-- List tables (should only see Guacamole tables)
\dt

-- Connect to ctf_platform
\c ctf_platform

-- List tables (should only see CTF platform tables)
\dt
```

---

## Backup Recommendations

**Before Migration:**
1. ✅ Backup MySQL database:
   ```bash
   mysqldump -u guacamole_user -p guacamole_db > guacamole_mysql_backup.sql
   ```

**After Migration:**
2. ✅ Backup PostgreSQL database:
   ```bash
   pg_dump -U postgres -h localhost guacamole_db > guacamole_postgresql_backup.sql
   ```

**Keep Both Backups** until you've verified everything works!

---

## Rollback Plan

If you need to rollback:

1. **Stop Guacamole service**
2. **Restore MySQL database** (if you kept it)
3. **Update configuration** back to MySQL
4. **Restart Guacamole**

Or keep both databases running during transition period.

---

## Summary

✅ **Completed Steps:**
1. Created PostgreSQL database `guacamole_db`
2. Created PostgreSQL schema
3. Migrated all data from MySQL
4. Updated Guacamole configuration
5. Tested Guacamole service

✅ **Databases Remain Separate:**
- `ctf_platform` (PostgreSQL) - Main CTF platform
- `guacamole_db` (PostgreSQL) - Guacamole connections

Both databases are on PostgreSQL but are **completely separate** - no mixing of data!

---

## Additional Resources

- **PostgreSQL Documentation**: https://www.postgresql.org/docs/
- **Guacamole PostgreSQL Setup**: https://guacamole.apache.org/doc/gug/jdbc-auth.html#postgresql
- **pgAdmin Documentation**: https://www.pgadmin.org/docs/

---

## Support

If you encounter issues:
1. Check migration logs
2. Verify database connections
3. Check Guacamole logs
4. Review this guide's troubleshooting section

Good luck with your migration! 🚀

