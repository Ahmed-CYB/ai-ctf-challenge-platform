# Migration Files Summary

## 📁 Files Created for MySQL to PostgreSQL Migration

This document lists all files created to help you migrate the Guacamole MySQL database to PostgreSQL.

---

## 📄 Core Migration Files

### 1. `database/guacamole-postgresql-schema.sql`
**Purpose**: PostgreSQL schema for Guacamole database  
**Usage**: Run this in pgAdmin or psql to create the database structure  
**Contains**: 
- All 23 Guacamole tables converted from MySQL to PostgreSQL
- Proper data types (SERIAL, BYTEA, etc.)
- Foreign keys and constraints
- Indexes for performance
- Initial admin user setup

### 2. `migrate_mysql_to_postgresql.py`
**Purpose**: Python script to migrate data from MySQL to PostgreSQL  
**Usage**: 
```bash
pip install -r requirements-migration.txt
python migrate_mysql_to_postgresql.py --pg-password YOUR_PASSWORD
```
**Features**:
- Connects to both MySQL and PostgreSQL
- Migrates all tables in correct order (respecting foreign keys)
- Handles binary data conversion (passwords, etc.)
- Resets sequences automatically
- Verifies row counts match
- Batch processing for large tables

### 3. `requirements-migration.txt`
**Purpose**: Python dependencies for migration script  
**Usage**: `pip install -r requirements-migration.txt`  
**Contains**:
- `mysql-connector-python` - MySQL connection
- `psycopg2-binary` - PostgreSQL connection

---

## 📚 Documentation Files

### 4. `MYSQL_TO_POSTGRESQL_MIGRATION_GUIDE.md`
**Purpose**: Complete step-by-step migration guide  
**Contains**:
- Prerequisites
- Database creation (pgAdmin & command line)
- Schema setup
- Data migration steps
- Configuration updates
- Testing procedures
- Troubleshooting
- Rollback plan

### 5. `PGADMIN_QUICK_REFERENCE.md`
**Purpose**: Quick reference for using pgAdmin  
**Contains**:
- Step-by-step pgAdmin instructions
- Common SQL queries
- Troubleshooting tips
- Keyboard shortcuts
- Verification checklist

### 6. `MIGRATION_FILES_SUMMARY.md` (this file)
**Purpose**: Overview of all migration files

---

## 🚀 Quick Start

### Step 1: Install Dependencies
```bash
pip install -r requirements-migration.txt
```

### Step 2: Create PostgreSQL Database
**Using pgAdmin:**
1. Create database: `guacamole_db`
2. Create user: `guacamole_user` (optional)
3. Grant permissions

**Or using psql:**
```bash
psql -U postgres -c "CREATE DATABASE guacamole_db;"
```

### Step 3: Create Schema
**Using pgAdmin:**
1. Open Query Tool on `guacamole_db`
2. File → Open → `database/guacamole-postgresql-schema.sql`
3. Execute (F5)

**Or using psql:**
```bash
psql -U postgres -d guacamole_db -f database/guacamole-postgresql-schema.sql
```

### Step 4: Migrate Data
```bash
python migrate_mysql_to_postgresql.py --pg-password YOUR_POSTGRES_PASSWORD
```

### Step 5: Verify
- Check tables in pgAdmin
- Verify row counts
- Test Guacamole service

---

## 📋 Migration Checklist

- [ ] Install Python dependencies
- [ ] Create PostgreSQL database `guacamole_db`
- [ ] Create PostgreSQL user `guacamole_user` (optional)
- [ ] Run schema script (`guacamole-postgresql-schema.sql`)
- [ ] Backup MySQL database (safety)
- [ ] Run migration script
- [ ] Verify data in pgAdmin
- [ ] Update Guacamole configuration
- [ ] Test Guacamole service
- [ ] Keep MySQL as backup until verified

---

## 🔍 Database Separation

**Important**: The databases remain **completely separate**:

1. **CTF Platform Database**: `ctf_platform` (PostgreSQL)
   - Port: 5433 (Docker) or 5432 (real PostgreSQL)
   - Contains: Users, sessions, challenges, chat messages, etc.

2. **Guacamole Database**: `guacamole_db` (PostgreSQL)
   - Port: 5432 (same PostgreSQL server, different database)
   - Contains: Guacamole users, connections, permissions, etc.

Both databases are on PostgreSQL but are **separate databases** - no data mixing!

---

## 🆘 Need Help?

1. **Read the full guide**: `MYSQL_TO_POSTGRESQL_MIGRATION_GUIDE.md`
2. **Check pgAdmin reference**: `PGADMIN_QUICK_REFERENCE.md`
3. **Review troubleshooting section** in the main guide
4. **Check migration script output** for specific errors

---

## 📝 Notes

- **Backup First**: Always backup before migration
- **Test Environment**: Test in development first if possible
- **Keep MySQL**: Keep MySQL database until migration is verified
- **Sequences**: Migration script automatically resets sequences
- **Binary Data**: Script handles password hashes and binary data correctly

---

## ✅ Success Criteria

Migration is successful when:
1. ✅ All 23 tables exist in PostgreSQL
2. ✅ Row counts match between MySQL and PostgreSQL
3. ✅ Guacamole can connect to PostgreSQL
4. ✅ Guacamole login works
5. ✅ Connections can be created/accessed

Good luck with your migration! 🎉

