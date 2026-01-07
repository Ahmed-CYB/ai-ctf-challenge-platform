# pgAdmin Quick Reference for Guacamole Migration

## Quick Setup in pgAdmin

### 1. Create Database

1. **Right-click** on "Databases" → **Create** → **Database...**
2. **General Tab:**
   - **Database**: `guacamole_db`
   - **Owner**: `postgres` (or your user)
3. Click **Save**

### 2. Create User (Optional)

1. **Right-click** on "Login/Group Roles" → **Create** → **Login/Group Role...**
2. **General Tab:**
   - **Name**: `guacamole_user`
3. **Definition Tab:**
   - **Password**: `guacamole_password_123`
4. **Privileges Tab:**
   - ✅ Can login?
   - ❌ Create databases?
   - ❌ Create roles?
5. Click **Save**

### 3. Grant Permissions

1. **Right-click** on `guacamole_db` → **Properties**
2. **Security Tab** → Click **Add**
3. Select `guacamole_user`
4. Grant: **ALL** privileges
5. Click **Save**

### 4. Create Schema

1. **Right-click** on `guacamole_db` → **Query Tool**
2. **File** → **Open** → Select `database/guacamole-postgresql-schema.sql`
3. Click **Execute** (F5)
4. Wait for "Success" message

### 5. Verify Tables

1. Expand: `guacamole_db` → `Schemas` → `public` → `Tables`
2. You should see 23 tables:
   - `guacamole_connection`
   - `guacamole_connection_group`
   - `guacamole_entity`
   - `guacamole_user`
   - ... (and 19 more)

### 6. View Data (After Migration)

1. **Right-click** on any table → **View/Edit Data** → **All Rows**
2. Verify data is present

---

## Common pgAdmin Queries

### Check Database Size
```sql
SELECT pg_size_pretty(pg_database_size('guacamole_db'));
```

### List All Tables
```sql
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name LIKE 'guacamole_%'
ORDER BY table_name;
```

### Count Rows in All Tables
```sql
SELECT 
    schemaname,
    tablename,
    n_live_tup as row_count
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY tablename;
```

### Check Connections
```sql
SELECT 
    datname,
    usename,
    application_name,
    client_addr,
    state
FROM pg_stat_activity
WHERE datname = 'guacamole_db';
```

### Backup Database (via pgAdmin)
1. **Right-click** on `guacamole_db` → **Backup...**
2. **Filename**: `guacamole_db_backup.sql`
3. **Format**: `Plain`
4. Click **Backup**

### Restore Database (via pgAdmin)
1. **Right-click** on `guacamole_db` → **Restore...**
2. **Filename**: Select your backup file
3. Click **Restore**

---

## Troubleshooting in pgAdmin

### Can't Connect to Server
- Check PostgreSQL service is running
- Verify connection settings (host, port, username)
- Check `pg_hba.conf` allows connections

### Permission Denied
- Grant privileges to user:
  ```sql
  GRANT ALL PRIVILEGES ON DATABASE guacamole_db TO guacamole_user;
  ```

### Schema Not Found
- Make sure you're connected to the correct database
- Check schema exists: `SELECT schema_name FROM information_schema.schemata;`

### Tables Not Showing
- Refresh: Right-click on "Tables" → **Refresh**
- Check you're in the correct schema: `public`

---

## Visual Verification Checklist

After migration, verify in pgAdmin:

- [ ] Database `guacamole_db` exists
- [ ] 23 tables visible under `Schemas` → `public` → `Tables`
- [ ] Tables have data (check row counts)
- [ ] No error messages in Query Tool
- [ ] Sequences are set correctly (check table properties)

---

## pgAdmin Keyboard Shortcuts

- **F5**: Execute query
- **F7**: Explain query plan
- **Ctrl+Space**: Auto-complete
- **Ctrl+Shift+C**: Comment/Uncomment
- **Ctrl+Enter**: Execute current query

---

## Next Steps After Migration

1. ✅ Verify data in pgAdmin
2. ✅ Update Guacamole configuration
3. ✅ Test Guacamole service
4. ✅ Keep MySQL as backup until verified

Good luck! 🎉

