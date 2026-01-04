# 📚 Database Migrations Explained

## 🤔 **What Are Database Migrations?**

**Database migrations** are scripts that create and update your database structure (tables, columns, indexes, etc.) in a controlled, versioned way.

Think of it like this:
- **Without migrations**: You manually create tables in the database, and if you need to change something, you manually edit it. This is error-prone and hard to track.
- **With migrations**: You have versioned SQL scripts that automatically create/update your database structure. Each migration is tracked, so you know exactly what changes have been applied.

---

## 🎯 **What Do Migrations Do in This Project?**

When you run `npm run db:migrate`, the migration script:

1. **Connects to PostgreSQL** (using `DATABASE_URL` from `.env`)
2. **Creates a tracking table** (`schema_migrations`) to record which migrations have been applied
3. **Reads all migration files** from `database/migrations/` folder
4. **Applies only new migrations** (skips ones already applied)
5. **Runs each migration in a transaction** (if it fails, it rolls back - no partial changes)

---

## 📁 **Migration Files in This Project**

Your project has these migration files:

```
database/migrations/
├── 001_add_session_columns.sql          # Adds session-related columns
├── 003_tool_learning_system.sql          # Creates tool learning tables
├── 004_add_ai_learning_method.sql       # Adds AI learning features
├── 004_fix_tool_learning_constraints.sql # Fixes constraints
├── 004_secure_sessions.sql               # Adds security features
├── 005_os_image_validation.sql         # Creates OS image validation tables
├── 006_package_service_mappings.sql     # Creates package mapping tables
├── 007_fixes_and_improvements.sql       # Various fixes
└── 008_session_improvements.sql          # Session system improvements
```

Each file contains SQL commands to:
- Create new tables
- Add new columns to existing tables
- Create indexes for performance
- Add constraints (foreign keys, unique constraints, etc.)
- Create functions and triggers

---

## 🗄️ **What Tables Are Created?**

The main schema (`database/schema.sql`) creates these core tables:

### **Core Tables:**
1. **`users`** - User accounts, profiles, streaks, leaderboard stats
2. **`sessions`** - User login sessions
3. **`challenges`** - CTF challenges created by users
4. **`chat_messages`** - Chat history between users and AI
5. **`challenge_submissions`** - User flag submissions
6. **`challenge_ratings`** - User ratings and reviews
7. **`daily_solves`** - Daily solve tracking
8. **`streak_history`** - Streak tracking history
9. **`password_reset_tokens`** - Password reset functionality
10. **`email_verification_tokens`** - Email verification
11. **`user_activity_log`** - Activity logging

### **CTF Automation Tables (from migrations):**
12. **`tool_learning_cache`** - Cached tool installation methods
13. **`os_images`** - Validated OS images for Docker
14. **`service_package_mappings`** - Service-to-package name mappings
15. **`tool_package_mappings`** - Tool-to-package name mappings
16. **`schema_migrations`** - Migration tracking table

---

## 🔄 **How Migrations Work**

### **Step 1: Check What's Already Applied**

The script checks the `schema_migrations` table to see which migrations have been run:

```sql
SELECT version FROM schema_migrations;
```

### **Step 2: Find New Migrations**

It reads all `.sql` files from `database/migrations/` and compares with applied migrations.

### **Step 3: Apply New Migrations**

For each new migration file:
1. **Start a transaction** (all-or-nothing)
2. **Execute the SQL** from the migration file
3. **Record it in `schema_migrations`** table
4. **Commit the transaction**

If any step fails, the transaction **rolls back** (undoes all changes).

---

## ✅ **Why Run Migrations?**

### **Before Running Migrations:**
- ❌ Database is empty (no tables)
- ❌ Application can't store data
- ❌ Backend will crash when trying to query tables

### **After Running Migrations:**
- ✅ All tables created
- ✅ All indexes and constraints set up
- ✅ Application can store and retrieve data
- ✅ Everything works correctly

---

## 🚀 **How to Run Migrations**

### **Command:**
```powershell
npm run db:migrate
```

### **What Happens:**
```
🔄 Starting database migrations...
📁 Migrations directory: C:\...\database\migrations
✅ Migrations table ready
📋 Found 0 applied migrations
📦 Found 8 migration files
🔄 Applying migration: 001_add_session_columns.sql
✅ Applied 001_add_session_columns.sql
🔄 Applying migration: 003_tool_learning_system.sql
✅ Applied 003_tool_learning_system.sql
...
✅ Migration complete! Applied 8 new migration(s)
```

### **Requirements:**
1. ✅ PostgreSQL must be running (Docker container `ctf-postgres-new`)
2. ✅ `.env` file must have correct `DATABASE_URL`
3. ✅ Database must exist (`ctf_platform`)

---

## 🔍 **What If I Run Migrations Twice?**

**Good news:** Migrations are **idempotent** (safe to run multiple times).

- ✅ Already-applied migrations are **skipped**
- ✅ Only new migrations are applied
- ✅ No duplicate tables or errors

Example:
```
📋 Found 8 applied migrations
📦 Found 8 migration files
⏭️  Skipping 001_add_session_columns.sql (already applied)
⏭️  Skipping 003_tool_learning_system.sql (already applied)
...
✅ Migration complete! Applied 0 new migration(s)
```

---

## 🛠️ **Migration Script Details**

The migration script (`scripts/migrate.js`) does:

1. **Connects to database** using `DATABASE_URL` from `.env`
2. **Creates `schema_migrations` table** (if it doesn't exist)
3. **Reads migration files** from `database/migrations/`
4. **Checks which are already applied**
5. **Applies new migrations in order** (sorted by filename)
6. **Records each migration** in `schema_migrations` table
7. **Uses transactions** for safety (rollback on error)

---

## 📊 **Example Migration File**

Here's what a migration file looks like:

```sql
-- 001_add_session_columns.sql

-- Add new column to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS session_timeout INTEGER DEFAULT 3600;

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_users_session_timeout 
ON users(session_timeout);

-- Add comment
COMMENT ON COLUMN users.session_timeout IS 'Session timeout in seconds';
```

---

## ⚠️ **Important Notes**

### **1. Run Migrations Before Starting Services**
Always run `npm run db:migrate` **before** starting the backend or CTF automation service. Otherwise, they'll crash when trying to query non-existent tables.

### **2. Migrations Are One-Way**
Migrations typically **add** things (tables, columns, indexes). They don't usually **remove** things. If you need to remove something, create a new migration.

### **3. Order Matters**
Migrations are applied in **alphabetical order** (by filename). That's why they're numbered:
- `001_...`
- `003_...`
- `004_...`

### **4. Don't Edit Applied Migrations**
Once a migration is applied, **don't edit it**. Create a new migration instead. Editing old migrations can cause inconsistencies.

---

## 🎯 **Summary**

| Question | Answer |
|----------|--------|
| **What are migrations?** | Versioned SQL scripts that create/update database structure |
| **Why use them?** | Track changes, ensure consistency, automate setup |
| **When to run?** | Before starting services (first time setup) |
| **How to run?** | `npm run db:migrate` |
| **Safe to run twice?** | Yes! Already-applied migrations are skipped |
| **What gets created?** | All tables, indexes, constraints, functions needed by the app |

---

## ✅ **Quick Checklist**

Before starting services locally:

1. ✅ PostgreSQL running (Docker)
2. ✅ `.env` file configured
3. ✅ Run `npm run db:migrate` ← **This step!**
4. ✅ Start services: `npm run dev`

---

**TL;DR:** Database migrations create all the tables and structure your application needs. Run `npm run db:migrate` once before starting services, and you're good to go! 🚀


