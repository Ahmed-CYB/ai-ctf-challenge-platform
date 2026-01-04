# Guacamole Database Information

## 🗄️ **Database Type: MySQL 8.0**

Guacamole uses **MySQL 8.0** (not PostgreSQL) for its database.

---

## 📋 **Current Configuration**

### **Database Details**
- **Type**: MySQL 8.0
- **Image**: `mysql:8.0` (Docker)
- **Container Name**: `ctf-guacamole-db-new`
- **Database Name**: `guacamole_db`
- **Username**: `guacamole_user`
- **Password**: `guacamole_password_123` (default, configurable via env)
- **Root Password**: `root_password_123` (default, configurable via env)

### **Port Configuration**
- **Internal Port**: 3306 (MySQL default)
- **External Port**: 3307 (mapped to avoid conflicts)
- **Connection**: `localhost:3307` (from host) or `guacamole-db-new:3306` (from Docker network)

### **Environment Variables**
```env
GUACAMOLE_DB_PASSWORD=guacamole_password_123
GUACAMOLE_ROOT_PASSWORD=root_password_123
GUACAMOLE_DB_PORT=3307
```

---

## 🔍 **Why MySQL for Guacamole?**

Guacamole officially supports:
- ✅ **MySQL** (recommended)
- ✅ **PostgreSQL** (also supported)
- ✅ **SQL Server** (also supported)

**Your setup uses MySQL** because:
1. **Official recommendation** - MySQL is the most commonly used and tested
2. **Docker image** - Easy to deploy with `mysql:8.0`
3. **Performance** - Well-optimized for Guacamole's schema
4. **Compatibility** - All Guacamole features work perfectly with MySQL

---

## 📊 **Database Architecture**

### **Two Separate Databases**

Your platform uses **two different databases**:

1. **CTF Platform Database** → **PostgreSQL**
   - Stores: Users, sessions, chat messages, challenges, tool learning data
   - Port: 5432 (real) or 5433 (Docker)
   - Database: `ctf_platform`

2. **Guacamole Database** → **MySQL**
   - Stores: Guacamole users, connections, permissions, sessions
   - Port: 3307 (external) or 3306 (internal)
   - Database: `guacamole_db`

### **Why Separate?**

- **Different purposes**: CTF platform data vs. Guacamole connection data
- **Different schemas**: PostgreSQL for application data, MySQL for Guacamole
- **Isolation**: Guacamole can be updated/replaced without affecting main platform
- **Performance**: Each database optimized for its specific use case

---

## 🔧 **Accessing Guacamole MySQL Database**

### **From Host Machine (Outside Docker)**

```bash
# Connect to MySQL
mysql -h localhost -P 3307 -u guacamole_user -p guacamole_db
# Password: guacamole_password_123
```

### **From Docker Container**

```bash
# Execute MySQL command in container
docker exec -it ctf-guacamole-db-new mysql -u guacamole_user -p guacamole_db
# Password: guacamole_password_123
```

### **Using MySQL Client Tools**

**Windows**:
- MySQL Workbench
- HeidiSQL
- DBeaver

**macOS/Linux**:
- MySQL Workbench
- DBeaver
- Command line: `mysql`

**Connection Details**:
- Host: `localhost`
- Port: `3307`
- Database: `guacamole_db`
- Username: `guacamole_user`
- Password: `guacamole_password_123`

---

## 📝 **Key Guacamole Tables**

The Guacamole MySQL database contains tables like:

- `guacamole_entity` - Users and user groups
- `guacamole_user` - User accounts with passwords
- `guacamole_connection` - SSH/RDP/VNC connections
- `guacamole_connection_parameter` - Connection settings (hostname, port, etc.)
- `guacamole_connection_permission` - User permissions for connections
- `guacamole_system_permission` - System-level permissions (admin, etc.)

---

## 🔄 **Switching Guacamole to Real MySQL (Non-Docker)**

If you want to use a real MySQL installation instead of Docker:

### **Step 1: Install MySQL**

**Windows**:
- Download from [MySQL Official Site](https://dev.mysql.com/downloads/mysql/)
- Or use: `choco install mysql`

**macOS**:
```bash
brew install mysql@8.0
brew services start mysql@8.0
```

**Linux**:
```bash
sudo apt-get install mysql-server-8.0  # Ubuntu/Debian
sudo yum install mysql-server          # RHEL/CentOS
```

### **Step 2: Create Database and User**

```sql
-- Connect as root
mysql -u root -p

-- Create database
CREATE DATABASE guacamole_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'guacamole_password_123';
CREATE USER 'guacamole_user'@'%' IDENTIFIED BY 'guacamole_password_123';

-- Grant privileges
GRANT SELECT,INSERT,UPDATE,DELETE ON guacamole_db.* TO 'guacamole_user'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON guacamole_db.* TO 'guacamole_user'@'%';

FLUSH PRIVILEGES;
```

### **Step 3: Initialize Guacamole Schema**

```bash
# Download Guacamole SQL schema
# Or use the existing guacamole-init.sql file

# Import schema
mysql -u guacamole_user -p guacamole_db < guacamole-init.sql
```

### **Step 4: Update Docker Compose**

Edit `docker/docker-compose.infrastructure.yml`:

```yaml
services:
  guacamole-new:
    environment:
      MYSQL_HOSTNAME: host.docker.internal  # For Windows/Mac
      # OR
      MYSQL_HOSTNAME: 172.17.0.1  # For Linux (Docker bridge IP)
      MYSQL_PORT: 3306  # Real MySQL port
      MYSQL_DATABASE: guacamole_db
      MYSQL_USERNAME: guacamole_user
      MYSQL_PASSWORD: guacamole_password_123
    # Remove depends_on: guacamole-db-new

  # Comment out or remove guacamole-db-new service
  # guacamole-db-new:
  #   ...
```

### **Step 5: Update Environment Variables**

```env
# Real MySQL (not Docker)
GUACAMOLE_DB_HOST=localhost
GUACAMOLE_DB_PORT=3306
GUACAMOLE_DB_NAME=guacamole_db
GUACAMOLE_DB_USER=guacamole_user
GUACAMOLE_DB_PASSWORD=guacamole_password_123
```

---

## ⚠️ **Important Notes**

### **MySQL vs PostgreSQL**

- **Guacamole**: Uses **MySQL** (required by Guacamole architecture)
- **CTF Platform**: Uses **PostgreSQL** (your application database)

These are **separate databases** for different purposes.

### **Can Guacamole Use PostgreSQL?**

Yes! Guacamole **does support PostgreSQL**, but:
- Your current setup uses MySQL
- Switching would require:
  1. Changing Docker image from `mysql:8.0` to `postgres:15`
  2. Updating connection strings
  3. Using PostgreSQL schema instead of MySQL schema
  4. Updating all MySQL-specific queries in `session-guacamole-manager.js`

**Recommendation**: Keep MySQL for Guacamole (it's the standard setup).

---

## 📊 **Summary**

| Component | Database Type | Port | Purpose |
|-----------|--------------|------|---------|
| **CTF Platform** | PostgreSQL | 5432/5433 | Application data |
| **Guacamole** | MySQL 8.0 | 3306/3307 | Connection management |

**Current Setup**: Both in Docker containers  
**Can Switch**: CTF Platform → Real PostgreSQL ✅  
**Can Switch**: Guacamole → Real MySQL ✅  
**Can Switch**: Guacamole → PostgreSQL ⚠️ (requires code changes)

---

## 🔗 **Related Files**

- `docker/docker-compose.infrastructure.yml` - Guacamole MySQL container config
- `packages/ctf-automation/src/session-guacamole-manager.js` - MySQL queries
- `guacamole-init.sql` - Guacamole database schema


