# Victim Machine Accessibility Verification Guide

This guide helps you verify that the victim machine is working correctly after deployment.

## Quick Verification Steps

### 1. Check Container Status

```powershell
# Check if containers are running
docker ps | Select-String "operation-silent-transfer"
```

**Expected Output:**
- Both `ctf-operation-silent-transfer-attacker` and `ctf-operation-silent-transfer-ftp-server` should show "Up" status

### 2. Get IP Addresses

```powershell
# Get victim IP
docker inspect ctf-operation-silent-transfer-ftp-server --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'

# Get attacker IP
docker inspect ctf-operation-silent-transfer-attacker --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
```

**Expected Output:**
- Victim IP: `172.23.195.12` (or similar)
- Attacker IP: `172.23.195.3` (or similar)

### 3. Test Connectivity from Attacker

```powershell
# Ping test
docker exec ctf-operation-silent-transfer-attacker ping -c 2 172.23.195.12

# Port scan
docker exec ctf-operation-silent-transfer-attacker nmap -p 21 172.23.195.12
```

**Expected Output:**
- Ping: `2 packets transmitted, 2 received, 0% packet loss`
- Nmap: `21/tcp open  ftp`

### 4. Test FTP Service

```powershell
# Test FTP connection
docker exec ctf-operation-silent-transfer-attacker ftp 172.23.195.12
# Type: anonymous
# Password: (press Enter)
# Type: quit
```

**Expected Output:**
- Connection successful
- FTP banner received

### 5. Check Container Logs

```powershell
# Check victim container logs
docker logs ctf-operation-silent-transfer-ftp-server --tail 20
```

**What to Look For:**
- ✅ **Good:** No "exec format error" messages
- ✅ **Good:** "FTP server started" or similar
- ❌ **Bad:** "exec format error" (indicates script creation bug - now fixed)
- ⚠️ **Warning:** "vsftpd failed" (config issue, but container may still work)

## Automated Verification Script

Run the provided PowerShell script:

```powershell
.\verify-victim-accessibility.ps1
```

This script automatically checks:
1. Container status
2. IP addresses
3. Connectivity (ping)
4. FTP port (21)
5. Container logs
6. FTP service response

## Common Issues and Solutions

### Issue: Container Exited Immediately

**Symptoms:**
- Container status shows "Exited"
- Logs show "exec format error"

**Solution:**
- This was a bug in startup script creation (now fixed)
- The auto-fix mechanism will handle this automatically
- For current container: Manually fix the script (see below)

### Issue: No IP Address

**Symptoms:**
- `docker inspect` returns empty IP
- Container is running but not accessible

**Solution:**
- Check network configuration in docker-compose.yml
- Verify container is connected to challenge network
- Auto-fix will reconnect container to network

### Issue: Cannot Ping Victim

**Symptoms:**
- Ping fails from attacker
- Container is running and has IP

**Solution:**
- Wait a few seconds for network to stabilize
- Check firewall rules (shouldn't be an issue in Docker)
- Auto-fix will wait and retry connectivity

### Issue: FTP Port Not Open

**Symptoms:**
- Nmap shows port 21 as closed
- Container is running

**Solution:**
- Check if vsftpd service started correctly
- Check container logs for vsftpd errors
- Auto-fix will restart services or container

## Manual Fix (If Needed)

If the container has issues, you can manually fix it:

### Fix Startup Script

```powershell
# Create a proper startup script
$script = @'
#!/bin/bash
set -e
# Your service startup commands here
tail -f /dev/null
'@

$script | Out-File -FilePath start-services-fix.sh -Encoding ASCII -NoNewline
docker cp start-services-fix.sh ctf-operation-silent-transfer-ftp-server:/start-services.sh
docker exec ctf-operation-silent-transfer-ftp-server chmod +x /start-services.sh
docker restart ctf-operation-silent-transfer-ftp-server
Remove-Item start-services-fix.sh
```

### Restart Container

```powershell
docker restart ctf-operation-silent-transfer-ftp-server
```

### Check After Restart

```powershell
Start-Sleep -Seconds 3
docker ps | Select-String "operation-silent-transfer"
docker inspect ctf-operation-silent-transfer-ftp-server --format='{{.State.Status}}'
```

## Verification Checklist

- [ ] Victim container is running
- [ ] Attacker container is running
- [ ] Victim has IP address assigned
- [ ] Attacker can ping victim
- [ ] FTP port (21) is open
- [ ] No "exec format error" in logs
- [ ] FTP service responds to connections

## What the Auto-Fix Does

The system now automatically:
1. **Detects** when victim container is not running → Starts it
2. **Detects** when services are not running → Restarts services or container
3. **Detects** when IP is not assigned → Reconnects to network
4. **Detects** connectivity issues → Waits and retries
5. **Re-validates** after fixes to confirm they worked

All of this happens automatically during deployment!


