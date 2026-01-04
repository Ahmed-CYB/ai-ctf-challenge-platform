# Guacamole Connection Test Script
# Tests SSH connectivity, user creation, and password validation

Write-Host "=== Guacamole Connection Testing ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check SSH is running on attacker container
Write-Host "Test 1: Checking SSH service on attacker container..." -ForegroundColor Yellow
$sshCheck = docker exec ctf-corporate-data-breach-ftp-server-misconfiguration-attacker ps aux | Select-String "sshd"
if ($sshCheck) {
    Write-Host "  ✓ SSH service is running" -ForegroundColor Green
} else {
    Write-Host "  ✗ SSH service is NOT running" -ForegroundColor Red
}

# Test 2: Check SSH port is listening
Write-Host "`nTest 2: Checking SSH port 22 is listening..." -ForegroundColor Yellow
$portCheck = docker exec ctf-corporate-data-breach-ftp-server-misconfiguration-attacker netstat -tlnp | Select-String ":22"
if ($portCheck) {
    Write-Host "  ✓ SSH port 22 is listening" -ForegroundColor Green
    Write-Host "    $portCheck" -ForegroundColor Gray
} else {
    Write-Host "  ✗ SSH port 22 is NOT listening" -ForegroundColor Red
}

# Test 3: Check SSH configuration
Write-Host "`nTest 3: Checking SSH configuration..." -ForegroundColor Yellow
$sshConfig = docker exec ctf-corporate-data-breach-ftp-server-misconfiguration-attacker cat /etc/ssh/sshd_config
$permitRoot = $sshConfig | Select-String "PermitRootLogin yes"
$passwordAuth = $sshConfig | Select-String "PasswordAuthentication yes"

if ($permitRoot) {
    Write-Host "  ✓ PermitRootLogin is enabled" -ForegroundColor Green
} else {
    Write-Host "  ✗ PermitRootLogin is NOT enabled" -ForegroundColor Red
}

if ($passwordAuth) {
    Write-Host "  ✓ PasswordAuthentication is enabled" -ForegroundColor Green
} else {
    Write-Host "  ✗ PasswordAuthentication is NOT enabled" -ForegroundColor Red
}

# Test 4: Check kali user exists
Write-Host "`nTest 4: Checking kali user..." -ForegroundColor Yellow
$kaliUser = docker exec ctf-corporate-data-breach-ftp-server-misconfiguration-attacker id kali
if ($kaliUser) {
    Write-Host "  ✓ kali user exists" -ForegroundColor Green
    Write-Host "    $kaliUser" -ForegroundColor Gray
} else {
    Write-Host "  ✗ kali user does NOT exist" -ForegroundColor Red
}

# Test 5: Check network IPs
Write-Host "`nTest 5: Checking network IPs..." -ForegroundColor Yellow
$ips = docker exec ctf-corporate-data-breach-ftp-server-misconfiguration-attacker hostname -I
Write-Host "  Container IPs: $ips" -ForegroundColor Gray
if ($ips -match "172\.22\.\d+\.\d+") {
    Write-Host "  ✓ Container is on ctf-instances-network (172.22.x.x)" -ForegroundColor Green
} else {
    Write-Host "  ✗ Container is NOT on ctf-instances-network" -ForegroundColor Red
}

# Test 6: Check Guacamole connection
Write-Host "`nTest 6: Checking Guacamole connection in database..." -ForegroundColor Yellow
$connection = docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "SELECT connection_id, connection_name, protocol FROM guacamole_connection WHERE connection_id = 8;" -sN 2>$null
if ($connection -match "ssh") {
    Write-Host "  ✓ Connection 8 exists with SSH protocol" -ForegroundColor Green
    Write-Host "    $connection" -ForegroundColor Gray
} else {
    Write-Host "  ✗ Connection 8 does NOT have SSH protocol" -ForegroundColor Red
}

# Test 7: Check connection parameters
Write-Host "`nTest 7: Checking connection parameters..." -ForegroundColor Yellow
$params = docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "SELECT parameter_name, parameter_value FROM guacamole_connection_parameter WHERE connection_id = 8 ORDER BY parameter_name;" -sN 2>$null
$requiredParams = @("hostname", "port", "username", "password")
$paramLines = $params -split "`n" | Where-Object { $_ -match "`t" }
$paramMap = @{}
foreach ($line in $paramLines) {
    $parts = $line -split "`t"
    if ($parts.Length -eq 2) {
        $paramMap[$parts[0]] = $parts[1]
    }
}

foreach ($param in $requiredParams) {
    if ($paramMap.ContainsKey($param)) {
        Write-Host "  ✓ $param = $($paramMap[$param])" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $param is MISSING" -ForegroundColor Red
    }
}

# Test 8: Check Guacamole users
Write-Host "`nTest 8: Checking Guacamole users..." -ForegroundColor Yellow
$users = docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "SELECT e.name, u.entity_id, u.disabled FROM guacamole_entity e LEFT JOIN guacamole_user u ON e.entity_id = u.entity_id WHERE e.name LIKE 'ctf_%' ORDER BY e.entity_id DESC LIMIT 5;" -sN 2>$null
$userLines = $users -split "`n" | Where-Object { $_ -match "`t" }
Write-Host "  Found $($userLines.Count) session users:" -ForegroundColor Gray
foreach ($line in $userLines) {
    $parts = $line -split "`t"
    if ($parts.Length -ge 3) {
        $disabled = if ($parts[2] -eq "0") { "enabled" } else { "disabled" }
        Write-Host "    - $($parts[0]) (ID: $($parts[1]), $disabled)" -ForegroundColor Gray
    }
}

# Test 9: Check user permissions
Write-Host "`nTest 9: Checking user permissions..." -ForegroundColor Yellow
$permissions = docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -e "SELECT entity_id, connection_id, permission FROM guacamole_connection_permission WHERE connection_id = 8;" -sN 2>$null
if ($permissions) {
    Write-Host "  ✓ Users have permissions on connection 8" -ForegroundColor Green
    Write-Host "    $permissions" -ForegroundColor Gray
} else {
    Write-Host "  ✗ No permissions found for connection 8" -ForegroundColor Red
}

# Test 10: Check Guacamole API
Write-Host "`nTest 10: Testing Guacamole API..." -ForegroundColor Yellow
$apiResponse = docker exec ctf-guacamole-new curl -s http://localhost:8080/guacamole/api/tokens -X POST -d "username=guacadmin&password=guacadmin" -H "Content-Type: application/x-www-form-urlencoded" 2>$null
if ($apiResponse -match "authToken") {
    Write-Host "  ✓ Guacamole API is working" -ForegroundColor Green
} else {
    Write-Host "  ✗ Guacamole API is NOT working" -ForegroundColor Red
    Write-Host "    Response: $apiResponse" -ForegroundColor Gray
}

Write-Host "`n=== Testing Complete ===" -ForegroundColor Cyan


