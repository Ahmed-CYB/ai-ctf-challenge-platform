# Verification Script for Victim Machine Accessibility
# This script verifies that the victim container is running and accessible

Write-Host "`n🔍 VICTIM MACHINE ACCESSIBILITY VERIFICATION" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$challengeName = "operation-silent-transfer"
$victimContainer = "ctf-$challengeName-ftp-server"
$attackerContainer = "ctf-$challengeName-attacker"

Write-Host "`n1️⃣ Checking Container Status..." -ForegroundColor Yellow
$victimStatus = docker ps -a --filter "name=$victimContainer" --format "{{.Status}}"
$attackerStatus = docker ps -a --filter "name=$attackerContainer" --format "{{.Status}}"

if ($victimStatus -match "Up") {
    Write-Host "   ✅ Victim container is RUNNING" -ForegroundColor Green
} else {
    Write-Host "   ❌ Victim container is NOT running: $victimStatus" -ForegroundColor Red
}

if ($attackerStatus -match "Up") {
    Write-Host "   ✅ Attacker container is RUNNING" -ForegroundColor Green
} else {
    Write-Host "   ❌ Attacker container is NOT running: $attackerStatus" -ForegroundColor Red
}

Write-Host "`n2️⃣ Getting IP Addresses..." -ForegroundColor Yellow
$victimIP = docker inspect $victimContainer --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>$null
$attackerIP = docker inspect $attackerContainer --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>$null

if ($victimIP) {
    Write-Host "   ✅ Victim IP: $victimIP" -ForegroundColor Green
} else {
    Write-Host "   ❌ Victim IP: NOT ASSIGNED" -ForegroundColor Red
}

if ($attackerIP) {
    Write-Host "   ✅ Attacker IP: $attackerIP" -ForegroundColor Green
} else {
    Write-Host "   ❌ Attacker IP: NOT ASSIGNED" -ForegroundColor Red
}

Write-Host "`n3️⃣ Testing Connectivity (Ping)..." -ForegroundColor Yellow
if ($victimIP -and $attackerIP) {
    $pingResult = docker exec $attackerContainer ping -c 2 $victimIP 2>&1
    if ($pingResult -match "2 received") {
        Write-Host "   ✅ Ping test PASSED - Attacker can reach victim" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Ping test FAILED" -ForegroundColor Red
        Write-Host "   Output: $pingResult" -ForegroundColor Gray
    }
} else {
    Write-Host "   ⚠️  Cannot test ping - missing IP addresses" -ForegroundColor Yellow
}

Write-Host "`n4️⃣ Testing FTP Port (21)..." -ForegroundColor Yellow
if ($victimIP) {
    $nmapResult = docker exec $attackerContainer nmap -p 21 $victimIP 2>&1
    if ($nmapResult -match "21/tcp.*open") {
        Write-Host "   ✅ FTP port 21 is OPEN" -ForegroundColor Green
    } else {
        Write-Host "   ❌ FTP port 21 is NOT open" -ForegroundColor Red
        Write-Host "   Output: $nmapResult" -ForegroundColor Gray
    }
} else {
    Write-Host "   ⚠️  Cannot test FTP port - missing victim IP" -ForegroundColor Yellow
}

Write-Host "`n5️⃣ Checking Container Logs..." -ForegroundColor Yellow
$logs = docker logs $victimContainer --tail 10 2>&1
if ($logs -match "exec format error") {
    Write-Host "   ❌ ERROR: Startup script has format error" -ForegroundColor Red
    Write-Host "   This indicates the script creation bug" -ForegroundColor Yellow
} elseif ($logs -match "vsftpd.*failed") {
    Write-Host "   ⚠️  WARNING: vsftpd config issue (but container is running)" -ForegroundColor Yellow
} else {
    Write-Host "   ✅ No critical errors in logs" -ForegroundColor Green
}

Write-Host "`n6️⃣ Testing FTP Connection..." -ForegroundColor Yellow
if ($victimIP) {
    $ftpTest = docker exec $attackerContainer sh -c "echo 'quit' | ftp -n $victimIP 2>&1 | head -5"
    if ($ftpTest -match "Connected" -or $ftpTest -match "220") {
        Write-Host "   ✅ FTP service is responding" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  FTP service may not be fully configured" -ForegroundColor Yellow
        Write-Host "   Output: $ftpTest" -ForegroundColor Gray
    }
} else {
    Write-Host "   ⚠️  Cannot test FTP - missing victim IP" -ForegroundColor Yellow
}

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "✅ VERIFICATION COMPLETE!" -ForegroundColor Green
Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "   - If victim is running and accessible: Everything is working!" -ForegroundColor White
Write-Host "   - If victim is not accessible: Check logs and network configuration" -ForegroundColor White
Write-Host "   - The auto-fix mechanism will handle issues automatically in future deployments" -ForegroundColor White

