# Test CTF Deployment and Guacamole Access
# This script tests the complete CTF deployment pipeline

Write-Host "🧪 Testing CTF Deployment System" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Step 1: Check if services are running
Write-Host "📊 Step 1: Checking Services..." -ForegroundColor Yellow
$ctfServiceRunning = Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -like "*3003*" }
$guacamoleRunning = docker ps --filter "name=ctf-guacamole" --format "{{.Status}}" 2>$null

if (-not $ctfServiceRunning) {
    Write-Host "❌ CTF Automation Service not running on port 3003" -ForegroundColor Red
    Write-Host "   Starting service..." -ForegroundColor Yellow
    Start-Process pwsh -ArgumentList "-NoExit", "-Command", "cd 'ctf-automation'; node src/index.js" -WindowStyle Normal
    Start-Sleep -Seconds 3
}

if ($guacamoleRunning -notlike "*Up*") {
    Write-Host "❌ Guacamole not running" -ForegroundColor Red
    Write-Host "   Start Guacamole with: docker-compose -f docker-compose.guacamole.yml up -d" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Services running`n" -ForegroundColor Green

# Step 2: Clean up old test challenges
Write-Host "📊 Step 2: Cleaning Old Test Challenges..." -ForegroundColor Yellow
$oldContainers = docker ps -a --filter "name=ftp-test" --format "{{.Names}}" 2>$null
if ($oldContainers) {
    docker rm -f $oldContainers 2>$null | Out-Null
    Write-Host "✅ Cleaned up old containers" -ForegroundColor Green
} else {
    Write-Host "✅ No old containers to clean" -ForegroundColor Green
}
Write-Host ""

# Step 3: Create a test FTP challenge
Write-Host "📊 Step 3: Creating Test FTP Challenge..." -ForegroundColor Yellow
$requestBody = @{
    userId = "test-user-$(Get-Random -Minimum 100 -Maximum 999)"
    category = "network"
    difficulty = "easy"
    sessionId = "test-session-$(Get-Date -Format 'yyyyMMddHHmmss')"
} | ConvertTo-Json

Write-Host "Request: $requestBody`n" -ForegroundColor Gray

$response = Invoke-WebRequest -Uri "http://localhost:3003/api/ctf/create" `
    -Method POST `
    -ContentType "application/json" `
    -Body $requestBody `
    -UseBasicParsing

$result = $response.Content | ConvertFrom-Json

Write-Host "✅ Challenge created: $($result.challenge.name)" -ForegroundColor Green
Write-Host "   Challenge ID: $($result.challenge.id)" -ForegroundColor Gray
Write-Host "   Category: $($result.challenge.category)" -ForegroundColor Gray
Write-Host "   Difficulty: $($result.challenge.difficulty)`n" -ForegroundColor Gray

# Step 4: Wait for containers to start
Write-Host "📊 Step 4: Waiting for Containers..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Step 5: Check container status
Write-Host "📊 Step 5: Checking Container Status..." -ForegroundColor Yellow
$victimContainer = docker ps --filter "name=victim" --format "{{.Names}}: {{.Status}}" | Select-Object -First 1
$attackerContainer = docker ps -a --filter "name=attacker" --format "{{.Names}}: {{.Status}}" | Select-Object -First 1

Write-Host "   Victim: $victimContainer" -ForegroundColor $(if ($victimContainer -like "*Up*") { "Green" } else { "Red" })
Write-Host "   Attacker: $attackerContainer" -ForegroundColor $(if ($attackerContainer -like "*Up*") { "Green" } else { "Red" })

# Check if attacker crashed
if ($attackerContainer -like "*Exited*") {
    Write-Host "`n❌ Attacker container crashed! Checking logs..." -ForegroundColor Red
    $containerName = ($attackerContainer -split ":")[0]
    $logs = docker logs $containerName 2>&1 | Select-Object -Last 20
    Write-Host "`nLast 20 log lines:" -ForegroundColor Yellow
    $logs | ForEach-Object { Write-Host "   $_" -ForegroundColor Gray }
}

Write-Host ""

# Step 6: Display Guacamole access information
Write-Host "📊 Step 6: Guacamole Access Information" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan

if ($result.guacamoleInfo) {
    Write-Host "✅ Guacamole Connection Created!" -ForegroundColor Green
    Write-Host "`n   🔗 URL:      $($result.guacamoleInfo.url)" -ForegroundColor Cyan
    Write-Host "   👤 Username: $($result.guacamoleInfo.username)" -ForegroundColor Cyan
    Write-Host "   🔑 Password: $($result.guacamoleInfo.password)" -ForegroundColor Cyan
    Write-Host "   🆔 Conn ID:  $($result.guacamoleInfo.connectionId)`n" -ForegroundColor Cyan
    
    Write-Host "📝 To access Kali Linux desktop:" -ForegroundColor Yellow
    Write-Host "   1. Navigate to: $($result.guacamoleInfo.url)" -ForegroundColor White
    Write-Host "   2. Login with username: $($result.guacamoleInfo.username)" -ForegroundColor White
    Write-Host "   3. Password: $($result.guacamoleInfo.password)" -ForegroundColor White
    Write-Host "   4. Click on the connection in the dashboard" -ForegroundColor White
} else {
    Write-Host "⚠️  No Guacamole info in response" -ForegroundColor Red
}

Write-Host "`n📋 Network Information:" -ForegroundColor Yellow
if ($result.deployment) {
    Write-Host "   Subnet:      $($result.deployment.subnet)" -ForegroundColor White
    Write-Host "   Victim IP:   $($result.deployment.victimIP)" -ForegroundColor White
    Write-Host "   Attacker IP: $($result.deployment.attackerIP)" -ForegroundColor White
}

Write-Host "`n🎯 Testing Guacamole Login..." -ForegroundColor Yellow

# Try to login to Guacamole with demo credentials
try {
    $loginResponse = Invoke-WebRequest -Uri "http://localhost:8080/guacamole/api/tokens" `
        -Method POST `
        -ContentType "application/x-www-form-urlencoded" `
        -Body "username=demo&password=password123" `
        -UseBasicParsing `
        -ErrorAction Stop
    
    Write-Host "✅ Guacamole login successful!" -ForegroundColor Green
    Write-Host "   Auth token received" -ForegroundColor Gray
} catch {
    Write-Host "❌ Guacamole login failed!" -ForegroundColor Red
    Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`n   Checking if demo user exists..." -ForegroundColor Yellow
    
    # Check database for demo user
    $userCheck = docker exec hackytalk_db psql -U postgres -d guacamole_db -t -c "SELECT name FROM guacamole_entity WHERE name='demo';" 2>$null
    if ($userCheck) {
        Write-Host "   ✅ Demo user exists in database: $($userCheck.Trim())" -ForegroundColor Green
        Write-Host "   ⚠️  Password might be incorrect or Guacamole auth issue" -ForegroundColor Yellow
    } else {
        Write-Host "   ❌ Demo user NOT found in database!" -ForegroundColor Red
        Write-Host "   Run: node src/guacamole-postgresql-manager.js to create" -ForegroundColor Yellow
    }
}

Write-Host "`n✅ Test Complete!" -ForegroundColor Green
Write-Host "================`n" -ForegroundColor Cyan
