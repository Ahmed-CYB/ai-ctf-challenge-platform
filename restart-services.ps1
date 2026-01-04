# PowerShell Script to Restart All CTF Platform Services
# Usage: .\restart-services.ps1

Write-Host "`n🔄 CTF Platform Service Restart" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Step 1: Stop all services
Write-Host "🛑 Stopping all services..." -ForegroundColor Yellow
docker compose -f docker/docker-compose.app.yml down
docker compose -f docker/docker-compose.ctf.yml down

if ($LASTEXITCODE -ne 0) {
    Write-Host "⚠️  Warning: Some services may not have stopped cleanly" -ForegroundColor Yellow
}

# Step 2: Wait a bit
Write-Host "`n⏳ Waiting 5 seconds for cleanup..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Step 3: Start all services
Write-Host "`n🚀 Starting all services..." -ForegroundColor Green
docker compose -f docker/docker-compose.app.yml up -d
docker compose -f docker/docker-compose.ctf.yml up -d

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Error starting services!" -ForegroundColor Red
    exit 1
}

# Step 4: Wait for services to initialize
Write-Host "`n⏳ Waiting 10 seconds for services to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Step 5: Check service status
Write-Host "`n✅ Checking service status..." -ForegroundColor Cyan
Write-Host "`n📊 Running Containers:" -ForegroundColor Cyan
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | Select-String "backend|frontend|ctf-automation|postgres|guacamole|guacd"

# Step 6: Display service URLs
Write-Host "`n📋 Service URLs:" -ForegroundColor Cyan
Write-Host "   🌐 Frontend:    http://localhost:4000" -ForegroundColor Green
Write-Host "   🔧 Backend:     http://localhost:4002" -ForegroundColor Green
Write-Host "   🤖 CTF API:     http://localhost:4003" -ForegroundColor Green
Write-Host "   🖥️  Guacamole:   http://localhost:8081/guacamole" -ForegroundColor Green

# Step 7: Check for errors in logs
Write-Host "`n🔍 Checking for errors in CTF automation logs..." -ForegroundColor Cyan
$ctfLogs = docker logs ctf-automation-new --tail 20 2>&1
$errors = $ctfLogs | Select-String -Pattern "error|Error|ERROR|failed|Failed|FAILED" -CaseSensitive:$false

if ($errors) {
    Write-Host "⚠️  Found potential errors in logs:" -ForegroundColor Yellow
    $errors | ForEach-Object { Write-Host "   $_" -ForegroundColor Yellow }
} else {
    Write-Host "✅ No errors found in recent logs" -ForegroundColor Green
}

# Step 8: Verify new fixes are active
Write-Host "`n🔍 Verifying new fixes are active..." -ForegroundColor Cyan
$fixesCheck = docker logs ctf-automation-new --tail 50 2>&1 | Select-String -Pattern "Database connection configured|Session cleanup scheduled|graceful shutdown|mutex|userCreationLocks"

if ($fixesCheck) {
    Write-Host "✅ New fixes detected in logs:" -ForegroundColor Green
    $fixesCheck | ForEach-Object { Write-Host "   $_" -ForegroundColor Green }
} else {
    Write-Host "⚠️  Could not verify fixes in logs (may need to check manually)" -ForegroundColor Yellow
}

Write-Host "`n✨ Restart complete!`n" -ForegroundColor Green
Write-Host "💡 Tip: Use 'docker logs -f ctf-automation-new' to follow logs" -ForegroundColor Cyan
Write-Host "💡 Tip: Use 'docker ps' to see all running containers`n" -ForegroundColor Cyan


