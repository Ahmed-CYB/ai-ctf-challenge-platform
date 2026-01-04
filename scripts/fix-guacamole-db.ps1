# PowerShell script to fix/reset Guacamole DB issues
# This script stops the Guacamole DB container, removes the corrupted volume, and restarts it

Write-Host "🔧 Guacamole DB Fix Script" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    docker ps | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 1: Stopping infrastructure services..." -ForegroundColor Yellow
docker-compose -f docker/docker-compose.infrastructure.yml down

Write-Host ""
Write-Host "Step 2: Removing Guacamole DB volume (this will delete all Guacamole data)..." -ForegroundColor Yellow
$volumeName = "ai-ctf-challenge-platform-copy_guacamole_db_new_data"
try {
    docker volume rm $volumeName 2>&1 | Out-Null
    Write-Host "✅ Volume removed successfully" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Volume may not exist (this is okay)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Step 3: Starting infrastructure services..." -ForegroundColor Yellow
docker-compose -f docker/docker-compose.infrastructure.yml up -d

Write-Host ""
Write-Host "⏳ Waiting for Guacamole DB to initialize (this may take 60-90 seconds)..." -ForegroundColor Yellow
Write-Host "   Please wait while MySQL initializes the database schema..." -ForegroundColor Gray

$maxAttempts = 30
$attempt = 0
$ready = $false

while ($attempt -lt $maxAttempts -and -not $ready) {
    Start-Sleep -Seconds 3
    $attempt++
    
    try {
        $logs = docker logs ctf-guacamole-db-new 2>&1 | Select-Object -Last 5
        if ($logs -match "ready for connections" -or $logs -match "MySQL init process done") {
            $ready = $true
            Write-Host "✅ Guacamole DB is ready!" -ForegroundColor Green
        } else {
            Write-Host "   Attempt $attempt/$maxAttempts - Still initializing..." -ForegroundColor Gray
        }
    } catch {
        Write-Host "   Attempt $attempt/$maxAttempts - Container starting..." -ForegroundColor Gray
    }
}

if (-not $ready) {
    Write-Host ""
    Write-Host "⚠️  Guacamole DB may still be initializing. Check logs with:" -ForegroundColor Yellow
    Write-Host "   docker logs ctf-guacamole-db-new" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "✅ Guacamole DB fix complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Restart CTF automation service: npm run ctf:restart" -ForegroundColor White
    Write-Host "2. Check health: npm run health" -ForegroundColor White
}

Write-Host ""
Write-Host "Current container status:" -ForegroundColor Cyan
docker ps --filter "name=guacamole" --format "table {{.Names}}\t{{.Status}}"


