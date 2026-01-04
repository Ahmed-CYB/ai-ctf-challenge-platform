# Guacamole Setup and Start Script
# This script initializes and starts Apache Guacamole with MySQL database

Write-Host "`n=== GUACAMOLE SETUP & START ===" -ForegroundColor Cyan
Write-Host "This will start Apache Guacamole for remote CTF access`n" -ForegroundColor Yellow

# Step 1: Create networks if they don't exist
Write-Host "Step 1: Creating Docker networks..." -ForegroundColor Green
docker network create ctf-guacamole-network 2>$null
docker network create ctf-instances-network 2>$null
Write-Host "✓ Networks ready`n" -ForegroundColor Green

# Step 2: Start Guacamole services
Write-Host "Step 2: Starting Guacamole services..." -ForegroundColor Green
Write-Host "(This may take 1-2 minutes on first run)`n" -ForegroundColor Yellow

docker-compose -f docker-compose.guacamole.yml up -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✓ Guacamole services started successfully!" -ForegroundColor Green
    
    # Step 3: Wait for services to be healthy
    Write-Host "`nStep 3: Waiting for services to be ready..." -ForegroundColor Green
    Write-Host "Checking database..." -ForegroundColor Yellow
    
    $maxAttempts = 30
    $attempt = 0
    $dbReady = $false
    
    while (-not $dbReady -and $attempt -lt $maxAttempts) {
        $attempt++
        $dbStatus = docker inspect ctf-guacamole-db --format '{{.State.Health.Status}}' 2>$null
        
        if ($dbStatus -eq "healthy") {
            $dbReady = $true
            Write-Host "✓ Database is ready!" -ForegroundColor Green
        } else {
            Write-Host "  Attempt $attempt/$maxAttempts - Database status: $dbStatus" -ForegroundColor Yellow
            Start-Sleep -Seconds 2
        }
    }
    
    if (-not $dbReady) {
        Write-Host "⚠️  Database not ready after 60 seconds, but continuing..." -ForegroundColor Yellow
    }
    
    # Check Guacamole
    Start-Sleep -Seconds 5
    Write-Host "Checking Guacamole..." -ForegroundColor Yellow
    $guacStatus = docker inspect ctf-guacamole --format '{{.State.Status}}' 2>$null
    
    if ($guacStatus -eq "running") {
        Write-Host "✓ Guacamole is running!" -ForegroundColor Green
    }
    
    # Step 4: Display access information
    Write-Host "`n=== GUACAMOLE READY ===" -ForegroundColor Cyan
    Write-Host "`n🌐 Access Guacamole:" -ForegroundColor Green
    Write-Host "   URL: http://localhost/guacamole" -ForegroundColor White
    Write-Host "   Username: guacadmin" -ForegroundColor White
    Write-Host "   Password: guacadmin" -ForegroundColor White
    
    Write-Host "`n📚 What to do next:" -ForegroundColor Green
    Write-Host "   1. Open http://localhost/guacamole in your browser" -ForegroundColor White
    Write-Host "   2. Login with credentials above" -ForegroundColor White
    Write-Host "   3. CTF challenges will automatically create connections" -ForegroundColor White
    Write-Host "   4. You'll see them in the connection list after deployment" -ForegroundColor White
    
    Write-Host "`n🔧 Useful commands:" -ForegroundColor Green
    Write-Host "   Check status: docker-compose -f docker-compose.guacamole.yml ps" -ForegroundColor White
    Write-Host "   View logs:    docker-compose -f docker-compose.guacamole.yml logs -f" -ForegroundColor White
    Write-Host "   Stop:         docker-compose -f docker-compose.guacamole.yml down" -ForegroundColor White
    Write-Host "   Restart:      docker-compose -f docker-compose.guacamole.yml restart" -ForegroundColor White
    
    Write-Host "`n✅ Guacamole is running and ready for CTF deployments!" -ForegroundColor Green
    
} else {
    Write-Host "`n❌ Failed to start Guacamole services" -ForegroundColor Red
    Write-Host "Check logs with: docker-compose -f docker-compose.guacamole.yml logs" -ForegroundColor Yellow
    exit 1
}
