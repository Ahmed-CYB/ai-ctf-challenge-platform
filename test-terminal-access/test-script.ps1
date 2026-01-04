# Test script for terminal access alternatives (Windows PowerShell)
# This script helps test the different terminal access tools

Write-Host "🔧 Terminal Access Alternatives Test Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    docker info | Out-Null
} catch {
    Write-Host "❌ Docker is not running. Please start Docker first." -ForegroundColor Red
    exit 1
}

# Start test environment
Write-Host "🚀 Starting test environment..." -ForegroundColor Yellow
docker compose -f docker-compose.test.yml up -d

Write-Host ""
Write-Host "⏳ Waiting for containers to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check container status
Write-Host ""
Write-Host "📊 Container Status:" -ForegroundColor Cyan
docker compose -f docker-compose.test.yml ps

Write-Host ""
Write-Host "✅ Test environment is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "🌐 Access URLs:" -ForegroundColor Cyan
Write-Host "   - ttyd:        http://localhost:7681" -ForegroundColor White
Write-Host "   - Wetty:       http://localhost:3000" -ForegroundColor White
Write-Host "   - Shellinabox: https://localhost:4200 (accept SSL warning)" -ForegroundColor White
Write-Host ""
Write-Host "🔐 Test Attacker Container:" -ForegroundColor Cyan
Write-Host "   - IP: 172.30.1.3" -ForegroundColor White
Write-Host "   - SSH: ssh kali@172.30.1.3 (password: kali)" -ForegroundColor White
Write-Host ""
Write-Host "📝 To stop: docker compose -f docker-compose.test.yml down" -ForegroundColor Yellow
Write-Host ""

