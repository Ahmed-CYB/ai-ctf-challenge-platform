# Manual fix script for attacker container issues
# Usage: .\fix-container-manual.ps1 -ContainerName "ctf-corporate-data-breach-samba-misconfiguration-attacker"

param(
    [Parameter(Mandatory=$true)]
    [string]$ContainerName
)

Write-Host "🔧 Fixing container: $ContainerName" -ForegroundColor Cyan

# 1. Fix metadata logging
Write-Host "`n1️⃣  Fixing metadata logging..." -ForegroundColor Yellow
docker exec $ContainerName bash -c "touch /home/kali/.hushlogin && chown kali:kali /home/kali/.hushlogin"
docker exec $ContainerName bash -c "echo 'export SYSTEMD_LOG_LEVEL=err' >> /home/kali/.bashrc"
docker exec $ContainerName bash -c "echo 'unset SYSTEMD_LOG_TARGET' >> /home/kali/.bashrc"
Write-Host "✅ Metadata logging disabled (reconnect to see effect)" -ForegroundColor Green

# 2. Fix nmap capabilities
Write-Host "`n2️⃣  Setting nmap capabilities..." -ForegroundColor Yellow
docker exec $ContainerName bash -c "setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap 2>/dev/null || true"
docker exec $ContainerName bash -c "setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/lib/nmap/nmap 2>/dev/null || true"

# 3. Check container capabilities
Write-Host "`n3️⃣  Checking container runtime capabilities..." -ForegroundColor Yellow
$capAdd = docker inspect $ContainerName --format "{{.HostConfig.CapAdd}}"
if ($capAdd -eq "[]" -or $capAdd -match "null") {
    Write-Host "⚠️  WARNING: Container does NOT have CAP_NET_RAW at runtime!" -ForegroundColor Red
    Write-Host "   Nmap will NOT work until container is recreated with cap_add in docker-compose.yml" -ForegroundColor Red
    Write-Host "`n   Required docker-compose.yml change:" -ForegroundColor Yellow
    Write-Host "   attacker:" -ForegroundColor Cyan
    Write-Host "     cap_add:" -ForegroundColor Cyan
    Write-Host "       - NET_RAW" -ForegroundColor Cyan
    Write-Host "       - NET_ADMIN" -ForegroundColor Cyan
    Write-Host "`n   Then run: docker compose down && docker compose up --build" -ForegroundColor Yellow
} else {
    Write-Host "✅ Container has runtime capabilities: $capAdd" -ForegroundColor Green
}

# 4. Test nmap
Write-Host "`n4️⃣  Testing nmap..." -ForegroundColor Yellow
$nmapTest = docker exec $ContainerName bash -c "nmap --version 2>&1"
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Nmap is working!" -ForegroundColor Green
    Write-Host $nmapTest
} else {
    Write-Host "❌ Nmap failed (container needs cap_add)" -ForegroundColor Red
    Write-Host "   Try: sudo nmap ... (if sudo is available)" -ForegroundColor Yellow
    $sudoTest = docker exec $ContainerName bash -c "sudo nmap --version 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Sudo nmap works as workaround!" -ForegroundColor Green
    }
}

Write-Host "`n✅ Manual fixes applied!" -ForegroundColor Green
Write-Host "Note: Reconnect via SSH to see metadata fix take effect." -ForegroundColor Yellow

