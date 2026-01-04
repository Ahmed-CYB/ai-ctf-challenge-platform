# Fix existing attacker container for nmap and metadata issues
# Usage: .\fix-attacker-container.ps1 -ContainerName "ctf-corporate-data-breach-samba-server-exploitation-attacker"

param(
    [Parameter(Mandatory=$true)]
    [string]$ContainerName
)

Write-Host "🔧 Fixing attacker container: $ContainerName" -ForegroundColor Cyan

# 1. Fix nmap permissions (setcap - better than setuid)
Write-Host "`n1️⃣  Fixing nmap permissions..." -ForegroundColor Yellow
docker exec $ContainerName bash -c "setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap 2>/dev/null || true"
docker exec $ContainerName bash -c "setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/lib/nmap/nmap 2>/dev/null || true"
docker exec $ContainerName bash -c "setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan 2>/dev/null || true"
docker exec $ContainerName bash -c "setcap cap_net_raw,cap_net_admin+eip /usr/sbin/tcpdump 2>/dev/null || true"
Write-Host "⚠️  Note: Container must have CAP_NET_RAW capability at runtime." -ForegroundColor Yellow
Write-Host "   If nmap still fails, container needs to be recreated with cap_add in docker-compose.yml" -ForegroundColor Yellow
Write-Host "✅ Nmap capabilities set" -ForegroundColor Green

# 2. Disable systemd/journald metadata logging
Write-Host "`n2️⃣  Disabling systemd/journald metadata logging..." -ForegroundColor Yellow
docker exec $ContainerName bash -c "touch ~/.hushlogin"
docker exec $ContainerName bash -c "echo 'export SYSTEMD_LOG_LEVEL=err' >> ~/.bashrc"
docker exec $ContainerName bash -c "echo 'unset SYSTEMD_LOG_TARGET' >> ~/.bashrc"
Write-Host "✅ Metadata logging disabled" -ForegroundColor Green

# 3. Test nmap
Write-Host "`n3️⃣  Testing nmap..." -ForegroundColor Yellow
$nmapTest = docker exec $ContainerName nmap --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Nmap is working!" -ForegroundColor Green
    Write-Host $nmapTest
} else {
    Write-Host "⚠️  Nmap test failed" -ForegroundColor Red
    Write-Host $nmapTest
}

Write-Host "`n✅ Container fixes applied!" -ForegroundColor Green
Write-Host "Note: You may need to reconnect to see the metadata fix take effect." -ForegroundColor Yellow

