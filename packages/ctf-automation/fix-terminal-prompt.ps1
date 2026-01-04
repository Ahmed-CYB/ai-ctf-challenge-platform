# Fix terminal prompts in all running attacker containers
Write-Host "🔧 Fixing terminal prompts in all attacker containers..." -ForegroundColor Cyan

# Get all running attacker containers
$containers = docker ps --filter "name=ctf-.*-attacker" --format "{{.Names}}"

if ($containers.Count -eq 0) {
    Write-Host "⚠️  No attacker containers found running" -ForegroundColor Yellow
    exit 0
}

foreach ($container in $containers) {
    Write-Host "  📝 Fixing $container..." -ForegroundColor Gray
    
    # Add clean PS1 prompt to .bashrc
    docker exec $container bash -c "echo 'export PS1=`"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ `"' >> /root/.bashrc"
    docker exec $container bash -c "echo 'export TERM=xterm-256color' >> /root/.bashrc"
    
    Write-Host "  ✅ Fixed $container" -ForegroundColor Green
}

Write-Host "`n✅ All containers fixed!" -ForegroundColor Green
Write-Host "📌 Note: Close and reopen your Guacamole SSH connection to see the clean prompt" -ForegroundColor Yellow
