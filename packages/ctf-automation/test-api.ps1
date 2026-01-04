# Test Guacamole API endpoints

Write-Host "`n=== Testing Guacamole User Creation API ===" -ForegroundColor Cyan

# Test 1: Create User
Write-Host "`n[1/2] Creating test user..." -ForegroundColor Yellow

$createUserBody = @{
    username = "testplayer"
    password = "TestPass2025!"
    email = "player@ctf.local"
    fullName = "Test Player"
} | ConvertTo-Json

try {
    $userResponse = Invoke-RestMethod -Uri "http://localhost:3003/api/guacamole/create-user" `
        -Method POST `
        -ContentType "application/json" `
        -Body $createUserBody

    Write-Host "✅ User created successfully!" -ForegroundColor Green
    Write-Host "Generated Username: $($userResponse.user.username)" -ForegroundColor Cyan
    Write-Host "Entity ID: $($userResponse.user.entityId)" -ForegroundColor Yellow
    Write-Host "User ID: $($userResponse.user.userId)" -ForegroundColor Yellow
    Write-Host "`nLogin URL: $($userResponse.loginInfo.url)" -ForegroundColor Cyan
    Write-Host "Login Username: $($userResponse.loginInfo.username)" -ForegroundColor Cyan
    Write-Host "Login Password: $($userResponse.loginInfo.password)" -ForegroundColor Cyan

    $guacUsername = $userResponse.user.username
    $guacPassword = $userResponse.loginInfo.password

    # Test 2: Add Connection
    Write-Host "`n[2/2] Adding SSH connection to user..." -ForegroundColor Yellow

    $addConnectionBody = @{
        username = $guacUsername
        connectionName = "CTF-Attacker-SSH"
        protocol = "ssh"
        hostname = "172.24.193.3"
        port = "22"
        connectionUsername = "root"
        connectionPassword = "kali"
        parameters = @{
            "enable-sftp" = "true"
            "sftp-root-directory" = "/root"
        }
    } | ConvertTo-Json

    $connectionResponse = Invoke-RestMethod -Uri "http://localhost:3003/api/guacamole/add-connection" `
        -Method POST `
        -ContentType "application/json" `
        -Body $addConnectionBody

    Write-Host "✅ Connection added successfully!" -ForegroundColor Green
    Write-Host "Connection ID: $($connectionResponse.connection.connectionId)" -ForegroundColor Cyan
    Write-Host "Connection Name: $($connectionResponse.connection.connectionName)" -ForegroundColor Yellow
    Write-Host "Protocol: $($connectionResponse.connection.protocol)" -ForegroundColor Yellow
    Write-Host "Hostname: $($connectionResponse.connection.hostname):$($connectionResponse.connection.port)" -ForegroundColor Yellow

    Write-Host "`n=== Test Complete ===" -ForegroundColor Green
    Write-Host "`n📝 Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Open browser to: $($userResponse.loginInfo.url)" -ForegroundColor White
    Write-Host "2. Login with username: $guacUsername" -ForegroundColor White
    Write-Host "3. Password: $guacPassword" -ForegroundColor White
    Write-Host "4. Click on 'CTF-Attacker-SSH' connection to access the attacker machine" -ForegroundColor White

} catch {
    Write-Host "Error occurred:" $_.Exception.Message -ForegroundColor Red
    if ($_.ErrorDetails) {
        Write-Host "Details:" $_.ErrorDetails.Message -ForegroundColor Red
    }
}
