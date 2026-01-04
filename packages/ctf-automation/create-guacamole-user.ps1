# Create Guacamole User Script
# This script creates a user with login always enabled
# Usage: .\create-guacamole-user.ps1 -Username "player1" -Password "Pass123!" -IsAdmin $false

param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [bool]$IsAdmin = $false
)

Write-Host "`n=== Creating Guacamole User ===" -ForegroundColor Cyan
Write-Host "Username: $Username" -ForegroundColor Yellow
Write-Host "Admin: $IsAdmin" -ForegroundColor $(if($IsAdmin){"Red"}else{"Green"})

# 1. Create entity
Write-Host "`nStep 1: Creating entity..." -ForegroundColor Yellow
docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "INSERT INTO guacamole_entity (name, type) VALUES ('$Username', 'USER')" 2>&1 | Out-Null

# 2. Get entity ID
$entityId = docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "SELECT entity_id FROM guacamole_entity WHERE name='$Username'" 2>&1 | Select-String -Pattern "^\d+$"
$entityId = [int]$entityId.ToString().Trim()

if (-not $entityId) {
    Write-Host "❌ Failed to create entity" -ForegroundColor Red
    exit 1
}

Write-Host "Entity ID: $entityId" -ForegroundColor Green

# 3. Generate password hash with cryptographically secure random salt
Write-Host "Step 2: Generating secure password hash..." -ForegroundColor Yellow
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$salt = New-Object byte[] 32
$rng.GetBytes($salt)
$saltHex = -join ($salt | ForEach-Object { $_.ToString("x2") })

# Hash = SHA256(password + hex(salt))
$combined = [System.Text.Encoding]::UTF8.GetBytes($Password + $saltHex)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hash = $sha256.ComputeHash($combined)
$hashHex = -join ($hash | ForEach-Object { $_.ToString("x2") })

Write-Host "Salt (hex): $($saltHex.Substring(0,16))..." -ForegroundColor DarkGray

# 4. Create user with login ENABLED (disabled = 0)
Write-Host "Step 3: Creating user record (login enabled)..." -ForegroundColor Yellow
docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, disabled) VALUES ($entityId, UNHEX('$hashHex'), UNHEX('$saltHex'), NOW(), 0)" 2>&1 | Out-Null

# 5. Grant admin permissions if requested
if ($IsAdmin) {
    Write-Host "Step 4: Granting admin permissions..." -ForegroundColor Yellow
    docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES ($entityId, 'ADMINISTER'), ($entityId, 'CREATE_CONNECTION'), ($entityId, 'CREATE_CONNECTION_GROUP'), ($entityId, 'CREATE_SHARING_PROFILE'), ($entityId, 'CREATE_USER'), ($entityId, 'CREATE_USER_GROUP')" 2>&1 | Out-Null
}

# 6. Verify
$result = docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "SELECT e.name, u.user_id, u.disabled FROM guacamole_entity e JOIN guacamole_user u ON e.entity_id = u.entity_id WHERE e.name='$Username'" 2>&1 | Select-String -Pattern $Username

Write-Host ""
Write-Host "========================================"
Write-Host "User Created Successfully!"
Write-Host "========================================"
Write-Host ""
Write-Host "Username:  $Username"
Write-Host "Password:  $Password"
Write-Host "Entity ID: $entityId"
Write-Host "Login:     Enabled"
Write-Host "Admin:     $(if($IsAdmin){'Yes'}else{'No'})"
Write-Host ""
Write-Host "Login at: http://localhost:8080/guacamole"
Write-Host ""
