# Recreate Guacadmin Account
# Run this if the admin account is accidentally deleted

Write-Host "`n=== Recreating Guacadmin Admin Account ===" -ForegroundColor Cyan

# 1. Delete existing guacadmin if it exists (clean slate)
Write-Host "`nStep 1: Cleaning up existing account..." -ForegroundColor Yellow
docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "DELETE FROM guacamole_user WHERE entity_id = 1" 2>$null
docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "DELETE FROM guacamole_entity WHERE entity_id = 1" 2>$null

# 2. Create guacadmin entity
Write-Host "Step 2: Creating guacadmin entity..." -ForegroundColor Yellow
docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "INSERT INTO guacamole_entity (entity_id, name, type) VALUES (1, 'guacadmin', 'USER')" 2>&1 | Out-Null

# 3. Create guacadmin user with default password "guacadmin"
Write-Host "Step 3: Creating guacadmin user with password..." -ForegroundColor Yellow
$sql = @"
INSERT INTO guacamole_user (user_id, entity_id, password_hash, password_salt, password_date, disabled) 
VALUES (
    1,
    1,
    UNHEX('ca458a7bc1a6481989598b5895e48d21ef7037c3239e282144d7ba556fbc0500'),
    UNHEX('fe24adc5e11e2b25288d1704abe67a79e342ecc26064ce69c5b3177795a9d06a'),
    NOW(),
    0
)
"@

docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e $sql 2>&1 | Out-Null

# 4. Grant all admin permissions
Write-Host "Step 4: Granting admin permissions..." -ForegroundColor Yellow
$permissions = @(
    "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES (1, 'ADMINISTER')",
    "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES (1, 'CREATE_CONNECTION')",
    "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES (1, 'CREATE_CONNECTION_GROUP')",
    "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES (1, 'CREATE_SHARING_PROFILE')",
    "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES (1, 'CREATE_USER')",
    "INSERT INTO guacamole_system_permission (entity_id, permission) VALUES (1, 'CREATE_USER_GROUP')"
)

foreach ($perm in $permissions) {
    docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e $perm 2>&1 | Out-Null
}

# 5. Verify
Write-Host "`nStep 5: Verifying account..." -ForegroundColor Yellow
docker exec ctf-guacamole-db mysql -u guacamole_user -pguacamole_pass guacamole_db -e "SELECT e.name, u.user_id, u.disabled FROM guacamole_entity e JOIN guacamole_user u ON e.entity_id = u.entity_id WHERE e.name = 'guacadmin'" 2>&1 | Select-String -Pattern "guacadmin"

Write-Host "`n✅ Guacadmin account recreated successfully!" -ForegroundColor Green
Write-Host "`nLogin Credentials:" -ForegroundColor Cyan
Write-Host "  URL:      http://localhost:8080/guacamole" -ForegroundColor White
Write-Host "  Username: guacadmin" -ForegroundColor Yellow
Write-Host "  Password: guacadmin" -ForegroundColor Yellow
Write-Host ""
