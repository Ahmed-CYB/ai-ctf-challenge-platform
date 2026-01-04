# Challenge Creation Verification Script
# Run this while creating a challenge to verify Guacamole setup

param(
    [string]$ChallengeName = "",
    [string]$SessionId = ""
)

Write-Host "🔍 Challenge Creation Verification Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to run MySQL query
function Invoke-MySQLQuery {
    param([string]$Query)
    $result = docker exec ctf-guacamole-db-new mysql -u guacamole_user -pguacamole_password_123 guacamole_db -sN -e $Query 2>$null
    return $result
}

# Wait for challenge creation
if (-not $ChallengeName) {
    Write-Host "⏳ Waiting for challenge creation..." -ForegroundColor Yellow
    Write-Host "   (Run this script with -ChallengeName 'challenge-name' to check specific challenge)" -ForegroundColor Gray
    Write-Host ""
}

# Get latest user
Write-Host "📋 Checking Latest Guacamole User..." -ForegroundColor Green
$latestUser = Invoke-MySQLQuery "SELECT name FROM guacamole_entity WHERE type='USER' AND name LIKE 'ctf_user_%' ORDER BY entity_id DESC LIMIT 1;"

if ($latestUser) {
    Write-Host "   ✅ Latest user: $latestUser" -ForegroundColor Green
    
    # Check user details
    Write-Host ""
    Write-Host "👤 User Details:" -ForegroundColor Green
    $userDetails = Invoke-MySQLQuery "SELECT e.name, u.disabled, u.password_date, LENGTH(HEX(u.password_hash)) DIV 2 as hash_len, LENGTH(HEX(u.password_salt)) DIV 2 as salt_len FROM guacamole_user u JOIN guacamole_entity e ON u.entity_id = e.entity_id WHERE e.name = '$latestUser';"
    
    if ($userDetails) {
        $parts = $userDetails -split "`t"
        Write-Host "   Username: $($parts[0])" -ForegroundColor White
        Write-Host "   Disabled: $($parts[1]) $(if ($parts[1] -eq '0') { '(✅ Enabled)' } else { '(❌ Disabled)' })" -ForegroundColor $(if ($parts[1] -eq '0') { 'Green' } else { 'Red' })
        Write-Host "   Password Date: $($parts[2])" -ForegroundColor White
        Write-Host "   Hash Length: $($parts[3]) bytes $(if ($parts[3] -eq '32') { '(✅ Correct)' } else { '(❌ Wrong)' })" -ForegroundColor $(if ($parts[3] -eq '32') { 'Green' } else { 'Red' })
        Write-Host "   Salt Length: $($parts[4]) bytes $(if ($parts[4] -eq '32') { '(✅ Correct)' } else { '(❌ Wrong)' })" -ForegroundColor $(if ($parts[4] -eq '32') { 'Green' } else { 'Red' })
    }
} else {
    Write-Host "   ⚠️  No session users found" -ForegroundColor Yellow
}

# Get latest connection
Write-Host ""
Write-Host "🔗 Checking Latest Guacamole Connection..." -ForegroundColor Green
$latestConnection = Invoke-MySQLQuery "SELECT connection_id, connection_name FROM guacamole_connection ORDER BY connection_id DESC LIMIT 1;"

if ($latestConnection) {
    $connParts = $latestConnection -split "`t"
    $connId = $connParts[0]
    $connName = $connParts[1]
    
    Write-Host "   ✅ Latest connection: $connName (ID: $connId)" -ForegroundColor Green
    
    # Check connection parameters
    Write-Host ""
    Write-Host "📡 Connection Parameters:" -ForegroundColor Green
    $params = Invoke-MySQLQuery "SELECT parameter_name, parameter_value FROM guacamole_connection_parameter WHERE connection_id = $connId ORDER BY parameter_name;"
    
    if ($params) {
        $hostname = ""
        $port = ""
        $username = ""
        $password = ""
        
        $params -split "`n" | ForEach-Object {
            if ($_) {
                $paramParts = $_ -split "`t"
                $paramName = $paramParts[0]
                $paramValue = $paramParts[1]
                
                Write-Host "   $paramName : $paramValue" -ForegroundColor White
                
                if ($paramName -eq "hostname") {
                    $hostname = $paramValue
                    if ($hostname -match "^172\.22\.") {
                        Write-Host "      ✅ Correct: Using ctf-instances-network IP" -ForegroundColor Green
                    } elseif ($hostname -match "^172\.23\.") {
                        Write-Host "      ❌ WRONG: Using challenge network IP (Guacamole cannot reach this!)" -ForegroundColor Red
                    }
                }
                if ($paramName -eq "port") { $port = $paramValue }
                if ($paramName -eq "username") { $username = $paramValue }
                if ($paramName -eq "password") { $password = $paramValue }
            }
        }
        
        Write-Host ""
        Write-Host "🎯 Connection Summary:" -ForegroundColor Cyan
        Write-Host "   Target: ${username}@${hostname}:${port}" -ForegroundColor White
    }
    
    # Check permissions
    Write-Host ""
    Write-Host "🔐 Connection Permissions:" -ForegroundColor Green
    if ($latestUser) {
        $entityId = Invoke-MySQLQuery "SELECT entity_id FROM guacamole_entity WHERE name = '$latestUser';"
        if ($entityId) {
            $permission = Invoke-MySQLQuery "SELECT permission FROM guacamole_connection_permission WHERE entity_id = $entityId AND connection_id = $connId;"
            if ($permission) {
                Write-Host "   ✅ User has $permission permission" -ForegroundColor Green
            } else {
                Write-Host "   ❌ User does NOT have permission!" -ForegroundColor Red
            }
        }
    }
} else {
    Write-Host "   ⚠️  No connections found" -ForegroundColor Yellow
}

# Check network connectivity
Write-Host ""
Write-Host "🌐 Network Verification:" -ForegroundColor Green

if ($ChallengeName) {
    $attackerContainer = "ctf-${ChallengeName}-attacker"
    Write-Host "   Checking container: $attackerContainer" -ForegroundColor White
    
    $containerExists = docker ps --filter "name=$attackerContainer" --format "{{.Names}}"
    if ($containerExists) {
        Write-Host "   ✅ Container exists" -ForegroundColor Green
        
        # Check networks
        $networks = docker inspect $attackerContainer --format "{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{println}}{{end}}" 2>$null
        if ($networks) {
            Write-Host "   Networks:" -ForegroundColor White
            $networks -split "`n" | ForEach-Object {
                if ($_) {
                    $netName = $_.Trim()
                    $netIP = docker inspect $attackerContainer --format "{{index .NetworkSettings.Networks `"$netName`"}}.IPAddress" 2>$null
                    Write-Host "      - $netName : $netIP" -ForegroundColor White
                    
                    if ($netName -eq "ctf-instances-network") {
                        if ($netIP -match "^172\.22\.") {
                            Write-Host "         ✅ Correct IP on ctf-instances-network" -ForegroundColor Green
                        } else {
                            Write-Host "         ❌ Wrong IP range!" -ForegroundColor Red
                        }
                    }
                }
            }
        }
    } else {
        Write-Host "   ⚠️  Container not found" -ForegroundColor Yellow
    }
}

# Summary
Write-Host ""
Write-Host "📊 Verification Summary:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan

$allGood = $true

if ($latestUser) {
    Write-Host "✅ User created" -ForegroundColor Green
} else {
    Write-Host "❌ User not created" -ForegroundColor Red
    $allGood = $false
}

if ($latestConnection) {
    Write-Host "✅ Connection created" -ForegroundColor Green
} else {
    Write-Host "❌ Connection not created" -ForegroundColor Red
    $allGood = $false
}

Write-Host ""
if ($allGood) {
    Write-Host "✅ All checks passed! Challenge should work correctly." -ForegroundColor Green
} else {
    Write-Host "⚠️  Some issues detected. Please review above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "💡 To test login:" -ForegroundColor Cyan
Write-Host "   1. Go to: http://localhost:8081/guacamole/" -ForegroundColor White
Write-Host "   2. Username: $latestUser" -ForegroundColor White
Write-Host "   3. Password: (check server logs for generated password)" -ForegroundColor White

