# PowerShell Script to Setup Real PostgreSQL for CTF Platform
# Run this script as Administrator

Write-Host "🚀 Setting up Real PostgreSQL for CTF Platform" -ForegroundColor Green
Write-Host ""

# Check if PostgreSQL is installed
Write-Host "📋 Checking PostgreSQL installation..." -ForegroundColor Yellow
$pgVersion = & psql --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ PostgreSQL is not installed or not in PATH" -ForegroundColor Red
    Write-Host "   Please install PostgreSQL from: https://www.postgresql.org/download/windows/" -ForegroundColor Yellow
    Write-Host "   Or use: choco install postgresql15" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ PostgreSQL found: $pgVersion" -ForegroundColor Green
Write-Host ""

# Get PostgreSQL connection details
Write-Host "📝 Enter PostgreSQL connection details:" -ForegroundColor Yellow
$pgHost = Read-Host "PostgreSQL Host (default: localhost)"
if ([string]::IsNullOrWhiteSpace($pgHost)) { $pgHost = "localhost" }

$pgPort = Read-Host "PostgreSQL Port (default: 5432)"
if ([string]::IsNullOrWhiteSpace($pgPort)) { $pgPort = "5432" }

$pgSuperUser = Read-Host "PostgreSQL Superuser (default: postgres)"
if ([string]::IsNullOrWhiteSpace($pgSuperUser)) { $pgSuperUser = "postgres" }

Write-Host ""
Write-Host "📝 Enter database details:" -ForegroundColor Yellow
$dbName = Read-Host "Database Name (default: ctf_platform)"
if ([string]::IsNullOrWhiteSpace($dbName)) { $dbName = "ctf_platform" }

$dbUser = Read-Host "Database User (default: ctf_user)"
if ([string]::IsNullOrWhiteSpace($dbUser)) { $dbUser = "ctf_user" }

$dbPassword = Read-Host "Database Password" -AsSecureString
$dbPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPassword)
)

Write-Host ""
Write-Host "🔧 Creating database and user..." -ForegroundColor Yellow

# Create SQL script
$sqlScript = @"
-- Create database
SELECT 'CREATE DATABASE $dbName' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$dbName')\gexec

-- Create user
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '$dbUser') THEN
        CREATE USER $dbUser WITH PASSWORD '$dbPasswordPlain';
    END IF;
END
\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $dbName TO $dbUser;

-- Connect to database and grant schema privileges
\c $dbName
GRANT ALL ON SCHEMA public TO $dbUser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $dbUser;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $dbUser;
"@

# Write SQL to temp file
$tempSqlFile = [System.IO.Path]::GetTempFileName() + ".sql"
$sqlScript | Out-File -FilePath $tempSqlFile -Encoding UTF8

# Execute SQL
Write-Host "   Executing SQL commands..." -ForegroundColor Gray
$env:PGPASSWORD = $dbPasswordPlain
& psql -h $pgHost -p $pgPort -U $pgSuperUser -f $tempSqlFile 2>&1 | Out-Null

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Database and user created successfully!" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to create database/user. Please check PostgreSQL is running and credentials are correct." -ForegroundColor Red
    Remove-Item $tempSqlFile -ErrorAction SilentlyContinue
    exit 1
}

# Clean up
Remove-Item $tempSqlFile -ErrorAction SilentlyContinue
$env:PGPASSWORD = $null

# Create .env file
Write-Host ""
Write-Host "📝 Creating .env file..." -ForegroundColor Yellow

$envContent = @"
# PostgreSQL Database Configuration (Real Installation)
DB_HOST=$pgHost
DB_PORT=$pgPort
DB_NAME=$dbName
DB_USER=$dbUser
DB_PASSWORD=$dbPasswordPlain

# Alternative: Use DATABASE_URL (for backend)
DATABASE_URL=postgresql://${dbUser}:${dbPasswordPlain}@${pgHost}:${pgPort}/${dbName}

# Keep other services in Docker (optional)
GUACAMOLE_DB_PASSWORD=guacamole_password_123
GUACAMOLE_ROOT_PASSWORD=root_password_123
"@

$envFile = Join-Path $PSScriptRoot ".env"
$envContent | Out-File -FilePath $envFile -Encoding UTF8

Write-Host "✅ .env file created at: $envFile" -ForegroundColor Green
Write-Host ""

# Test connection
Write-Host "🔍 Testing database connection..." -ForegroundColor Yellow
$testQuery = "SELECT version();"
$env:PGPASSWORD = $dbPasswordPlain
$result = & psql -h $pgHost -p $pgPort -U $dbUser -d $dbName -c $testQuery 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Database connection successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Next steps:" -ForegroundColor Yellow
    Write-Host "   1. Run migrations: npm run db:migrate" -ForegroundColor White
    Write-Host "   2. Start your application" -ForegroundColor White
    Write-Host "   3. Verify connection in application logs" -ForegroundColor White
} else {
    Write-Host "❌ Database connection failed!" -ForegroundColor Red
    Write-Host "   Error: $result" -ForegroundColor Red
}

$env:PGPASSWORD = $null
Write-Host ""
Write-Host "✅ Setup complete!" -ForegroundColor Green


