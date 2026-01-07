# PowerShell Script to Migrate MySQL to Isolated PostgreSQL Testing Server
# This script sets up the migration on your isolated testing server

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "MySQL to PostgreSQL Migration - Isolated Testing Server" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if isolated PostgreSQL is running
Write-Host "Checking if isolated PostgreSQL server is running..." -ForegroundColor Yellow
$postgresRunning = docker ps --filter "name=isolated-postgres-server" --format "{{.Names}}"

if (-not $postgresRunning) {
    Write-Host "⚠️  Isolated PostgreSQL server is not running!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Starting isolated PostgreSQL server..." -ForegroundColor Yellow
    docker-compose -f docker-compose.isolated-postgres.yml up -d
    
    Write-Host "Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    
    # Check again
    $postgresRunning = docker ps --filter "name=isolated-postgres-server" --format "{{.Names}}"
    if (-not $postgresRunning) {
        Write-Host "✗ Failed to start PostgreSQL server!" -ForegroundColor Red
        exit 1
    }
}

Write-Host "✓ Isolated PostgreSQL server is running" -ForegroundColor Green
Write-Host ""

# PostgreSQL connection details for isolated server
$PG_HOST = "localhost"
$PG_PORT = "5435"
$PG_USER = "gpadmin"
$PG_PASSWORD = "gpadmin123"
$PG_DATABASE = "guacamole_db"

# MySQL connection details (from your current setup)
$MYSQL_HOST = "localhost"
$MYSQL_PORT = "3307"
$MYSQL_USER = "guacamole_user"
$MYSQL_PASSWORD = "guacamole_password_123"
$MYSQL_DATABASE = "guacamole_db"

Write-Host "Migration Configuration:" -ForegroundColor Cyan
Write-Host "  Source: MySQL $MYSQL_HOST`:$MYSQL_PORT/$MYSQL_DATABASE" -ForegroundColor White
Write-Host "  Target: PostgreSQL $PG_HOST`:$PG_PORT/$PG_DATABASE" -ForegroundColor White
Write-Host ""

# Check if MySQL is accessible
Write-Host "Checking MySQL connection..." -ForegroundColor Yellow
$mysqlCheck = docker ps --filter "name=ctf-guacamole-db-new" --format "{{.Names}}"
if (-not $mysqlCheck) {
    Write-Host "⚠️  MySQL container not found. Make sure it's running." -ForegroundColor Yellow
    Write-Host "   Container name should be: ctf-guacamole-db-new" -ForegroundColor Yellow
} else {
    Write-Host "✓ MySQL container is running" -ForegroundColor Green
}
Write-Host ""

# Step 1: Create guacamole_db database in isolated PostgreSQL
Write-Host "Step 1: Creating guacamole_db database..." -ForegroundColor Cyan
$createDbScript = @"
-- Create database if not exists
SELECT 'CREATE DATABASE guacamole_db'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'guacamole_db')\gexec
"@

try {
    $env:PGPASSWORD = $PG_PASSWORD
    $createDbScript | psql -h $PG_HOST -p $PG_PORT -U $PG_USER -d postgres 2>&1 | Out-Null
    
    # Try to connect to verify
    $testConn = "SELECT 1;" | psql -h $PG_HOST -p $PG_PORT -U $PG_USER -d $PG_DATABASE 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Database guacamole_db created/verified" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Database might already exist or connection issue" -ForegroundColor Yellow
    }
} catch {
    Write-Host "⚠️  Note: You may need to create the database manually in pgAdmin" -ForegroundColor Yellow
    Write-Host "   Database name: guacamole_db" -ForegroundColor White
}
Write-Host ""

# Step 2: Create schema
Write-Host "Step 2: Creating PostgreSQL schema..." -ForegroundColor Cyan
if (Test-Path "database\guacamole-postgresql-schema.sql") {
    Write-Host "   Loading schema from database\guacamole-postgresql-schema.sql..." -ForegroundColor Yellow
    try {
        $env:PGPASSWORD = $PG_PASSWORD
        Get-Content "database\guacamole-postgresql-schema.sql" | psql -h $PG_HOST -p $PG_PORT -U $PG_USER -d $PG_DATABASE 2>&1 | Out-Null
        Write-Host "✓ Schema created successfully" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Schema creation had issues. Check manually in pgAdmin." -ForegroundColor Yellow
    }
} else {
    Write-Host "✗ Schema file not found: database\guacamole-postgresql-schema.sql" -ForegroundColor Red
    Write-Host "   Please create the schema manually in pgAdmin" -ForegroundColor Yellow
}
Write-Host ""

# Step 3: Run migration script
Write-Host "Step 3: Running data migration..." -ForegroundColor Cyan
Write-Host ""

# Check if Python migration script exists
if (Test-Path "migrate_mysql_to_postgresql.py") {
    Write-Host "   Running Python migration script..." -ForegroundColor Yellow
    Write-Host ""
    
    # Build migration command
    $migrationCmd = @"
python migrate_mysql_to_postgresql.py `
    --mysql-host $MYSQL_HOST `
    --mysql-port $MYSQL_PORT `
    --mysql-user $MYSQL_USER `
    --mysql-password $MYSQL_PASSWORD `
    --mysql-database $MYSQL_DATABASE `
    --pg-host $PG_HOST `
    --pg-port $PG_PORT `
    --pg-user $PG_USER `
    --pg-password $PG_PASSWORD `
    --pg-database $PG_DATABASE
"@
    
    Write-Host "   Command:" -ForegroundColor Gray
    Write-Host $migrationCmd -ForegroundColor Gray
    Write-Host ""
    
    $response = Read-Host "   Run migration now? (yes/no)"
    if ($response -eq "yes") {
        Invoke-Expression $migrationCmd
    } else {
        Write-Host "   Migration skipped. Run manually when ready." -ForegroundColor Yellow
    }
} else {
    Write-Host "✗ Migration script not found: migrate_mysql_to_postgresql.py" -ForegroundColor Red
    Write-Host "   Please run the migration manually" -ForegroundColor Yellow
}
Write-Host ""

# Step 4: Instructions
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Access pgAdmin:" -ForegroundColor Yellow
Write-Host "   URL: http://localhost:5051" -ForegroundColor White
Write-Host "   Email: admin@test.com" -ForegroundColor White
Write-Host "   Password: admin123" -ForegroundColor White
Write-Host ""
Write-Host "2. Connect to PostgreSQL server:" -ForegroundColor Yellow
Write-Host "   Host: isolated-postgres (or localhost)" -ForegroundColor White
Write-Host "   Port: 5432" -ForegroundColor White
Write-Host "   Database: guacamole_db" -ForegroundColor White
Write-Host "   Username: gpadmin" -ForegroundColor White
Write-Host "   Password: gpadmin123" -ForegroundColor White
Write-Host ""
Write-Host "3. Verify migration:" -ForegroundColor Yellow
Write-Host "   - Check that all 23 tables exist" -ForegroundColor White
Write-Host "   - Verify data in tables" -ForegroundColor White
Write-Host "   - Check row counts match MySQL" -ForegroundColor White
Write-Host ""
Write-Host "4. Test Guacamole connection:" -ForegroundColor Yellow
Write-Host "   - Update Guacamole config to use PostgreSQL" -ForegroundColor White
Write-Host "   - Test login and connections" -ForegroundColor White
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Migration setup complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

