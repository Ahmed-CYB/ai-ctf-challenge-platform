#!/bin/bash
# Bash Script to Setup Real PostgreSQL for CTF Platform
# Run this script with: bash setup-real-postgresql.sh

echo "🚀 Setting up Real PostgreSQL for CTF Platform"
echo ""

# Check if PostgreSQL is installed
echo "📋 Checking PostgreSQL installation..."
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL is not installed"
    echo "   Please install PostgreSQL:"
    echo "   - macOS: brew install postgresql@15"
    echo "   - Ubuntu/Debian: sudo apt-get install postgresql-15"
    echo "   - RHEL/CentOS: sudo yum install postgresql15"
    exit 1
fi

PG_VERSION=$(psql --version)
echo "✅ PostgreSQL found: $PG_VERSION"
echo ""

# Get PostgreSQL connection details
echo "📝 Enter PostgreSQL connection details:"
read -p "PostgreSQL Host (default: localhost): " PG_HOST
PG_HOST=${PG_HOST:-localhost}

read -p "PostgreSQL Port (default: 5432): " PG_PORT
PG_PORT=${PG_PORT:-5432}

read -p "PostgreSQL Superuser (default: postgres): " PG_SUPERUSER
PG_SUPERUSER=${PG_SUPERUSER:-postgres}

echo ""
echo "📝 Enter database details:"
read -p "Database Name (default: ctf_platform): " DB_NAME
DB_NAME=${DB_NAME:-ctf_platform}

read -p "Database User (default: ctf_user): " DB_USER
DB_USER=${DB_USER:-ctf_user}

read -sp "Database Password: " DB_PASSWORD
echo ""

echo ""
echo "🔧 Creating database and user..."

# Create SQL script
SQL_SCRIPT=$(cat <<EOF
-- Create database
SELECT 'CREATE DATABASE $DB_NAME' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec

-- Create user
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '$DB_USER') THEN
        CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
    END IF;
END
\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;

-- Connect to database and grant schema privileges
\c $DB_NAME
GRANT ALL ON SCHEMA public TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DB_USER;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO $DB_USER;
EOF
)

# Execute SQL
echo "   Executing SQL commands..."
export PGPASSWORD="$DB_PASSWORD"
echo "$SQL_SCRIPT" | psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" -f - > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Database and user created successfully!"
else
    echo "❌ Failed to create database/user. Please check PostgreSQL is running and credentials are correct."
    unset PGPASSWORD
    exit 1
fi

# Create .env file
echo ""
echo "📝 Creating .env file..."

ENV_CONTENT="
# PostgreSQL Database Configuration (Real Installation)
DB_HOST=$PG_HOST
DB_PORT=$PG_PORT
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD

# Alternative: Use DATABASE_URL (for backend)
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${PG_HOST}:${PG_PORT}/${DB_NAME}

# Keep other services in Docker (optional)
GUACAMOLE_DB_PASSWORD=guacamole_password_123
GUACAMOLE_ROOT_PASSWORD=root_password_123
"

ENV_FILE=".env"
echo "$ENV_CONTENT" > "$ENV_FILE"

echo "✅ .env file created at: $ENV_FILE"
echo ""

# Test connection
echo "🔍 Testing database connection..."
TEST_QUERY="SELECT version();"
export PGPASSWORD="$DB_PASSWORD"
RESULT=$(psql -h "$PG_HOST" -p "$PG_PORT" -U "$DB_USER" -d "$DB_NAME" -c "$TEST_QUERY" 2>&1)

if [ $? -eq 0 ]; then
    echo "✅ Database connection successful!"
    echo ""
    echo "📋 Next steps:"
    echo "   1. Run migrations: npm run db:migrate"
    echo "   2. Start your application"
    echo "   3. Verify connection in application logs"
else
    echo "❌ Database connection failed!"
    echo "   Error: $RESULT"
fi

unset PGPASSWORD
echo ""
echo "✅ Setup complete!"


