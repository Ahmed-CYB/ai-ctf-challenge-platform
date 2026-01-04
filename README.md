# AI CTF Challenge Platform

A comprehensive, AI-powered platform for creating, deploying, and managing Capture The Flag (CTF) cybersecurity challenges.

## 🏗️ Architecture

This project uses a **monorepo structure** with multiple services:

```
ctf-platform/
├── packages/
│   ├── frontend/          # React + TypeScript frontend (Port 4000)
│   ├── backend/           # Express.js API server (Port 4002)
│   ├── ctf-automation/    # AI-powered challenge generator (Port 4003)
│   └── shared/            # Shared utilities, types, and config
├── docker/                # Docker Compose configurations
├── scripts/               # Build and deployment scripts
├── database/              # Database schema and migrations
└── tests/                 # Integration and E2E tests
```

## 🚀 Quick Start

### Prerequisites

- **Node.js** 18+ and npm 9+
- **Docker** and Docker Compose
- **PostgreSQL** 15+ (or use Docker)
- **Git** (for challenge repository management)

### Option 1: Docker Compose (Recommended)

Start all services with one command:

```bash
# Copy environment file
cp .env.example .env

# Edit .env with your API keys and configuration
# Required: ANTHROPIC_API_KEY, OPENAI_API_KEY, GITHUB_TOKEN

# Start all services
npm run dev:docker
```

This starts:
- ✅ PostgreSQL database (Port 5433)
- ✅ Backend API (Port 4002)
- ✅ Frontend (Port 4000)
- ✅ CTF Automation Service (Port 4003)
- ✅ Guacamole Server (Port 8081)

Access the platform at: **http://localhost:4000**

### Option 2: Local Development

```bash
# Install all dependencies
npm run install:all

# Set up database
npm run db:migrate

# Start all services
npm run dev
```

Or start services individually:
```bash
npm run dev:frontend   # Port 4000
npm run dev:backend    # Port 4002
npm run dev:ctf        # Port 4003
```

## 📋 Port Configuration

### New Services (Current)
- **Frontend**: `4000` (original: 3000)
- **Backend API**: `4002` (original: 3002)
- **CTF Automation**: `4003` (original: 3003)
- **PostgreSQL**: `5433` (original: 5432)
- **Guacamole**: `8081` (original: 8080)
- **Guacamole MySQL**: `3307` (original: 3306)

### Original Services (Backup)
The original services remain unchanged and can run alongside the new ones:
- Frontend: `3000`
- Backend: `3002`
- CTF Automation: `3003`
- PostgreSQL: `5432`
- Guacamole: `8080`
- MySQL: `3306`

## 🛠️ Available Scripts

### Development
```bash
npm run dev              # Start all services concurrently
npm run dev:docker       # Start all services in Docker
npm run dev:frontend     # Start frontend only
npm run dev:backend      # Start backend only
npm run dev:ctf          # Start CTF automation only
```

### Database
```bash
npm run db:migrate       # Run database migrations
npm run db:seed          # Seed database with sample data
npm run db:reset         # Reset database (⚠️ deletes all data)
```

### Health & Monitoring
```bash
npm run health           # Check health of all services
```

### Build
```bash
npm run build            # Build all packages
npm run build:frontend   # Build frontend only
npm run build:backend    # Build backend only
```

## 🔧 Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```env
# Required API Keys
ANTHROPIC_API_KEY=your-anthropic-key
OPENAI_API_KEY=your-openai-key
GITHUB_TOKEN=your-github-token

# Database
DATABASE_URL=postgresql://ctf_user:password@localhost:5433/ctf_platform

# JWT Secret (change in production!)
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
```

See `.env.example` for all available options.

## 📦 Project Structure

### Packages

- **`@ctf-platform/frontend`**: React application with TypeScript
- **`@ctf-platform/backend`**: Express.js REST API
- **`@ctf-platform/ctf-automation`**: AI-powered challenge generator
- **`@ctf-platform/shared`**: Shared utilities, types, config, logging

### Key Features

✅ **Monorepo Structure** - Unified dependency management
✅ **Docker Compose** - One-command development environment
✅ **Database Migrations** - Version-controlled schema changes
✅ **Health Checks** - Service status monitoring
✅ **Centralized Logging** - Winston-based logging system
✅ **Type-Safe Config** - Zod-validated configuration
✅ **Error Handling** - Centralized error management

## 🧪 Testing

```bash
npm test                 # Run all tests
npm test --workspace=@ctf-platform/backend
```

## 📊 Health Monitoring

Check service health:
```bash
npm run health
```

Or visit:
- Frontend: http://localhost:4000
- Backend: http://localhost:4002/api/health
- CTF Service: http://localhost:4003/health
- Guacamole: http://localhost:8081

## 🐳 Docker Services

### Start Services
```bash
npm run dev:docker
```

### Stop Services
```bash
npm run dev:docker:down
```

### View Logs
```bash
npm run dev:docker:logs
```

### Individual Service Logs
```bash
docker-compose -f docker/docker-compose.dev.yml logs -f backend-new
docker-compose -f docker/docker-compose.dev.yml logs -f frontend-new
```

## 🔄 Database Migrations

Migrations are automatically tracked and applied:

```bash
# Apply pending migrations
npm run db:migrate

# Reset database (⚠️ deletes all data)
npm run db:reset
```

Migrations are stored in `database/migrations/` and tracked in the `schema_migrations` table.

## 🏥 Health Checks

All services include health check endpoints:

- **Backend**: `GET /api/health`
- **CTF Automation**: `GET /health`
- **Frontend**: Root endpoint
- **Guacamole**: Root endpoint

Use `npm run health` to check all services at once.

## 📝 Development Workflow

1. **Start services**: `npm run dev:docker` or `npm run dev`
2. **Make changes**: Edit code in `packages/*`
3. **Test changes**: Services auto-reload (or restart Docker)
4. **Run migrations**: `npm run db:migrate` (if schema changed)
5. **Check health**: `npm run health`

## 🚨 Troubleshooting

### Port Already in Use
```bash
# Kill process on port
Get-NetTCPConnection -LocalPort 4002 | Select-Object -ExpandProperty OwningProcess | Stop-Process -Force
```

### Database Connection Issues
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check database URL in .env
# Should be: postgresql://ctf_user:password@localhost:5433/ctf_platform
```

### Services Not Starting
```bash
# Check logs
npm run dev:docker:logs

# Check health
npm run health

# Verify environment variables
cat .env
```

## 📚 Documentation

- [Architecture Improvements](./ARCHITECTURE_IMPROVEMENTS.md) - Detailed architecture recommendations
- [Project Analysis](./PROJECT_ANALYSIS_AND_FIXES.md) - Project flow and fixes
- [Runtime Errors Fixed](./RUNTIME_ERRORS_FIXED.md) - Error fixes applied

## 🔐 Security Notes

- ⚠️ Change `JWT_SECRET` in production
- ⚠️ Use strong database passwords
- ⚠️ Keep API keys secure (never commit to git)
- ⚠️ Enable SSL in production

## 🤝 Contributing

1. Create a feature branch
2. Make your changes
3. Run tests: `npm test`
4. Check health: `npm run health`
5. Submit a pull request

## 📄 License

MIT

---

**Note**: Original services (ports 3000, 3002, 3003, etc.) are kept as backup and can run alongside the new services.
