#!/bin/bash

# Test script for terminal access alternatives
# This script helps test the different terminal access tools

echo "🔧 Terminal Access Alternatives Test Script"
echo "=========================================="
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Start test environment
echo "🚀 Starting test environment..."
docker compose -f docker-compose.test.yml up -d

echo ""
echo "⏳ Waiting for containers to be ready..."
sleep 5

# Check container status
echo ""
echo "📊 Container Status:"
docker compose -f docker-compose.test.yml ps

echo ""
echo "✅ Test environment is ready!"
echo ""
echo "🌐 Access URLs:"
echo "   - ttyd:        http://localhost:7681"
echo "   - Wetty:       http://localhost:3000"
echo "   - Shellinabox: https://localhost:4200 (accept SSL warning)"
echo ""
echo "🔐 Test Attacker Container:"
echo "   - IP: 172.30.1.3"
echo "   - SSH: ssh kali@172.30.1.3 (password: kali)"
echo ""
echo "📝 To stop: docker compose -f docker-compose.test.yml down"
echo ""

