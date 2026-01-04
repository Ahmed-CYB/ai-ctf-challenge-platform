FROM node:18-alpine

WORKDIR /app

# Install Docker CLI, docker-compose, and git
RUN apk add --no-cache docker-cli docker-compose git

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --only=production

# Copy application code
COPY . .

# Expose port
EXPOSE 4003

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4003/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start server
CMD ["node", "src/index.js"]

