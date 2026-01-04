FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy application code
COPY . .

# Expose port
EXPOSE 4000

# Build application
RUN npm run build

# Serve with a simple HTTP server
RUN npm install -g serve

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4000 || exit 1

# Start server
CMD ["serve", "-s", "build", "-l", "4000"]

