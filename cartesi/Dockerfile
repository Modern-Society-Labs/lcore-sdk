# syntax=docker.io/docker/dockerfile:1
FROM node:20-bookworm AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src/ ./src/

# Build the application
RUN npm run build

# Production stage
FROM node:20-bookworm-slim AS production

WORKDIR /app

# Copy package files for production install
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production

# Copy built files
COPY --from=builder /app/dist ./dist

# Copy sql.js WASM file
COPY --from=builder /app/node_modules/sql.js/dist/sql-wasm.wasm ./dist/

# Set environment variables
ENV NODE_ENV=production
ENV ROLLUP_HTTP_SERVER_URL=http://127.0.0.1:5004

# Default: Run the L{CORE} SDK
# Override with --entrypoint or command for test-rollup-server
CMD ["node", "dist/lcore-main.js"]
