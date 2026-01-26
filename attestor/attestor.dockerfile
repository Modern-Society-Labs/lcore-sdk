# ============= Build Stage =============
FROM node:20 AS builder

# Install git for any git-based dependencies
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy package files first for better layer caching
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./

# Create placeholder files to satisfy npm install
RUN mkdir -p src/scripts && \
    echo '' > src/scripts/prepare.sh && \
    echo 'console.log("TMP")' > src/index.ts

# Install all dependencies (including dev for building)
RUN npm ci

# Copy source code
COPY . .

# Build production bundle
RUN npm run build:prod

# Download ZK files (these go into node_modules/@reclaimprotocol/zk-symmetric-crypto/)
RUN npm run download:zk-files

# Prune to production dependencies only
RUN npm prune --production

# ============= Production Stage =============
FROM node:20-slim

WORKDIR /app

# Copy only production artifacts from builder
COPY --from=builder /build/lib ./lib
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/package.json ./

# Environment variables
ENV NODE_ENV=production
ENV LCORE_ENABLED=1

# NOTE: EigenCloud TEE requires root user for entrypoint injection
# The TEE provides isolation security instead of container user separation

# Labels for EigenCloud TEE
LABEL tee.launch_policy.log_redirect="always"
LABEL tee.launch_policy.monitoring_memory_allow="always"

EXPOSE 8001

CMD ["node", "lib/start-server.bundle.mjs"]
