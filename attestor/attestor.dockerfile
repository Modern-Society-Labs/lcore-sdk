FROM node:20

# install git
RUN apt update -y && apt upgrade -y && apt install git -y

# ============= Build Attestor =============
COPY ./package.json /app/
COPY ./package-lock.json /app/
COPY ./tsconfig.json /app/
COPY ./tsconfig.build.json /app/
RUN mkdir -p /app/src/scripts
RUN echo '' > /app/src/scripts/prepare.sh
RUN echo 'console.log("TMP")' > /app/src/index.ts

WORKDIR /app

RUN npm i

COPY ./ /app

RUN npm run build:prod
RUN npm run download:zk-files

# ============= Build L{CORE} Cartesi Layer =============
WORKDIR /app/cartesi

# Install and build Cartesi layer
RUN npm ci
RUN npm run build

# Copy sql.js WASM file
RUN cp node_modules/sql.js/dist/sql-wasm.wasm dist/

# ============= Finalize =============
WORKDIR /app

# Prune attestor production deps (but keep cartesi deps)
RUN npm prune --production

# Create startup script that runs both services
RUN echo '#!/bin/bash\n\
# Start L{CORE} rollup server in background\n\
cd /app/cartesi && node dist/rollup-server.js &\n\
\n\
# Wait for rollup server to be ready\n\
sleep 2\n\
\n\
# Start L{CORE} main in background\n\
ROLLUP_HTTP_SERVER_URL=http://127.0.0.1:5004 node dist/lcore-main.js &\n\
\n\
# Wait for lcore to be ready\n\
sleep 1\n\
\n\
# Start attestor (foreground)\n\
cd /app && exec node lib/start-server.bundle.mjs\n\
' > /app/start.sh && chmod +x /app/start.sh

# Environment variables
ENV LCORE_ENABLED=1
ENV LCORE_ROLLUP_URL=http://127.0.0.1:5004

CMD ["/app/start.sh"]
EXPOSE 8001 5004
