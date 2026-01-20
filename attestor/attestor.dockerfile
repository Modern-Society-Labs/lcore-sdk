FROM --platform=linux/amd64 node:20

# Create non-root user for security
# NOTE: TEE deployments may need to override this with --user root or via docker-compose
RUN useradd -r -s /bin/false -d /app attestor

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

# Prune production deps
RUN npm prune --production

# Set ownership of app directory to non-root user
RUN chown -R attestor:attestor /app

# Environment variables
ENV NODE_ENV=production
ENV LCORE_ENABLED=1

# Switch to non-root user
# NOTE: For TEE deployments requiring root access, override with:
# docker run --user root ... OR in docker-compose: user: root
USER attestor

# Labels for EigenCloud TEE
LABEL tee.launch_policy.log_redirect="always"
LABEL tee.launch_policy.monitoring_memory_allow="always"

EXPOSE 8001

CMD ["node", "lib/start-server.bundle.mjs"]
