# syntax=docker.io/docker/dockerfile:1

# build stage: includes resources necessary for installing dependencies
FROM node:20.16.0-bookworm AS build-stage

WORKDIR /opt/cartesi/dapp
COPY . .
RUN npm ci && npm run build

# runtime stage: produces final image that will be executed
FROM --platform=linux/riscv64 cartesi/node:20.16.0-jammy-slim

ARG MACHINE_EMULATOR_TOOLS_VERSION=0.14.1
ADD https://github.com/cartesi/machine-emulator-tools/releases/download/v${MACHINE_EMULATOR_TOOLS_VERSION}/machine-emulator-tools-v${MACHINE_EMULATOR_TOOLS_VERSION}.deb /
RUN dpkg -i /machine-emulator-tools-v${MACHINE_EMULATOR_TOOLS_VERSION}.deb \
  && rm /machine-emulator-tools-v${MACHINE_EMULATOR_TOOLS_VERSION}.deb

LABEL io.cartesi.rollups.sdk_version=0.9.0
LABEL io.cartesi.rollups.ram_size=128Mi

ARG DEBIAN_FRONTEND=noninteractive
RUN <<EOF
set -e
apt-get update
apt-get install -y --no-install-recommends \
  busybox-static=1:1.30.1-7ubuntu3
rm -rf /var/lib/apt/lists/* /var/log/* /var/cache/*
useradd --create-home --user-group dapp
EOF

ENV PATH="/opt/cartesi/bin:${PATH}"

WORKDIR /opt/cartesi/dapp

# Copy built dist files
COPY --from=build-stage /opt/cartesi/dapp/dist .

# Copy sql.js WASM file
COPY --from=build-stage /opt/cartesi/dapp/node_modules/sql.js/dist/sql-wasm.wasm .

# ROLLUP_HTTP_SERVER_URL is set by Cartesi runtime at startup
# Default for local development only - will be overridden in production
ENV ROLLUP_HTTP_SERVER_URL="http://127.0.0.1:5004"

# Input decryption key for device attestation privacy
# This key is baked into the machine image - Cartesi can decrypt encrypted inputs
# Keypair: Private (here) -> Public (attestor LCORE_INPUT_PUBLIC_KEY)
# IMPORTANT: Generate your own keypair before deploying! See /SECURITY-ACCESS-CONTROL.md
ENV LCORE_INPUT_PRIVATE_KEY=REPLACE_WITH_YOUR_BASE64_PRIVATE_KEY

ENTRYPOINT ["rollup-init"]
CMD ["node", "lcore-main.js"]
