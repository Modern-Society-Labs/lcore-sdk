# Attestor Core

Decentralized attestation infrastructure for trustless off-chain data verification, powered by TEE (Trusted Execution Environment).

Part of the [lcore-sdk](https://github.com/Modern-Society-Labs/lcore-sdk) ecosystem.

## Overview

Attestor Core enables trustless verification of off-chain data for blockchain applications. It runs in a Trusted Execution Environment (TEE) and:

1. Observes TLS-encrypted traffic between a client and external servers
2. Verifies the authenticity of responses using TLS certificate chains
3. Generates zero-knowledge proofs to protect sensitive data
4. Signs verifiable claims that settle on Arbitrum

## Quick Start

```bash
npm install
npm run start
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 8001) |
| `PRIVATE_KEY` | Wallet private key |
| `MNEMONIC` | Wallet mnemonic (TEE mode) |

## Docker

```bash
docker build -f attestor.dockerfile -t lcore-attestor .
docker run -p 8001:8001 lcore-attestor
```

## License

AGPL v3
