# Attestor Core

Decentralized attestation infrastructure for trustless off-chain data verification, powered by TEE (Trusted Execution Environment).

Part of the [lcore-sdk](https://github.com/Modern-Society-Labs/lcore-sdk) ecosystem by [Modern Society Labs](https://github.com/Modern-Society-Labs).

## What is Attestor Core?

Attestor Core enables **trustless verification of off-chain data** for blockchain applications. It solves the fundamental problem that blockchains can only verify on-chain data, but real-world applications need external data (APIs, databases, services) without trusting a central authority.

The system works by having an attestor server run in a Trusted Execution Environment (TEE), which:
1. Observes TLS-encrypted traffic between a client and external servers
2. Verifies the authenticity of responses using TLS certificate chains
3. Generates zero-knowledge proofs to protect sensitive data
4. Signs verifiable claims that settle on Base L2

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ATTESTOR CORE ECOSYSTEM                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐ │
│  │   Client     │────▶│  Attestor Server │────▶│  External API    │ │
│  │   (SDK)      │◀────│  (TEE)           │◀────│  (TLS)           │ │
│  └──────────────┘     └────────┬─────────┘     └──────────────────┘ │
│                                │                                     │
│                                │ Signed Claims                       │
│                                ▼                                     │
│                    ┌──────────────────────┐                         │
│                    │   Cartesi Rollup     │  ◀── Deterministic      │
│                    │   (SQLite State)     │      state management   │
│                    └──────────────────────┘                         │
│                                │                                     │
│                                │ Settlement                          │
│                                ▼                                     │
│                    ┌──────────────────────┐                         │
│                    │      Base L2         │  ◀── Final settlement   │
│                    └──────────────────────┘                         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```bash
npm install @localecore/attestor-core
```

For NodeJS environments, download the ZK circuit files:

```bash
npm run download:zk-files
```

### Creating a Verified Claim

```typescript
import { createClaimOnAttestor } from '@localecore/attestor-core'

const result = await createClaimOnAttestor({
  name: 'http',
  params: {
    url: 'https://api.example.com/user/balance',
    method: 'GET',
    responseMatches: [
      { type: 'jsonPath', value: '$.balance' }
    ]
  },
  secretParams: {
    headers: {
      'Authorization': 'Bearer <your-token>'
    }
  },
  ownerPrivateKey: '0x...',
  client: { url: 'wss://attestor.example.com/ws' }
})

if (result.error) {
  console.error('Claim failed:', result.error)
} else {
  console.log('Claim:', result.claim)
  console.log('Signature:', result.signatures.claimSignature)
}
```

### Verifying a Claim

```typescript
import { assertValidClaimSignatures } from '@localecore/attestor-core'

// Throws if claim is invalid
await assertValidClaimSignatures(result)
```

## Project Structure

```
attestor-core/
├── src/
│   ├── server/           # Attestor server implementation
│   │   ├── handlers/     # RPC request handlers
│   │   ├── tunnels/      # TCP tunnel management
│   │   └── utils/        # Server utilities
│   ├── client/           # Client SDK for creating claims
│   │   ├── tunnels/      # Client-side tunnel implementations
│   │   └── utils/        # Client utilities
│   ├── providers/        # Data provider implementations
│   │   └── http/         # HTTP provider (generic API verification)
│   ├── external-rpc/     # Browser/JSC RPC client
│   ├── mechain/          # Mechain integration
│   ├── api/              # HTTP API routes
│   ├── db/               # Database layer
│   ├── proto/            # Protobuf generated types
│   ├── types/            # TypeScript type definitions
│   ├── utils/            # Shared utilities
│   └── scripts/          # Build and utility scripts
├── cartesi/              # Cartesi rollup integration
│   ├── src/
│   │   ├── handlers/     # Business logic handlers
│   │   └── utils/        # Cartesi utilities
│   └── ARCHITECTURE.md   # Detailed Cartesi documentation
├── docs/                 # Documentation
├── proto/                # Protobuf definitions
└── provider-schemas/     # Provider JSON schemas
```

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Quick start guide for SDK usage |
| [Project Structure](docs/project.md) | Codebase organization |
| [Providers](docs/provider.md) | Creating custom data providers |
| [Claim Creation](docs/claim-creation.md) | Deep dive into claim creation flow |
| [RPC Protocol](docs/rpc.md) | WebSocket RPC protocol details |
| [External RPC](docs/external-rpc.md) | Browser/mobile integration |
| [Zero-Knowledge Proofs](docs/zkp.md) | ZK proof usage for privacy |
| [Cartesi Integration](cartesi/ARCHITECTURE.md) | Rollup state management |
| [Running a Server](docs/run-server.md) | Deploying your own attestor |
| [Environment Variables](docs/env.md) | Configuration options |

## Development

### Prerequisites

- Node.js 18+
- npm
- Docker (for TEE deployment)

### Build Commands

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Build production bundle
npm run build:prod

# Build browser RPC client
npm run build:browser

# Start development server
npm run start

# Start production server
npm run start:prod
```

### Docker Deployment

```bash
# Build Docker image
npm run docker:build

# Get image hash (for TEE wallet derivation)
npm run docker:image-hash
```

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 8001) |
| `PRIVATE_KEY` | Wallet private key (traditional mode) |
| `MNEMONIC` | Wallet mnemonic (TEE mode) |
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_SERVICE_KEY` | Supabase service role key |
| `LOG_LEVEL` | Logging level (debug/info/warn/error) |
| `CHAIN_ID` | Blockchain chain ID |
| `LOCALE_PUBLIC_URL` | Public attestor URL |

See [.env.example](.env.example) for full configuration options.

## Related Projects

| Repository | Description |
|------------|-------------|
| [lcore-sdk](https://github.com/Modern-Society-Labs/lcore-sdk) | Combined SDK for verified data applications |
| [cartesi-sqlite-node](https://github.com/Modern-Society-Labs/cartesi-sqlite-node) | Deterministic rollup state management |

## Key Features

### TLS-Based Verification
The attestor observes TLS-encrypted traffic and verifies certificate chains to ensure data authenticity without decrypting sensitive content.

### Zero-Knowledge Proofs
Sensitive data can be redacted from proofs using ZK circuits, allowing verification without revealing private information like passwords or tokens.

### TEE Security
Running in a Trusted Execution Environment provides hardware-backed isolation, ensuring the attestor cannot be tampered with.

### Cartesi Rollup Integration
Verified claims are stored deterministically in a Cartesi rollup with SQLite-based state, enabling complex off-chain computation with on-chain verification.

### Base L2 Settlement
Final settlement happens on Base L2, providing fast, low-cost transactions with Ethereum security guarantees.

### Provider Architecture
Extensible provider system supports any HTTP API. Custom providers can be created for specific data sources.

## License

AGPL v3
