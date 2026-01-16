# L{CORE} SDK

Privacy-preserving attestation layer for off-chain data, combining TEE-based verification with Cartesi rollups for deterministic storage.

By [Modern Society Labs](https://github.com/Modern-Society-Labs).

## What is L{CORE}?

L{CORE} enables **trustless verification of off-chain data** for blockchain applications. It solves the fundamental problem that blockchains can only verify on-chain data, but real-world applications need external data (APIs, IoT sensors, databases) without trusting a central authority.

**Key Features:**

- **zkTLS Attestation** - Cryptographic proofs of HTTP responses
- **Privacy Buckets** - Discretize sensitive data (e.g., "income > $50k" instead of exact amount)
- **Deterministic Storage** - SQLite on Cartesi for verifiable queries
- **No Oracles** - Direct verification, no trusted third parties

## Quick Start

### Option 1: Use the SDK (Recommended)

```bash
npm install @localecore/lcore-sdk
```

```typescript
import { LCore } from '@localecore/lcore-sdk'

const lcore = new LCore({
  attestorUrl: 'http://localhost:8001',
  cartesiUrl: 'http://localhost:10000',
  dappAddress: '0xYourDappAddress',
})

// Attest data from any HTTP source
const result = await lcore.attest({
  provider: 'http',
  params: {
    url: 'https://api.example.com/data',
    responseRedactions: [{ jsonPath: 'temperature' }]
  }
})

// Query attested data
const data = await lcore.query({
  type: 'attestation',
  params: { claimId: result.claimId }
})
```

### Option 2: Self-Host with Docker

```bash
# Clone and configure
git clone https://github.com/Modern-Society-Labs/lcore-sdk.git
cd lcore-sdk
cp .env.example .env
# Edit .env with your values

# Start services
docker-compose up -d

# Verify
curl http://localhost:8001/healthcheck
```

See [Self-Hosting Guide](docs/SELF-HOSTING.md) for full instructions.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Your Application                              │
│                                                                         │
│   ┌───────────────────┐     ┌───────────────────┐     ┌──────────────┐ │
│   │  lcore-sdk        │     │  Attestor         │     │ Cartesi Node │ │
│   │  (npm package)    │     │  (TEE/zkTLS)      │     │ (SQLite)     │ │
│   │                   │     │                   │     │              │ │
│   │  lcore.attest()   │────▶│  Verify & Sign    │────▶│  Store &     │ │
│   │  lcore.query()    │◀────│                   │◀────│  Query       │ │
│   └───────────────────┘     └───────────────────┘     └──────────────┘ │
│                                      │                       │         │
│                                      └───────────────────────┘         │
│                                               │                        │
│                                               ▼                        │
│                                    ┌───────────────────┐               │
│                                    │  Arbitrum Sepolia │               │
│                                    │  (Settlement)     │               │
│                                    └───────────────────┘               │
└─────────────────────────────────────────────────────────────────────────┘
```

## Documentation

| Guide | Description |
|-------|-------------|
| [SDK Usage](docs/SDK-USAGE.md) | TypeScript SDK reference |
| [Self-Hosting](docs/SELF-HOSTING.md) | Run your own infrastructure |
| [Configuration](docs/CONFIGURATION.md) | Environment variables |
| [IoT Patterns](memory-bank/iot-providers.md) | AWS IoT, Azure, GCP examples |

## Project Structure

```
lcore-sdk/
├── packages/
│   └── sdk/                  # @localecore/lcore-sdk npm package
├── attestor/                 # TEE-based attestation server
│   ├── src/
│   │   ├── api/              # REST API routes
│   │   ├── lcore/            # Cartesi integration
│   │   └── providers/        # Data providers
│   └── docs/                 # Attestor documentation
├── cartesi/                  # Deterministic compute layer
│   ├── src/
│   │   ├── handlers/         # L{CORE} handlers (privacy, buckets)
│   │   └── db.ts             # SQLite schema
│   └── Dockerfile            # RISC-V build
├── docs/                     # User documentation
├── memory-bank/              # Architecture decisions & roadmap
├── docker-compose.yml        # Self-hosting template
└── .env.example              # Configuration template
```

## Use Cases

- **IoT Data Attestation** - Verify sensor readings without exposing raw data
- **Financial Verification** - Prove income brackets without revealing exact amounts
- **Identity Claims** - Attest attributes without full disclosure
- **API Data Proofs** - Verifiable snapshots of external API responses

## Roadmap

See [roadmap-pending.md](memory-bank/roadmap-pending.md) for current status.

**Completed:**

- [x] TEE attestation infrastructure
- [x] Cartesi privacy layer (buckets, encryption)
- [x] HTTP provider for API attestation
- [x] TypeScript SDK
- [x] Docker Compose self-hosting

**Phase 2 (Planned):**

- [ ] Device SDK HTTP client (direct IoT attestation)
- [ ] EigenCloud deployment automation
- [ ] Additional provider types

## Contributing

Contributions welcome! Please read the existing code patterns before submitting PRs.

## License

AGPL v3

## Related

- [Reclaim Protocol](https://reclaimprotocol.org) - zkTLS attestation (upstream)
- [Cartesi](https://cartesi.io) - Deterministic rollups
- [Arbitrum](https://arbitrum.io) - L2 settlement
