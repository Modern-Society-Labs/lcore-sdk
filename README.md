# L{CORE} SDK

Template SDK combining [attestor-core](https://github.com/Modern-Society-Labs/attestor-core) with [cartesi-sqlite-node](https://github.com/Modern-Society-Labs/cartesi-sqlite-node) for building verified data applications.

Part of the L{CORE} ecosystem by [Modern Society Labs](https://github.com/Modern-Society-Labs).

## Overview

L{CORE} SDK provides a complete foundation for building applications that require:
- **Verified off-chain data** via TEE attestation
- **Deterministic state management** via Cartesi rollups
- **SQLite persistence** for complex queries and data relationships

This is a **generic template** - extend it with your own handlers and database schema for your specific use case.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Application                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────┐    ┌─────────────────────────────┐ │
│  │      Attestor       │    │         Cartesi             │ │
│  │                     │    │                             │ │
│  │  - TLS Verification │    │  - SQLite State             │ │
│  │  - ZK Proofs        │───▶│  - Deterministic Execution  │ │
│  │  - TEE Signing      │    │  - Entity Management        │ │
│  │                     │    │  - Data Sync                │ │
│  └─────────────────────┘    └─────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Project Structure

```
lcore-sdk/
├── attestor/                 # Attestation infrastructure
│   ├── src/
│   │   ├── server/           # Attestor server
│   │   ├── providers/        # Data providers (HTTP, etc.)
│   │   └── utils/            # Utilities
│   └── package.json
├── cartesi/                  # Rollup framework
│   ├── src/
│   │   ├── index.ts          # Entry point
│   │   ├── db.ts             # SQLite schema
│   │   ├── router.ts         # Request routing
│   │   ├── handlers/         # Generic handlers
│   │   │   ├── entity.ts     # Entity management
│   │   │   ├── data-source.ts# External data sync
│   │   │   ├── computation.ts# Derived calculations
│   │   │   ├── proof.ts      # Data verification
│   │   │   ├── approval.ts   # Approval workflow
│   │   │   └── stats.ts      # Statistics
│   │   └── utils/            # Utilities
│   └── package.json
└── README.md
```

## Quick Start

### 1. Clone the Template

```bash
git clone https://github.com/Modern-Society-Labs/lcore-sdk.git my-app
cd my-app
```

### 2. Install Dependencies

```bash
# Attestor
cd attestor && npm install

# Cartesi
cd ../cartesi && npm install
```

### 3. Run Development Environment

```bash
# Start attestor (in one terminal)
cd attestor && npm run start

# Start Cartesi rollup (in another terminal)
cd cartesi && npx @cartesi/cli run
```

## Extending the Template

### Adding Custom Handlers

Create new handlers in `cartesi/src/handlers/`:

```typescript
// cartesi/src/handlers/my-feature.ts
import { RouteHandler } from '../router'

export const myFeatureHandler: RouteHandler = async (db, payload) => {
  // Your logic here
  return { success: true }
}
```

Register in `cartesi/src/handlers/index.ts`:

```typescript
export { myFeatureHandler } from './my-feature'
```

### Extending the Database Schema

Modify `cartesi/src/db.ts` to add your tables:

```typescript
db.run(`
  CREATE TABLE IF NOT EXISTS my_table (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
  )
`)
```

### Adding Custom Providers

Create providers in `attestor/src/providers/` for new data sources.

## Configuration

### Attestor Environment

Copy `attestor/.env.example` to `attestor/.env`:

```env
PORT=8001
PRIVATE_KEY=your_wallet_private_key
LOG_LEVEL=info
```

### Cartesi Environment

```env
ROLLUP_HTTP_SERVER_URL=http://localhost:5004
```

## Generic Handlers

| Handler | Purpose |
|---------|---------|
| `entity` | CRUD operations for entities |
| `data-source` | Sync external data into rollup |
| `computation` | Derived/calculated values |
| `proof` | Data verification and attestation |
| `approval` | Multi-party approval workflows |
| `stats` | Aggregate statistics |

## Documentation

Full documentation available on GitBook (coming soon).

## Related Projects

| Repository | Description |
|------------|-------------|
| [attestor-core](https://github.com/Modern-Society-Labs/attestor-core) | Standalone attestation infrastructure |
| [cartesi-sqlite-node](https://github.com/Modern-Society-Labs/cartesi-sqlite-node) | Standalone Cartesi framework |
| [locale-city-chain](https://github.com/Locale-Network/locale-city-chain) | Production implementation example |

## License

AGPL v3
