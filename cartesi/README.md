# Cartesi SQLite Node

A generalized framework for building Cartesi rollup applications with SQLite-based state persistence and multi-source data ingestion capabilities.

Part of the [lcore-sdk](https://github.com/Modern-Society-Labs/lcore-sdk) ecosystem by [Modern Society Labs](https://github.com/Modern-Society-Labs).

## Overview

This framework provides a robust foundation for Cartesi dApps that need to:

- **Ingest data** from multiple external sources (any API)
- **Store state** deterministically in SQLite (via sql.js WebAssembly)
- **Compute derived values** from aggregated data
- **Verify data authenticity** via cryptographic proofs
- **Query data** through inspect requests

## Quick Start

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Start development server
npm start

# Run tests
npm test
```

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for comprehensive documentation including:

- System architecture diagrams
- File structure and responsibilities
- Data flow patterns
- Step-by-step guide for adding new data sources
- API reference
- Best practices

## Project Structure

```
cartesi-sqlite-node/
├── src/
│   ├── index.ts              # Entry point & main loop
│   ├── router.ts             # Request routing & authorization
│   ├── db.ts                 # SQLite schema & CRUD operations
│   ├── config.ts             # Environment configuration
│   ├── schema.d.ts           # OpenAPI type definitions
│   ├── test-rollup-server.ts # Mock Cartesi server for local dev
│   │
│   ├── handlers/             # Business logic handlers
│   │   ├── index.ts          # Handler exports
│   │   ├── entity.ts         # Entity management
│   │   ├── data-source.ts    # External data sync
│   │   ├── computation.ts    # Derived calculations
│   │   ├── proof.ts          # Data verification
│   │   ├── approval.ts       # Approval workflow
│   │   └── stats.ts          # Statistics
│   │
│   └── utils/                # Cartesi utilities
│       ├── voucher-generator.ts  # L1 voucher helpers
│       ├── notice-batcher.ts     # Batch notices for performance
│       ├── db-maintenance.ts     # SQLite maintenance
│       └── domain-config.ts      # Configurable domain registry
│
├── package.json
├── tsconfig.json
├── Dockerfile                # Cartesi deployment image
├── ARCHITECTURE.md           # Comprehensive docs
└── README.md                 # This file
```

## Configuration

Configure via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ROLLUP_HTTP_SERVER_URL` | Cartesi rollup server URL | `http://127.0.0.1:5004` |
| `AUTHORIZED_SENDERS` | Comma-separated list of authorized addresses | Empty (dev mode) |
| `REQUIRE_APPROVAL` | Require approval for status changes | `false` |
| `MAX_RECORDS_PER_SYNC` | Max records per sync operation | `500` |
| `DEFAULT_THRESHOLD` | Default computation threshold | `1.25` |

## Adding a New Data Source

1. **Define Schema** - Add tables in `db.ts` `initDatabase()`
2. **Add Types** - Create interfaces for your data
3. **Implement CRUD** - Add database functions
4. **Create Handler** - Add handler file in `handlers/`
5. **Register Routes** - Add to `routeConfig` in `index.ts`

See the "Adding a New Data Source" section in ARCHITECTURE.md for a detailed walkthrough.

## Testing

### Unit Tests

```bash
npm test           # Run unit tests
npm run test:watch # Watch mode
```

### E2E Tests

E2E tests verify the full attestor-to-Cartesi flow using a mock rollup server.

```bash
# Build the project first
npm run build

# Terminal 1: Start the E2E test servers
npm run start:e2e-servers

# Terminal 2: Run E2E tests
npm run test:e2e
```

**E2E Test Coverage (116 tests):**

| Test File | Tests | Coverage |
|-----------|-------|----------|
| `e2e.coingecko.test.ts` | 16 | Real-world CoinGecko price attestation flow |
| `e2e.attestation.test.ts` | 18 | Attestation ingestion, queries, revocation |
| `e2e.discovery.test.ts` | 18 | Privacy-preserving bucket queries |
| `e2e.access-control.test.ts` | 22 | Grant/revoke data access |
| `e2e.schema.test.ts` | 20 | Provider schema lifecycle |
| `e2e.integration.test.ts` | 22 | Full DeFi attestation workflow |

## API

### Advance Requests (State Changes)

```json
{
  "action": "create_entity",
  "id": "entity-123",
  "entity_type": "user"
}
```

### Inspect Requests (Queries)

**JSON format:**
```json
{
  "type": "entity",
  "params": { "id": "entity-123" }
}
```

**Path format:**
```
entity/id/entity-123
```

## Related Projects

| Repository | Description |
|------------|-------------|
| [lcore-sdk](https://github.com/Modern-Society-Labs/lcore-sdk) | Combined SDK for verified data applications |
| [attestor-core](https://github.com/Modern-Society-Labs/attestor-core) | Decentralized attestation infrastructure |

## License

MIT
