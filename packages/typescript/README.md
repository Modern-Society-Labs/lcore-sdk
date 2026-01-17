# @localecore/lcore-sdk

TypeScript SDK for L{CORE} - Privacy-preserving attestation layer for off-chain data.

## Installation

```bash
npm install @localecore/lcore-sdk
```

## Quick Start

```typescript
import { LCore } from '@localecore/lcore-sdk'

const lcore = new LCore({
  attestorUrl: 'http://localhost:8001',
  cartesiUrl: 'http://localhost:10000',
  dappAddress: '0xYourDappAddress',
})

const result = await lcore.attest({
  provider: 'http',
  params: {
    url: 'https://api.example.com/data',
    responseRedactions: [
      { jsonPath: 'temperature' },
      { jsonPath: 'humidity' }
    ]
  }
})

if (result.success) {
  console.log('Claim ID:', result.claimId)
}
```

## API Reference

### Constructor

```typescript
new LCore(config: LCoreConfig)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `attestorUrl` | `string` | URL of the L{CORE} attestor |
| `cartesiUrl` | `string` | URL of the Cartesi node |
| `dappAddress` | `string` | Cartesi DApp address |

### Methods

#### `attest(request): Promise<AttestResult>`

Create an attestation for off-chain data.

#### `query(request): Promise<QueryResult>`

Query data from the Cartesi node.

#### `health(): Promise<HealthStatus>`

Check health of attestor and Cartesi node.

## License

MIT
