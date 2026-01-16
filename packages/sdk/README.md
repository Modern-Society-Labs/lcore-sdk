# @localecore/lcore-sdk

TypeScript SDK for L{CORE} - Privacy-preserving attestation layer for off-chain data.

## Installation

```bash
npm install @localecore/lcore-sdk
```

## Quick Start

```typescript
import { LCore } from '@localecore/lcore-sdk'

// Initialize client
const lcore = new LCore({
  attestorUrl: 'http://localhost:8001',
  cartesiUrl: 'http://localhost:10000',
  dappAddress: '0xYourDappAddress',
})

// Create an attestation
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
  console.log('Extracted:', result.extractedData)
}

// Query attested data
const query = await lcore.query({
  type: 'attestation',
  params: { claimId: result.claimId }
})
```

## Self-Hosting

To run your own L{CORE} infrastructure, see the [Self-Hosting Guide](../../docs/SELF-HOSTING.md).

## API Reference

### LCore

Main client class for interacting with L{CORE}.

#### Constructor

```typescript
new LCore(config: LCoreConfig)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `attestorUrl` | `string` | URL of the L{CORE} attestor |
| `cartesiUrl` | `string` | URL of the Cartesi node |
| `dappAddress` | `string` | Cartesi DApp address |
| `timeout?` | `number` | Request timeout in ms (default: 30000) |

#### Methods

##### `attest(request: AttestRequest): Promise<AttestResult>`

Create an attestation for off-chain data.

```typescript
const result = await lcore.attest({
  provider: 'http',
  params: {
    url: 'https://api.example.com/sensor/123',
    method: 'GET',
    responseRedactions: [{ jsonPath: 'value' }]
  },
  secretParams: {
    headers: { 'Authorization': 'Bearer token' }
  }
})
```

##### `query<T>(request: QueryRequest): Promise<QueryResult<T>>`

Query data from the Cartesi node.

```typescript
const result = await lcore.query({
  type: 'attestation',
  params: { claimId: '...' }
})
```

##### `health(): Promise<HealthStatus>`

Check health of attestor and Cartesi node.

```typescript
const status = await lcore.health()
// { status: 'ok', version: '5.0.0', lcoreEnabled: true, cartesiConnected: true }
```

### Environment Variables

Create a client from environment variables:

```typescript
import { createLCoreFromEnv } from '@localecore/lcore-sdk'

// Uses LCORE_ATTESTOR_URL, LCORE_CARTESI_URL, LCORE_DAPP_ADDRESS
const lcore = createLCoreFromEnv()
```

## IoT Integration

L{CORE} works with any HTTP-accessible data source, including IoT platforms:

```typescript
// AWS IoT Device Shadow
const result = await lcore.attest({
  provider: 'http',
  params: {
    url: 'https://data-ats.iot.us-east-1.amazonaws.com/things/{{deviceId}}/shadow',
    paramValues: { deviceId: 'sensor-001' },
    responseRedactions: [
      { jsonPath: 'state.reported.temperature' }
    ]
  },
  secretParams: {
    headers: { 'Authorization': 'AWS4-HMAC-SHA256 ...' }
  }
})
```

See [IoT Patterns](../../docs/iot-providers.md) for more examples.

## License

MIT
