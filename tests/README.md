# L{CORE} SDK Tests

Test suite for the L{CORE} attestor device submission endpoint and DID utilities.

## Test Structure

```
tests/
└── attestor/
    ├── did.test.ts      # Unit tests for DID utilities (21 tests)
    └── device.test.ts   # E2E tests for device endpoint (22 tests)
```

## Prerequisites

- Node.js v20+ (with `--experimental-strip-types` support)
- Dependencies installed: `cd attestor && npm install`

## Running Tests

From the repository root:

```bash
# Run all tests (43 total)
npm test

# Run DID unit tests only
npm run test:did

# Run device endpoint E2E tests only
npm run test:device
```

## Test Categories

### DID Utilities (`did.test.ts`)

Unit tests for cryptographic utilities in `attestor/src/api/services/did.ts`:

| Function | Tests | Description |
|----------|-------|-------------|
| `parseDIDKey` | 7 | Parse `did:key:z...` to secp256k1 public key |
| `publicKeyToDIDKey` | 3 | Generate `did:key` from public key bytes |
| `createJWS` | 3 | Create JWS compact serialization |
| `verifyJWS` | 7 | Verify JWS signature against payload |
| Round-trip | 1 | Full sign-verify cycle |

These tests run without any external dependencies.

### Device Endpoint E2E (`device.test.ts`)

End-to-end tests for `POST /api/device/submit`:

| Category | Tests | Description |
|----------|-------|-------------|
| Valid submissions | 2 | Correctly signed device data |
| Missing fields | 4 | Required field validation |
| Invalid DID format | 4 | DID format validation |
| Signature verification | 3 | Cryptographic signature checks |
| Timestamp validation | 4 | Timestamp window enforcement |
| Payload validation | 3 | Payload type validation |
| Request body | 2 | JSON parsing validation |

**Important:** E2E tests require the attestor server to be running.

## Starting the Attestor Server

### Option 1: Direct (Development)

```bash
cd attestor

# Set required environment variables
export MNEMONIC="your twelve word mnemonic phrase here"
export LCORE_ENABLED=1
export LCORE_RPC_URL="https://arb-sepolia.g.alchemy.com/v2/YOUR_KEY"
export LCORE_DAPP_ADDRESS="0xAE0863401D5B953b89cad8a5E7c98f5136E9C26d"
export LCORE_INPUTBOX_ADDRESS="0x59b22D57D4f067708AB0c00552767405926dc768"

npm run start
```

### Option 2: Using .env file

```bash
cd attestor
cp .env.example .env
# Edit .env with your values
npm run start
```

### Option 3: Docker

```bash
cd attestor
docker build -f attestor.dockerfile -t lcore-attestor .
docker run -p 8001:8001 --env-file .env lcore-attestor
```

## Server URL Configuration

By default, E2E tests connect to `http://localhost:8001`. Override with:

```bash
ATTESTOR_URL=http://your-server:8001 npm run test:device
```

## Expected Behavior

### Valid Submissions

Valid signed device data may return:
- `201` - Full success (data submitted to Cartesi)
- `500` - Signature verified, but Cartesi submission failed (node unavailable)

Both indicate the signature verification passed.

### Validation Errors

- `400` - Missing/invalid fields, bad DID format, timestamp out of range
- `401` - Invalid signature (wrong key, tampered payload)

## Writing New Tests

Tests use Node.js native test runner with TypeScript:

```typescript
import { describe, it } from 'node:test'
import assert from 'node:assert'

describe('My Feature', () => {
  it('should work correctly', () => {
    assert.strictEqual(1 + 1, 2)
  })
})
```

Import DID utilities for device identity generation:

```typescript
import { secp256k1 } from '@noble/curves/secp256k1'
import { createJWS, publicKeyToDIDKey } from '../../attestor/src/api/services/did.ts'

function generateDeviceIdentity() {
  const privKey = secp256k1.utils.randomPrivateKey()
  const pubKey = secp256k1.getPublicKey(privKey, true)
  const did = publicKeyToDIDKey(pubKey)
  return { privKey, pubKey, did }
}
```
