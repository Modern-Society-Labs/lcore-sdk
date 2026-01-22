# Access Control Example

Demonstrates address-based access control for L{CORE} device attestation queries.

**Only the deployer address can query device attestation data.**

## Authorized Address

```
0xYOUR_AUTHORIZED_ADDRESS_HERE
```

## What This Example Shows

- How to restrict inspect query handlers to specific addresses
- Pattern for checking `sender` parameter in queries
- Keeping aggregate endpoints (stats) public while protecting individual data

## Quick Start

### 1. Apply the patch to your cartesi code

```bash
cd /path/to/lcore-sdk
patch -p0 < examples/access-control/lcore-device.patch
```

### 2. Build and run locally

```bash
cd cartesi
npm install
npm run build

# Start the servers
node dist/rollup-server.js &
sleep 2
ROLLUP_HTTP_SERVER_URL=http://127.0.0.1:5004 node dist/lcore-main.js &
sleep 3
```

### 3. Run the test

```bash
cd examples/access-control
npm install
npm test
```

### 4. Revert the patch when done

```bash
cd /path/to/lcore-sdk
patch -R -p0 < examples/access-control/lcore-device.patch
```

## What the Patch Changes

The patch modifies `cartesi/src/handlers/lcore-device.ts` to add:

1. **Authorized address constant**

```typescript
const AUTHORIZED_ADDRESS = '0xYOUR_AUTHORIZED_ADDRESS_HERE';
```

2. **Access control check** (added to `handleInspectDeviceAttestations` and `handleInspectDeviceLatest`)

```typescript
const requester = query.params.sender?.toLowerCase();
if (!requester || requester !== AUTHORIZED_ADDRESS.toLowerCase()) {
  return {
    error: 'ACCESS DENIED',
    message: 'Only the deployer address can query device attestations',
    authorized: AUTHORIZED_ADDRESS,
    requester: requester || 'none',
  };
}
```

3. **`handleInspectDeviceStats` remains public** (aggregate data only)

## Test Results

```text
[Test 1] Query with AUTHORIZED address...
  ✅ PASS: Access granted to deployer

[Test 2] Query with UNAUTHORIZED address...
  ✅ PASS: Access correctly denied
  Result: { error: 'ACCESS DENIED', ... }

[Test 3] Query with NO sender...
  ✅ PASS: Access correctly denied (no sender)

[Test 4] Query device_stats (public endpoint)...
  ✅ PASS: Stats endpoint is public
```

## Files

| File                          | Description                                  |
|-------------------------------|----------------------------------------------|
| `lcore-device.patch`          | Unified diff to apply access control         |
| `test-access-control.js`      | Integration test (requires running Cartesi)  |
| `test-local-access-control.js`| Unit test (no server required)               |

## Unit Test (No Server Required)

Test the access control logic without running Cartesi:

```bash
npm run test:local
```

## Production Considerations

In production, the `sender` would be verified via:

1. **Signed messages** - Require signature proving address ownership
2. **On-chain context** - Use `msg_sender` from advance calls
3. **Attestor relay** - Include authenticated sender in encrypted payload

This example uses a simple parameter check to demonstrate the concept.

## Customization

To use a different authorized address, modify the `AUTHORIZED_ADDRESS` constant in the patch or edit the patched file directly.

For multiple authorized addresses:

```typescript
const AUTHORIZED_ADDRESSES = new Set([
  '0xYOUR_AUTHORIZED_ADDRESS_HERE',
  '0xAnotherAddress...',
].map(a => a.toLowerCase()));

// In handler:
if (!AUTHORIZED_ADDRESSES.has(requester)) {
  return { error: 'ACCESS DENIED' };
}
```
