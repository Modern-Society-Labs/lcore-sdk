# L{CORE} v2.0

**Open attestation infrastructure for the sovereign web.**

L{CORE} is a complete, self-hostable stack for device and data attestation. It combines TEE-verified execution, on-chain settlement with fraud proofs, and SDKs for embedded devices—all open source, all deploy-anywhere.

**No tokens. No fees. No lock-in.**

## Who It's For

- **Cities & Governments** — Infrastructure you control, no external dependencies
- **Enterprises** — Self-host, audit the code, own your attestation layer
- **DePIN Builders** — Device attestation without ecosystem lock-in
- **L2s & Chains** — Add attestation capabilities without adopting another protocol

## Why L{CORE}?

**No Lock-In** — Deploy on any EVM chain. Run on any infrastructure. Switch chains without rewriting your application.

**No Fees** — Zero protocol fees. Zero token requirements. You pay gas costs on your chosen chain—that's it.

**Full Compute** — Not a sandbox. Full Linux environment. Run SQLite, Python libraries, existing codebases—anything that runs on Linux.

**Self-Sovereign** — Run your own attestors. Own your infrastructure. No dependency on external networks or third-party uptime.

**Device-First** — C SDK for resource-constrained embedded devices. Real IoT attestation, not just mobile apps.

## How It Works

```
Device (did:key + secp256k1) → Attestor (TEE) → InputBox (on-chain) → Cartesi (RISC-V) → EVM
```

1. **Device** generates a `did:key` identity, a per-submission random `salt`, and computes a deterministic hash:
   ```
   data_hash = sha256(JCS(payload) + device_did + timestamp + salt)
   ```
   The `salt` is sent to the attestor and stored **inside the encrypted blob** — it never goes on-chain. Because `device_did` and `timestamp` are public, the salt is what stops an observer from brute-forcing low-entropy sensor data (e.g. a temperature) out of the on-chain hash.
2. **Device** signs `data_hash` as a JWS (ES256K / secp256k1)
3. **Attestor** recomputes the hash (using the device's `salt`), verifies the JWS (fail-fast), encrypts the payload, and submits to the Cartesi InputBox
4. **Cartesi** independently re-verifies the JWS over the hash inside a RISC-V VM — fully fraud-provable
5. **Anyone** can re-run the Cartesi node and verify every device signature was valid

### Encryption

| Version | Algorithm | Key Scope | Use Case |
|---------|-----------|-----------|----------|
| V1 | XChaCha20-Poly1305 + X25519 | Single admin keypair | Simple deployments |
| V2 | ECDH (secp256k1) + XChaCha20-Poly1305 | Per-device shared secret | Production — blast radius isolation |

V2 ensures that compromise of one device key cannot decrypt another device's data.

### Batching

Device submissions are buffered and flushed as `batch_device_attestation` transactions, decoupling individual device timing from on-chain activity patterns.

| Config | Default | Description |
|--------|---------|-------------|
| `LCORE_BATCH_FLUSH_INTERVAL` | 30000ms | Flush timer interval |
| `LCORE_BATCH_MAX_SIZE` | 50 | Max submissions before forced flush |

## Quick Start

### Device Submission (TypeScript)

```typescript
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import canonicalize from 'canonicalize'

// 1. Generate device identity
const privateKey = crypto.getRandomValues(new Uint8Array(32))
const publicKey = secp256k1.getPublicKey(privateKey, true)
const did = publicKeyToDIDKey(publicKey) // did:key:zQ3sh...

// 2. Build payload + per-submission random salt
const payload = { temperature: 22.5, humidity: 65, location: 'lab-1' }
const timestamp = Math.floor(Date.now() / 1000)
const salt = bytesToHex(crypto.getRandomValues(new Uint8Array(16)))

// 3. Compute deterministic, salted hash
const canonical = canonicalize(payload)
const combined = canonical + did + String(timestamp) + salt
const dataHash = bytesToHex(sha256(new TextEncoder().encode(combined)))

// 4. Sign hash as JWS (ES256K)
const jws = createJWSOverHash(dataHash, privateKey)

// 5. Submit to attestor (include the salt so it can reproduce the hash)
await fetch('https://your-attestor/api/device/submit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ did, payload, signature: jws, timestamp, salt }),
})
```

> **Tip:** the `@localecore/lcore-sdk` `DeviceIdentity.sign(payload)` does steps 2–4 for you and returns `{ did, payload, signature, timestamp, salt }` ready to POST.

```typescript
// Equivalent using the SDK:
import { DeviceIdentity } from '@localecore/lcore-sdk'
const device = DeviceIdentity.generate()
const submission = device.sign({ temperature: 22.5, humidity: 65 })
await fetch('https://your-attestor/api/device/submit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(submission),
})
```

### Querying Data

```bash
# Latest attestation for a device
curl -X POST https://your-attestor/api/inspect/device-latest \
  -H 'Content-Type: application/json' \
  -d '{"device_did":"did:key:zQ3sh..."}'

# All attestations for a device
curl -X POST https://your-attestor/api/inspect/device-attestations \
  -H 'Content-Type: application/json' \
  -d '{"device_did":"did:key:zQ3sh...","limit":50,"offset":0}'

# Get admin public key (for re-encryption requests)
curl https://your-attestor/api/inspect/public-key
```

## Self-Hosting

```bash
git clone https://github.com/Modern-Society-Labs/lcore-sdk.git
cd lcore-sdk
cp .env.example .env
# Edit .env with your RPC URL, mnemonic, and encryption keys
docker-compose up -d
```

### Environment Variables

#### Attestor

| Variable | Required | Description |
|----------|----------|-------------|
| `MNEMONIC` | Yes | Wallet mnemonic for signing on-chain transactions |
| `LCORE_RPC_URL` | Yes | Blockchain RPC endpoint (e.g. Alchemy Arbitrum Sepolia) |
| `LCORE_DAPP_ADDRESS` | Yes | Cartesi dApp contract address (from `cartesi deploy`) |
| `LCORE_INPUTBOX_ADDRESS` | No | InputBox contract (default: `0x59b22D57D4f067708AB0c00552767405926dc768`) |
| `LCORE_NODE_URL` | Yes | Cartesi node URL for inspect queries |
| `LCORE_PRIVATE_KEY` | Yes | V1 X25519 private key (base64) |
| `LCORE_PUBLIC_KEY` | Yes | V1 X25519 public key (base64) |
| `LCORE_PRIVATE_KEY_V2` | No | V2 secp256k1 private key (hex) — enables per-device ECDH |
| `LCORE_BATCH_ENABLED` | No | Enable submission batching (default: `1`) |

#### Cartesi Node

| Variable | Required | Description |
|----------|----------|-------------|
| `CARTESI_BLOCKCHAIN_HTTP_ENDPOINT` | Yes | Same RPC as attestor |
| `CARTESI_CONTRACTS_APPLICATION_ADDRESS` | Yes | Must match attestor's `LCORE_DAPP_ADDRESS` |
| `CARTESI_POSTGRES_ENDPOINT` | Yes | PostgreSQL connection string for inputs/outputs |
| `CARTESI_AUTH_MNEMONIC` | Yes | Wallet for Cartesi node operations |

### Docker Images

```bash
docker pull modernsociety/lcore-attestor:latest
docker pull modernsociety/lcore-node:latest
```

Both images are built for `linux/amd64`.

## Project Structure

```
lcore-sdk/
├── attestor/            # Attestor server (TEE-ready, fork of Reclaim attestor-core)
│   ├── src/api/routes/  # Device submission + inspect proxy endpoints
│   ├── src/lcore/       # Encryption (V1/V2), hash computation, Cartesi client
│   └── src/submission-batcher.ts
├── cartesi/             # Cartesi rollup application (RISC-V)
│   ├── src/handlers/    # Device attestation, access control, schemas
│   └── ARCHITECTURE.md  # Security architecture deep-dive
├── tests/               # Integration tests
├── docker-compose.yml   # Self-hosting stack
└── .env.example         # Configuration template
```

## API Reference

### Device Submission

```
POST /api/device/submit
```

| Field | Type | Description |
|-------|------|-------------|
| `did` | string | Device DID (`did:key:zQ3sh...`) |
| `payload` | object | Sensor data (any JSON) |
| `signature` | string | JWS over `sha256(JCS(payload) + did + timestamp + salt)` |
| `timestamp` | number | Unix epoch seconds |
| `salt` | string | Per-submission random salt, 32 hex chars (16 bytes). Folded into the signed hash; stored only inside the encrypted blob, never on-chain. |

### Inspect Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/inspect/device-latest` | POST | Latest attestation for a device |
| `/api/inspect/device-attestations` | POST | All attestations for a device (paginated) |
| `/api/inspect/attestation-data` | POST | Gated data access (requires access grant) |
| `/api/inspect/public-key` | GET | Admin NaCl public key |

## Credits

Built on open-source infrastructure:

- [Reclaim Protocol](https://reclaimprotocol.org) — Attestor built on [reclaimprotocol/attestor-core](https://github.com/reclaimprotocol/attestor-core)
- [Cartesi](https://cartesi.io) — Full Linux runtime with fraud proofs
- [Arbitrum](https://arbitrum.io) — Default L2 settlement (deploy on any EVM)

## License

| Component | License | SPDX |
|---|---|---|
| `attestor/`, `cartesi/` (and repository root) | AGPL-3.0 | `AGPL-3.0-only` |
| `packages/typescript`, `packages/python`, `packages/c` | MIT | `MIT` |

**Building a device or client?** The SDKs are MIT — embed them in commercial or
proprietary firmware with no obligation to publish your code.

**Running or modifying the attestor or rollup application?** Those are AGPL-3.0 — fork
them, modify them, audit them, but if you offer a modified L{CORE} service over a
network you must publish your changes.

The SDKs can be MIT because they talk to the attestor over HTTP and link no AGPL code:
no import, `require`, or dependency in any SDK resolves into `attestor/`, and every
third-party SDK dependency is permissive. *Maintainers: if an SDK ever imports from
`attestor/`, MIT is no longer available for that package.*

`attestor/` is a fork of [reclaimprotocol/attestor-core](https://github.com/reclaimprotocol/attestor-core)
(AGPL-3.0); see [`attestor/NOTICE`](./attestor/NOTICE). The C SDK uses MbedTLS
(Apache-2.0).
