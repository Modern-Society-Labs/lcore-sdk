# L{CORE} SDK

Privacy-preserving IoT attestation layer built on [Cartesi](https://cartesi.io) rollups and [Reclaim Protocol](https://reclaimprotocol.org).

## Overview

L{CORE} enables **trustless verification of IoT and off-chain data** for blockchain applications. Devices sign data with decentralized identities (did:key), which is verified and stored in a deterministic Cartesi rollup.

### Features

- **Device Identity** — did:key based identity with ES256K signatures
- **Privacy Buckets** — Discretize sensitive data (e.g., "temp > 30°C" instead of exact values)
- **Deterministic Storage** — SQLite on Cartesi for verifiable queries
- **Multi-Platform SDKs** — Python, TypeScript, and C for embedded devices

## Installation

### Python

```bash
pip install lcore-sdk
```

```python
from lcore import LCore, DeviceIdentity

device = DeviceIdentity.generate()

async with LCore(attestor_url="http://localhost:8001") as lcore:
    result = await lcore.submit_device_data(
        device=device,
        payload={"temperature": 23.4, "humidity": 65}
    )
    print(f"TX: {result.tx_hash}")
```

### TypeScript

```bash
npm install @localecore/lcore-sdk
```

```typescript
import { LCore, DeviceIdentity } from '@localecore/lcore-sdk'

const device = DeviceIdentity.generate()
const lcore = new LCore({ attestorUrl: 'http://localhost:8001' })

const result = await lcore.submitDeviceData(device, {
  temperature: 23.4,
  humidity: 65
})
```

### C (Embedded)

See [packages/c/README.md](packages/c/README.md) for ESP32, Arduino, and ARM integration.

## Self-Hosting

```bash
git clone https://github.com/Modern-Society-Labs/lcore-sdk.git
cd lcore-sdk
cp .env.example .env
# Edit .env with your RPC endpoint and wallet

docker-compose up -d
```

## Architecture

```
Device (did:key) → Attestor (verify signature) → Cartesi (SQLite) → Arbitrum
```

## Project Structure

```
lcore-sdk/
├── packages/
│   ├── python/          # pip install lcore-sdk
│   ├── typescript/      # @localecore/lcore-sdk
│   └── c/               # Embedded C library
├── attestor/            # Verification server
├── cartesi/             # Rollup application
└── docker-compose.yml   # Self-hosting
```

## Testnet

| Service | Endpoint |
|---------|----------|
| Attestor | `http://104.197.228.179:8001` |
| Cartesi | `http://34.70.167.143:10000` |

## Credits

Built on:

- [Reclaim Protocol](https://reclaimprotocol.org) — zkTLS attestation infrastructure
- [Cartesi](https://cartesi.io) — Deterministic rollups with Linux runtime
- [Arbitrum](https://arbitrum.io) — L2 settlement layer

## License

AGPL-3.0

---

**[Modern Society Labs](https://github.com/Modern-Society-Labs)**
