# L{CORE} SDK

Privacy-preserving IoT attestation layer built on [Cartesi](https://cartesi.io) rollups and [Reclaim Protocol](https://reclaimprotocol.org).

## Overview

L{CORE} enables trustless verification of IoT and off-chain data for blockchain applications. Devices sign data with decentralized identities (did:key), verified and stored in a deterministic Cartesi rollup.

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

See [packages/c/README.md](packages/c/README.md) for ESP32, Arduino, and ARM.

## Self-Hosting

```bash
git clone https://github.com/Modern-Society-Labs/lcore-sdk.git
cd lcore-sdk
cp .env.example .env
docker-compose up -d
```

## Architecture

```
Device (did:key) → Attestor → Cartesi (SQLite) → Arbitrum
```

## Credits

- [Reclaim Protocol](https://reclaimprotocol.org)
- [Cartesi](https://cartesi.io)
- [Arbitrum](https://arbitrum.io)

## License

AGPL-3.0
