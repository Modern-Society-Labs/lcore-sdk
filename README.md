# L{CORE}

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

## Project Structure

```
lcore-sdk/
├── packages/
│   ├── python/          # pip install lcore-sdk
│   ├── typescript/      # @localecore/lcore-sdk
│   └── c/               # Embedded C library
├── attestor/            # Verification server (fork of Reclaim attestor-core)
├── cartesi/             # Rollup application
└── docker-compose.yml   # Self-hosting
```

## Architecture

```
Device (did:key) → Attestor → Cartesi (SQLite) → EVM
```

## Credits

Built on open-source infrastructure:

- [Reclaim Protocol](https://reclaimprotocol.org) — Attestor built on [reclaimprotocol/attestor-core](https://github.com/reclaimprotocol/attestor-core)
- [Cartesi](https://cartesi.io) — Full Linux runtime with fraud proofs
- [Arbitrum](https://arbitrum.io) — Default L2 settlement (deploy on any EVM)

## License

AGPL-3.0 — Open source, fork it, modify it, audit it. Derivative works must also be open-sourced.
