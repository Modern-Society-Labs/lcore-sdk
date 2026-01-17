# L{CORE} Python SDK

Python SDK for L{CORE} - Privacy-preserving IoT attestation layer built on Cartesi Rollups.

## Installation

```bash
pip install lcore-sdk
```

Or install from source:

```bash
cd packages/python
pip install -e .
```

## Quick Start

```python
import asyncio
from lcore import LCore, DeviceIdentity

async def main():
    # Initialize client
    lcore = LCore(
        attestor_url="http://localhost:8001",
        cartesi_url="http://localhost:10000",
        dapp_address="0xAE0863401D5B953b89cad8a5E7c98f5136E9C26d"
    )

    # Generate a new device identity
    device = DeviceIdentity.generate()
    print(f"Device DID: {device.did}")

    # Submit sensor data
    result = await lcore.submit_device_data(
        device=device,
        payload={"temperature": 23.4, "humidity": 65}
    )

    if result.success:
        print(f"Submitted! TX: {result.tx_hash}")
    else:
        print(f"Error: {result.error}")

    await lcore.close()

asyncio.run(main())
```

## Device Identity

### Generate New Identity

```python
from lcore import DeviceIdentity

# Generate random keypair
device = DeviceIdentity.generate()
print(device.did)  # did:key:zQ3sh...

# Save for later use
device.save("device.json")
```

### Load Existing Identity

```python
# From file
device = DeviceIdentity.load("device.json")

# From hex private key
device = DeviceIdentity.from_hex("0xabcd1234...")

# From raw bytes
device = DeviceIdentity.from_private_key(key_bytes)
```

### Sign Data

```python
# Sign and get submission-ready data
signed = device.sign({"temperature": 23.4})
# Returns: {"did": "...", "payload": {...}, "signature": "...", "timestamp": ...}
```

## Synchronous Usage

For non-async environments (scripts, Jupyter notebooks):

```python
from lcore import DeviceIdentity
from lcore.client import LCoreSync

lcore = LCoreSync(attestor_url="http://localhost:8001")
device = DeviceIdentity.generate()

result = lcore.submit_device_data(device, {"temperature": 23.4})
print(result)

lcore.close()
```

## DID Utilities

Low-level utilities for working with did:key and JWS:

```python
from lcore import (
    public_key_to_did_key,
    parse_did_key,
    create_jws,
    verify_jws,
)

# Convert public key to DID
did = public_key_to_did_key(public_key_bytes)

# Parse DID back to public key
pub_key = parse_did_key("did:key:zQ3sh...")

# Create JWS signature
jws = create_jws({"temp": 23.4}, private_key_bytes)

# Verify JWS
is_valid = verify_jws(jws, {"temp": 23.4}, public_key_bytes)
```

## Raspberry Pi / Jetson Example

```python
#!/usr/bin/env python3
"""
Raspberry Pi sensor data submission example.
"""

import asyncio
import json
from pathlib import Path
from lcore import LCore, DeviceIdentity

# Try to import GPIO (only available on Pi)
try:
    import board
    import adafruit_dht
    HAS_SENSOR = True
except ImportError:
    HAS_SENSOR = False
    print("Warning: No DHT sensor library, using mock data")

DEVICE_FILE = Path.home() / ".lcore" / "device.json"
ATTESTOR_URL = "http://your-attestor:8001"

def get_or_create_device() -> DeviceIdentity:
    """Load device identity or create new one."""
    if DEVICE_FILE.exists():
        return DeviceIdentity.load(str(DEVICE_FILE))

    DEVICE_FILE.parent.mkdir(parents=True, exist_ok=True)
    device = DeviceIdentity.generate()
    device.save(str(DEVICE_FILE))
    print(f"Created new device: {device.did}")
    return device

def read_sensor() -> dict:
    """Read temperature and humidity from DHT22."""
    if HAS_SENSOR:
        dht = adafruit_dht.DHT22(board.D4)
        return {
            "temperature": dht.temperature,
            "humidity": dht.humidity,
        }
    else:
        # Mock data for testing
        return {"temperature": 23.4, "humidity": 65}

async def main():
    device = get_or_create_device()

    async with LCore(attestor_url=ATTESTOR_URL) as lcore:
        while True:
            # Read sensor
            data = read_sensor()
            print(f"Read: {data}")

            # Submit to L{CORE}
            result = await lcore.submit_device_data(device, data)

            if result.success:
                print(f"Submitted: {result.tx_hash}")
            else:
                print(f"Error: {result.error}")

            # Wait before next reading
            await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(main())
```

## API Reference

### LCore

| Method | Description |
|--------|-------------|
| `submit_device_data(device, payload)` | Submit signed device data |
| `submit_raw(did, payload, signature, timestamp)` | Submit pre-signed data |
| `inspect(path)` | Query Cartesi via inspect endpoint |
| `health_check()` | Check attestor health |

### DeviceIdentity

| Method | Description |
|--------|-------------|
| `generate()` | Create new random identity |
| `from_private_key(bytes)` | Create from 32-byte key |
| `from_hex(str)` | Create from hex string |
| `load(path)` | Load from JSON file |
| `save(path)` | Save to JSON file |
| `sign(payload)` | Sign data for submission |
| `to_hex()` | Export private key as hex |

## Requirements

- Python 3.9+
- `httpx` - HTTP client
- `coincurve` - secp256k1 cryptography
- `base58` - Base58 encoding
- `pynacl` - Additional crypto utilities
