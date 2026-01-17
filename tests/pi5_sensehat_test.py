#!/usr/bin/env python3
"""
Standalone E2E Test: Pi 5 Sense HAT → EigenCloud

No package installation required - just copy this file to Pi and run:
    pip install httpx coincurve
    python pi5_sensehat_test.py

Or with Sense HAT:
    pip install httpx coincurve sense-hat
    python pi5_sensehat_test.py
"""

import os
import sys
import json
import time
import base64
import hashlib
import asyncio
from dataclasses import dataclass
from typing import Optional, Any

import httpx

# EigenCloud endpoints
ATTESTOR_URL = "http://104.197.228.179:8001"
CARTESI_URL = "http://34.70.167.143:10000"

# Device identity file
DEVICE_FILE = os.path.expanduser("~/.lcore_device.json")


# ============================================================
# DID:KEY Implementation (minimal, standalone)
# ============================================================

def _base58btc_encode(data: bytes) -> str:
    """Encode bytes to base58btc with 'z' prefix."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r])
    # Add leading zeros
    for b in data:
        if b == 0:
            result.append(ALPHABET[0])
        else:
            break
    return "z" + "".join(reversed(result))


def public_key_to_did_key(public_key: bytes) -> str:
    """Convert secp256k1 compressed public key to did:key."""
    # Multicodec prefix for secp256k1-pub: 0xe7 0x01
    multicodec = bytes([0xe7, 0x01]) + public_key
    return f"did:key:{_base58btc_encode(multicodec)}"


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_jws(payload: dict, private_key: bytes) -> str:
    """Create JWS compact serialization."""
    from coincurve import PrivateKey

    # Header
    header = {"alg": "ES256K", "typ": "JWT"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())

    # Payload
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Message to sign
    message = f"{header_b64}.{payload_b64}".encode()
    msg_hash = hashlib.sha256(message).digest()

    # Sign
    priv = PrivateKey(private_key)
    sig = priv.sign(msg_hash, hasher=None)

    # Convert DER to compact (r || s)
    # DER: 0x30 len 0x02 r_len r 0x02 s_len s
    r_len = sig[3]
    r = sig[4 : 4 + r_len]
    s_start = 4 + r_len + 2
    s_len = sig[s_start - 1]
    s = sig[s_start : s_start + s_len]

    # Pad/trim to 32 bytes each
    r = r[-32:].rjust(32, b"\x00")
    s = s[-32:].rjust(32, b"\x00")

    sig_b64 = _base64url_encode(r + s)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ============================================================
# Device Identity
# ============================================================

@dataclass
class DeviceIdentity:
    """Device identity with did:key and signing."""

    private_key: bytes
    public_key: bytes
    did: str

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        """Generate new random identity."""
        from coincurve import PrivateKey

        private_key = os.urandom(32)
        priv = PrivateKey(private_key)
        public_key = priv.public_key.format(compressed=True)
        did = public_key_to_did_key(public_key)

        return cls(private_key=private_key, public_key=public_key, did=did)

    @classmethod
    def from_hex(cls, hex_key: str) -> "DeviceIdentity":
        """Create from hex private key."""
        from coincurve import PrivateKey

        if hex_key.startswith("0x"):
            hex_key = hex_key[2:]
        private_key = bytes.fromhex(hex_key)
        priv = PrivateKey(private_key)
        public_key = priv.public_key.format(compressed=True)
        did = public_key_to_did_key(public_key)

        return cls(private_key=private_key, public_key=public_key, did=did)

    def sign(self, payload: dict) -> dict:
        """Sign payload and return submission data."""
        signature = create_jws(payload, self.private_key)
        timestamp = int(time.time())

        return {
            "did": self.did,
            "payload": payload,
            "signature": signature,
            "timestamp": timestamp,
        }

    def save(self, path: str):
        """Save to JSON file."""
        with open(path, "w") as f:
            json.dump({"private_key": self.private_key.hex(), "did": self.did}, f)

    @classmethod
    def load(cls, path: str) -> "DeviceIdentity":
        """Load from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls.from_hex(data["private_key"])


# ============================================================
# Test Functions
# ============================================================

def get_sensor_data() -> dict:
    """Read from Sense HAT or return mock data."""
    try:
        from sense_hat import SenseHat
        sense = SenseHat()
        return {
            "temperature": round(sense.get_temperature(), 2),
            "humidity": round(sense.get_humidity(), 2),
            "pressure": round(sense.get_pressure(), 2),
            "source": "pi5-sensehat",
        }
    except ImportError:
        print("[WARN] Sense HAT not available, using mock data")
        return {
            "temperature": 23.4 + (time.time() % 10) / 10,  # Vary slightly
            "humidity": 65.2,
            "pressure": 1013.25,
            "source": "mock-sensor",
        }


def get_device() -> DeviceIdentity:
    """Load or create device identity."""
    if os.path.exists(DEVICE_FILE):
        print(f"[INFO] Loading device from {DEVICE_FILE}")
        return DeviceIdentity.load(DEVICE_FILE)
    else:
        print("[INFO] Generating new device identity...")
        device = DeviceIdentity.generate()
        device.save(DEVICE_FILE)
        print(f"[INFO] Saved to {DEVICE_FILE}")
        return device


async def test_health():
    """Check EigenCloud services."""
    print("\n=== Health Check ===")

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Attestor
        try:
            resp = await client.get(f"{ATTESTOR_URL}/api/health")
            data = resp.json()
            print(f"Attestor: OK - {data.get('status')}")
        except Exception as e:
            print(f"Attestor: FAILED - {e}")

        # Cartesi
        try:
            resp = await client.post(
                f"{CARTESI_URL}/graphql",
                json={"query": "{ inputs { totalCount } }"},
            )
            data = resp.json()
            count = data.get("data", {}).get("inputs", {}).get("totalCount", "?")
            print(f"Cartesi: OK - {count} inputs")
        except Exception as e:
            print(f"Cartesi: FAILED - {e}")


async def test_submit():
    """Submit sensor data to EigenCloud."""
    print("\n=== Submit Sensor Data ===")

    device = get_device()
    print(f"Device DID: {device.did}")

    payload = get_sensor_data()
    payload["timestamp_local"] = int(time.time())
    print(f"Payload: {payload}")

    # Sign and submit
    submission = device.sign(payload)

    async with httpx.AsyncClient(timeout=30.0) as client:
        print("\n[INFO] Submitting to attestor...")
        try:
            resp = await client.post(
                f"{ATTESTOR_URL}/api/device/submit",
                json=submission,
            )
            data = resp.json()
            print(f"Response ({resp.status_code}): {json.dumps(data, indent=2)}")

            if resp.status_code == 201:
                tx_hash = data.get("data", {}).get("txHash")
                block = data.get("data", {}).get("blockNumber")
                print(f"\n[SUCCESS] TX: {tx_hash} @ block {block}")
                return True
            else:
                print(f"\n[FAILED] {data.get('error', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"\n[ERROR] {e}")
            return False


async def test_query():
    """Query recent inputs from Cartesi."""
    print("\n=== Query Cartesi ===")

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{CARTESI_URL}/graphql",
            json={
                "query": """
                    query {
                        inputs(last: 5) {
                            edges {
                                node {
                                    index
                                    status
                                    timestamp
                                }
                            }
                        }
                    }
                """
            },
        )
        data = resp.json()
        inputs = data.get("data", {}).get("inputs", {}).get("edges", [])

        print(f"Recent inputs ({len(inputs)}):")
        for edge in inputs:
            node = edge.get("node", {})
            print(f"  #{node.get('index')}: {node.get('status')} @ {node.get('timestamp')}")


async def main():
    """Run E2E test."""
    print("=" * 60)
    print("L{CORE} E2E: Pi 5 Sense HAT → EigenCloud")
    print("=" * 60)
    print(f"Attestor: {ATTESTOR_URL}")
    print(f"Cartesi:  {CARTESI_URL}")

    await test_health()
    success = await test_submit()

    if success:
        print("\n[INFO] Waiting 5s for Cartesi processing...")
        await asyncio.sleep(5)
        await test_query()

    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
