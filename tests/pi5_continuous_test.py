#!/usr/bin/env python3
"""
Continuous E2E Test: Pi 5 Sense HAT → EigenCloud

Submits sensor data every 10 seconds to EigenCloud.

Run on Pi 5:
    pip install httpx coincurve sense-hat
    python pi5_continuous_test.py

Or without Sense HAT (mock data):
    pip install httpx coincurve
    python pi5_continuous_test.py
"""

import os
import sys
import json
import time
import base64
import hashlib
import asyncio
from dataclasses import dataclass
from typing import Optional

import httpx

# EigenCloud endpoints
ATTESTOR_URL = "http://104.197.228.179:8001"
CARTESI_URL = "http://34.70.167.143:10000"

# Submission interval (seconds)
INTERVAL = 10

# Device identity file
DEVICE_FILE = os.path.expanduser("~/.lcore_device.json")


# ============================================================
# DID:KEY Implementation
# ============================================================

def _base58btc_encode(data: bytes) -> str:
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r])
    for b in data:
        if b == 0:
            result.append(ALPHABET[0])
        else:
            break
    return "z" + "".join(reversed(result))


def public_key_to_did_key(public_key: bytes) -> str:
    multicodec = bytes([0xe7, 0x01]) + public_key
    return f"did:key:{_base58btc_encode(multicodec)}"


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def create_jws(payload: dict, private_key: bytes) -> str:
    from coincurve import PrivateKey

    header = {"alg": "ES256K", "typ": "JWT"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    message = f"{header_b64}.{payload_b64}".encode()
    msg_hash = hashlib.sha256(message).digest()

    priv = PrivateKey(private_key)
    sig = priv.sign(msg_hash, hasher=None)

    r_len = sig[3]
    r = sig[4 : 4 + r_len]
    s_start = 4 + r_len + 2
    s_len = sig[s_start - 1]
    s = sig[s_start : s_start + s_len]

    r = r[-32:].rjust(32, b"\x00")
    s = s[-32:].rjust(32, b"\x00")

    sig_b64 = _base64url_encode(r + s)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ============================================================
# Device Identity
# ============================================================

@dataclass
class DeviceIdentity:
    private_key: bytes
    public_key: bytes
    did: str

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        from coincurve import PrivateKey
        private_key = os.urandom(32)
        priv = PrivateKey(private_key)
        public_key = priv.public_key.format(compressed=True)
        did = public_key_to_did_key(public_key)
        return cls(private_key=private_key, public_key=public_key, did=did)

    @classmethod
    def from_hex(cls, hex_key: str) -> "DeviceIdentity":
        from coincurve import PrivateKey
        if hex_key.startswith("0x"):
            hex_key = hex_key[2:]
        private_key = bytes.fromhex(hex_key)
        priv = PrivateKey(private_key)
        public_key = priv.public_key.format(compressed=True)
        did = public_key_to_did_key(public_key)
        return cls(private_key=private_key, public_key=public_key, did=did)

    def sign(self, payload: dict) -> dict:
        signature = create_jws(payload, self.private_key)
        timestamp = int(time.time())
        return {
            "did": self.did,
            "payload": payload,
            "signature": signature,
            "timestamp": timestamp,
        }

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"private_key": self.private_key.hex(), "did": self.did}, f)

    @classmethod
    def load(cls, path: str) -> "DeviceIdentity":
        with open(path) as f:
            data = json.load(f)
        return cls.from_hex(data["private_key"])


# ============================================================
# Sensor Reading
# ============================================================

sense = None


def init_sense_hat():
    """Initialize Sense HAT (lazy load)."""
    global sense
    if sense is not None:
        return True

    try:
        from sense_hat import SenseHat
        sense = SenseHat()
        print("[INFO] Sense HAT initialized")
        return True
    except ImportError:
        print("[WARN] Sense HAT not available - using mock data")
        return False


def get_sensor_data() -> dict:
    """Read from Sense HAT or return mock data."""
    if sense is not None:
        return {
            "temperature": round(sense.get_temperature(), 2),
            "humidity": round(sense.get_humidity(), 2),
            "pressure": round(sense.get_pressure(), 2),
            "source": "pi5-sensehat",
        }
    else:
        # Mock data with slight variation
        import random
        return {
            "temperature": round(23.0 + random.uniform(-2, 2), 2),
            "humidity": round(65.0 + random.uniform(-5, 5), 2),
            "pressure": round(1013.0 + random.uniform(-5, 5), 2),
            "source": "mock-sensor",
        }


def get_device() -> DeviceIdentity:
    """Load or create device identity."""
    if os.path.exists(DEVICE_FILE):
        return DeviceIdentity.load(DEVICE_FILE)
    else:
        print("[INFO] Generating new device identity...")
        device = DeviceIdentity.generate()
        device.save(DEVICE_FILE)
        print(f"[INFO] Saved to {DEVICE_FILE}")
        return device


# ============================================================
# Submission
# ============================================================

async def submit_once(client: httpx.AsyncClient, device: DeviceIdentity) -> bool:
    """Submit one sensor reading."""
    payload = get_sensor_data()
    payload["timestamp_local"] = int(time.time())

    submission = device.sign(payload)

    try:
        resp = await client.post(
            f"{ATTESTOR_URL}/api/device/submit",
            json=submission,
            timeout=30.0,
        )
        data = resp.json()

        if resp.status_code == 201:
            tx = data.get("data", {}).get("txHash", "?")[:16]
            block = data.get("data", {}).get("blockNumber", "?")
            print(f"[OK] temp={payload['temperature']}°C hum={payload['humidity']}% | tx={tx}... block={block}")
            return True
        else:
            error = data.get("error", f"HTTP {resp.status_code}")
            print(f"[ERR] {error[:80]}")
            return False
    except Exception as e:
        print(f"[ERR] {str(e)[:80]}")
        return False


async def check_health(client: httpx.AsyncClient) -> bool:
    """Check if attestor is healthy."""
    try:
        resp = await client.get(f"{ATTESTOR_URL}/api/health", timeout=5.0)
        return resp.status_code == 200
    except:
        return False


async def main():
    """Run continuous submission loop."""
    print("=" * 60)
    print("L{CORE} Continuous Sensor Submission")
    print("=" * 60)
    print(f"Attestor: {ATTESTOR_URL}")
    print(f"Interval: {INTERVAL}s")
    print()

    # Initialize
    init_sense_hat()
    device = get_device()
    print(f"Device: {device.did}")
    print()

    # Stats
    total = 0
    success = 0
    start_time = time.time()

    async with httpx.AsyncClient() as client:
        # Initial health check
        if not await check_health(client):
            print("[ERR] Attestor not responding - check connection")
            return

        print("[INFO] Starting continuous submission (Ctrl+C to stop)")
        print("-" * 60)

        try:
            while True:
                total += 1
                if await submit_once(client, device):
                    success += 1

                # Wait for next interval
                await asyncio.sleep(INTERVAL)

        except KeyboardInterrupt:
            pass

    # Summary
    elapsed = time.time() - start_time
    print()
    print("-" * 60)
    print(f"Summary: {success}/{total} successful ({success/total*100:.1f}%)")
    print(f"Runtime: {elapsed/60:.1f} minutes")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
