#!/usr/bin/env python3
"""
E2E Test: Raspberry Pi 5 Sense HAT → EigenCloud

Tests the complete L{CORE} data flow:
1. Read real sensor data from Sense HAT
2. Sign with did:key using Python SDK
3. Submit to EigenCloud Attestor
4. Verify on-chain via Cartesi GraphQL

Run on Pi 5:
    pip install -e packages/python
    pip install sense-hat  # or sense-emu for testing without hardware
    python tests/test_eigencloud_e2e.py
"""

import asyncio
import sys
import os
import time

# Add packages/python to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "packages", "python", "src"))

from client import LCore
from device import DeviceIdentity

# EigenCloud endpoints
ATTESTOR_URL = "http://104.197.228.179:8001"
CARTESI_URL = "http://34.70.167.143:10000"
DAPP_ADDRESS = "0xCe5d7Fd245De833eEC7BDbeEb10b75D0e13E9Ec4"

# Device identity file (persistent across runs)
DEVICE_FILE = os.path.expanduser("~/.lcore_device.json")


def get_sense_hat_data() -> dict:
    """Read real sensor data from Sense HAT."""
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
        # Fallback for testing without Sense HAT
        print("[WARN] Sense HAT not available, using mock data")
        return {
            "temperature": 23.4,
            "humidity": 65.2,
            "pressure": 1013.25,
            "source": "mock-sensor",
        }


def get_or_create_device() -> DeviceIdentity:
    """Load existing device identity or create new one."""
    if os.path.exists(DEVICE_FILE):
        print(f"[INFO] Loading device identity from {DEVICE_FILE}")
        device = DeviceIdentity.load(DEVICE_FILE)
    else:
        print("[INFO] Generating new device identity...")
        device = DeviceIdentity.generate()
        device.save(DEVICE_FILE)
        print(f"[INFO] Saved device identity to {DEVICE_FILE}")

    return device


async def test_health():
    """Test that EigenCloud services are responding."""
    print("\n=== Health Check ===")

    async with LCore(attestor_url=ATTESTOR_URL, cartesi_url=CARTESI_URL) as lcore:
        # Check attestor
        healthy = await lcore.health_check()
        status = "OK" if healthy else "FAILED"
        print(f"Attestor ({ATTESTOR_URL}): {status}")

        # Check Cartesi via GraphQL
        import httpx
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{CARTESI_URL}/graphql",
                    json={"query": "{ inputs { totalCount } }"},
                    timeout=10.0,
                )
                data = resp.json()
                count = data.get("data", {}).get("inputs", {}).get("totalCount", "?")
                print(f"Cartesi ({CARTESI_URL}): OK - {count} inputs")
        except Exception as e:
            print(f"Cartesi ({CARTESI_URL}): FAILED - {e}")


async def test_submit():
    """Submit real sensor data to EigenCloud."""
    print("\n=== Sensor Data Submission ===")

    # Get device identity
    device = get_or_create_device()
    print(f"Device DID: {device.did}")

    # Read sensor data
    payload = get_sense_hat_data()
    payload["timestamp_local"] = int(time.time())
    print(f"Sensor data: {payload}")

    # Submit to EigenCloud
    async with LCore(
        attestor_url=ATTESTOR_URL,
        cartesi_url=CARTESI_URL,
        dapp_address=DAPP_ADDRESS,
    ) as lcore:
        print("\n[INFO] Submitting to EigenCloud...")
        result = await lcore.submit_device_data(device, payload)

        if result.success:
            print(f"\n[SUCCESS] Data submitted!")
            print(f"  TX Hash: {result.tx_hash}")
            print(f"  Block: {result.block_number}")
            return True
        else:
            print(f"\n[FAILED] {result.error}")
            return False


async def test_query():
    """Query device attestations from Cartesi."""
    print("\n=== Query Attestations ===")

    device = get_or_create_device()

    async with LCore(
        attestor_url=ATTESTOR_URL,
        cartesi_url=CARTESI_URL,
    ) as lcore:
        # Query all inputs
        import httpx
        async with httpx.AsyncClient() as client:
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
                                        msgSender
                                    }
                                }
                            }
                        }
                    """
                },
                timeout=10.0,
            )
            data = resp.json()
            inputs = data.get("data", {}).get("inputs", {}).get("edges", [])

            print(f"Recent inputs: {len(inputs)}")
            for edge in inputs:
                node = edge.get("node", {})
                print(f"  - Index {node.get('index')}: {node.get('status')} @ {node.get('timestamp')}")


async def main():
    """Run all E2E tests."""
    print("=" * 60)
    print("L{CORE} E2E Test: Pi 5 → EigenCloud")
    print("=" * 60)
    print(f"Attestor: {ATTESTOR_URL}")
    print(f"Cartesi:  {CARTESI_URL}")
    print(f"DApp:     {DAPP_ADDRESS}")

    # Run tests
    await test_health()
    success = await test_submit()

    if success:
        # Wait for Cartesi to process
        print("\n[INFO] Waiting 5s for Cartesi to process...")
        await asyncio.sleep(5)
        await test_query()

    print("\n" + "=" * 60)
    print("E2E Test Complete")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
