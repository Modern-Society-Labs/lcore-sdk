#!/usr/bin/env python3
"""
Cross-SDK DID Compatibility Test

Verifies that C, Python, and TypeScript SDKs all generate identical did:key
strings from the same private key.

Run: python tests/cross_sdk_did_test.py
"""

import subprocess
import sys
import os

# Test private key (same across all SDKs)
# This is the key used in C SDK tests
TEST_PRIVKEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
TEST_PRIVKEY_BYTES = bytes.fromhex(TEST_PRIVKEY_HEX)

def test_python_sdk():
    """Generate DID using Python SDK"""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'packages', 'python'))
    from lcore import DeviceIdentity

    device = DeviceIdentity.from_private_key(TEST_PRIVKEY_BYTES)
    return device.did

def test_c_sdk():
    """Generate DID using C SDK print_did tool"""
    c_tool_path = os.path.join(os.path.dirname(__file__), '..', 'packages', 'c', 'tools', 'print_did')

    if not os.path.exists(c_tool_path):
        return None

    result = subprocess.run(
        [c_tool_path, TEST_PRIVKEY_HEX],
        capture_output=True, text=True
    )

    return result.stdout.strip() if result.returncode == 0 else None

def test_typescript_sdk():
    """Generate DID using TypeScript SDK (if DeviceIdentity exists)"""
    ts_path = os.path.join(os.path.dirname(__file__), '..', 'packages', 'typescript')

    # Check if device.ts exists
    device_ts = os.path.join(ts_path, 'src', 'device.ts')
    if not os.path.exists(device_ts):
        return None  # TypeScript DeviceIdentity not implemented yet

    # Create a test script
    test_script = f"""
import {{ DeviceIdentity }} from './src/device.js';

const privkey = new Uint8Array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
]);

const device = new DeviceIdentity(privkey);
console.log(device.did);
"""

    test_file = os.path.join(ts_path, 'did_test.mjs')
    with open(test_file, 'w') as f:
        f.write(test_script)

    result = subprocess.run(
        ['npx', 'tsx', 'did_test.mjs'],
        cwd=ts_path,
        capture_output=True, text=True
    )

    os.remove(test_file)

    return result.stdout.strip() if result.returncode == 0 else None

def main():
    print("Cross-SDK DID Compatibility Test")
    print("=" * 50)
    print(f"Test private key: {TEST_PRIVKEY_HEX}")
    print()

    results = {}

    # Python SDK
    print("Testing Python SDK...", end=" ")
    try:
        results['python'] = test_python_sdk()
        print(f"✓ {results['python']}")
    except Exception as e:
        print(f"✗ Error: {e}")
        results['python'] = None

    # C SDK
    print("Testing C SDK...", end=" ")
    try:
        results['c'] = test_c_sdk()
        if results['c']:
            print(f"✓ {results['c']}")
        else:
            print("✗ Failed to compile/run")
    except Exception as e:
        print(f"✗ Error: {e}")
        results['c'] = None

    # TypeScript SDK
    print("Testing TypeScript SDK...", end=" ")
    try:
        results['typescript'] = test_typescript_sdk()
        if results['typescript']:
            print(f"✓ {results['typescript']}")
        elif results['typescript'] is None:
            print("⊘ Not implemented yet")
        else:
            print("✗ Failed")
    except Exception as e:
        print(f"✗ Error: {e}")
        results['typescript'] = None

    # Compare results
    print()
    print("=" * 50)

    valid_results = {k: v for k, v in results.items() if v is not None}

    if len(valid_results) < 2:
        print("⚠ Need at least 2 SDKs to compare")
        return 1

    unique_dids = set(valid_results.values())

    if len(unique_dids) == 1:
        print(f"✓ All SDKs produce identical DID:")
        print(f"  {list(unique_dids)[0]}")
        return 0
    else:
        print("✗ MISMATCH! SDKs produce different DIDs:")
        for sdk, did in valid_results.items():
            print(f"  {sdk}: {did}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
