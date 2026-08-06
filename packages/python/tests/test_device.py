"""
Tests for DeviceIdentity class
"""

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from lcore.device import DeviceIdentity
from lcore.did import (
    canonicalize_payload,
    parse_did_key,
    verify_jws,
    verify_jws_over_hash,
)


class TestDeviceIdentityGenerate:
    """Tests for DeviceIdentity.generate()."""

    def test_generates_valid_identity(self):
        """Should generate a valid device identity."""
        device = DeviceIdentity.generate()

        assert device.did.startswith("did:key:z")
        assert len(device.private_key) == 32
        assert len(device.public_key) == 33

    def test_generates_unique_identities(self):
        """Each call should generate a unique identity."""
        device1 = DeviceIdentity.generate()
        device2 = DeviceIdentity.generate()

        assert device1.did != device2.did
        assert device1.private_key != device2.private_key


class TestDeviceIdentityFromPrivateKey:
    """Tests for DeviceIdentity.from_private_key()."""

    def test_creates_from_valid_key(self):
        """Should create identity from valid private key."""
        key = bytes.fromhex("ab" * 32)
        device = DeviceIdentity.from_private_key(key)

        assert device.did.startswith("did:key:z")
        assert device.private_key == key

    def test_same_key_produces_same_did(self):
        """Same private key should always produce same DID."""
        key = bytes.fromhex("cd" * 32)

        device1 = DeviceIdentity.from_private_key(key)
        device2 = DeviceIdentity.from_private_key(key)

        assert device1.did == device2.did

    def test_rejects_invalid_key_length(self):
        """Should reject keys that aren't 32 bytes."""
        with pytest.raises(ValueError):
            DeviceIdentity.from_private_key(b"too short")

        with pytest.raises(ValueError):
            DeviceIdentity.from_private_key(b"x" * 64)


class TestDeviceIdentityFromHex:
    """Tests for DeviceIdentity.from_hex()."""

    def test_creates_from_hex_string(self):
        """Should create identity from hex string."""
        hex_key = "ab" * 32
        device = DeviceIdentity.from_hex(hex_key)

        assert device.did.startswith("did:key:z")
        assert device.private_key == bytes.fromhex(hex_key)

    def test_handles_0x_prefix(self):
        """Should handle 0x prefix."""
        hex_key = "cd" * 32
        device = DeviceIdentity.from_hex("0x" + hex_key)

        assert device.private_key == bytes.fromhex(hex_key)


class TestDeviceIdentitySign:
    """Tests for DeviceIdentity.sign()."""

    def test_signs_payload(self):
        """Should sign payload and return submission data."""
        device = DeviceIdentity.generate()
        payload = {"temperature": 23.4}

        result = device.sign(payload)

        assert "did" in result
        assert "payload" in result
        assert "signature" in result
        assert "timestamp" in result
        assert "salt" in result

        assert result["did"] == device.did
        assert result["payload"] == payload
        assert isinstance(result["timestamp"], int)
        # Per-submission salt: 16 random bytes as lowercase hex
        assert len(result["salt"]) == 32
        int(result["salt"], 16)  # raises if not hex

    def test_salt_is_unique_per_submission(self):
        """Each signature must use a fresh salt, or the hash is replayable."""
        device = DeviceIdentity.generate()
        salts = {device.sign({"temperature": 23.4})["salt"] for _ in range(5)}
        assert len(salts) == 5

    def test_signature_is_verifiable(self):
        """Signature should be verifiable with public key."""
        device = DeviceIdentity.generate()
        payload = {"temperature": 23.4, "humidity": 65}

        result = device.sign(payload)

        # sign() signs the salted data_hash, NOT the raw payload:
        #   data_hash = sha256(JCS(payload) + did + timestamp + salt)
        combined = (
            canonicalize_payload(payload)
            + device.did
            + str(result["timestamp"])
            + result["salt"]
        )
        data_hash = hashlib.sha256(combined.encode()).hexdigest()

        is_valid = verify_jws_over_hash(
            result["signature"], data_hash, device.public_key
        )
        assert is_valid is True

    def test_timestamp_is_recent(self):
        """Timestamp should be recent (within 5 seconds)."""
        import time

        device = DeviceIdentity.generate()
        result = device.sign({"temp": 23.4})

        now = int(time.time())
        assert abs(result["timestamp"] - now) < 5


class TestDeviceIdentitySaveLoad:
    """Tests for save() and load() methods."""

    def test_save_and_load(self):
        """Should save and load identity correctly."""
        device = DeviceIdentity.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "device.json"
            device.save(str(path))

            loaded = DeviceIdentity.load(str(path))

        assert loaded.did == device.did
        assert loaded.private_key == device.private_key
        assert loaded.public_key == device.public_key

    def test_saved_file_format(self):
        """Saved file should be valid JSON."""
        device = DeviceIdentity.generate()

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "device.json"
            device.save(str(path))

            with open(path) as f:
                data = json.load(f)

        assert "private_key" in data
        assert "did" in data
        assert data["did"] == device.did


class TestDeviceIdentityToHex:
    """Tests for to_hex() method."""

    def test_exports_as_hex(self):
        """Should export private key as hex string."""
        key_hex = "ef" * 32
        device = DeviceIdentity.from_hex(key_hex)

        result = device.to_hex()

        assert result == key_hex
        assert len(result) == 64


class TestDeviceIdentityIntegration:
    """Integration tests for DeviceIdentity."""

    def test_did_can_be_parsed(self):
        """Generated DID should be parseable."""
        device = DeviceIdentity.generate()

        parsed_pub = parse_did_key(device.did)

        assert parsed_pub == device.public_key

    def test_full_workflow(self):
        """Complete device workflow should work."""
        # Generate device
        device = DeviceIdentity.generate()

        # Sign multiple payloads
        payload1 = {"temperature": 23.4}
        payload2 = {"humidity": 65}

        signed1 = device.sign(payload1)
        signed2 = device.sign(payload2)

        # Signatures are over the salted data_hash, not the raw payload
        def data_hash(payload, signed):
            combined = (
                canonicalize_payload(payload)
                + device.did
                + str(signed["timestamp"])
                + signed["salt"]
            )
            return hashlib.sha256(combined.encode()).hexdigest()

        assert verify_jws_over_hash(
            signed1["signature"], data_hash(payload1, signed1), device.public_key
        )
        assert verify_jws_over_hash(
            signed2["signature"], data_hash(payload2, signed2), device.public_key
        )

        # Cross-verification must fail: signature 1 does not cover payload 2
        assert not verify_jws_over_hash(
            signed1["signature"], data_hash(payload2, signed2), device.public_key
        )
