"""
Device identity management for L{CORE}

Provides DeviceIdentity class for generating and managing device credentials.
"""

import os
import json
import time
from dataclasses import dataclass
from typing import Optional

from coincurve import PrivateKey

from .did import public_key_to_did_key, create_jws


@dataclass
class DeviceIdentity:
    """
    Represents a device identity with did:key and signing capabilities.

    Use DeviceIdentity.generate() to create a new identity or
    DeviceIdentity.from_private_key() to restore from existing key.

    Example:
        >>> device = DeviceIdentity.generate()
        >>> print(device.did)
        did:key:zQ3sh...

        >>> # Sign sensor data
        >>> signed = device.sign({"temperature": 23.4})
        >>> print(signed["signature"][:20])
        eyJhbGciOiJFUzI1Nksi...
    """

    private_key: bytes
    public_key: bytes
    did: str

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        """
        Generate a new random device identity.

        Returns:
            New DeviceIdentity with random secp256k1 keypair

        Example:
            >>> device = DeviceIdentity.generate()
            >>> device.did.startswith("did:key:z")
            True
        """
        private_key = os.urandom(32)
        return cls.from_private_key(private_key)

    @classmethod
    def from_private_key(cls, private_key: bytes) -> "DeviceIdentity":
        """
        Create a DeviceIdentity from an existing private key.

        Args:
            private_key: 32-byte secp256k1 private key

        Returns:
            DeviceIdentity with the given private key

        Example:
            >>> key = bytes.fromhex("abcd" * 16)
            >>> device = DeviceIdentity.from_private_key(key)
            >>> device.did.startswith("did:key:z")
            True
        """
        if len(private_key) != 32:
            raise ValueError(f"Private key must be 32 bytes, got {len(private_key)}")

        priv = PrivateKey(private_key)
        public_key = priv.public_key.format(compressed=True)
        did = public_key_to_did_key(public_key)

        return cls(
            private_key=private_key,
            public_key=public_key,
            did=did,
        )

    @classmethod
    def from_hex(cls, hex_key: str) -> "DeviceIdentity":
        """
        Create a DeviceIdentity from a hex-encoded private key.

        Args:
            hex_key: 64-character hex string (with or without 0x prefix)

        Returns:
            DeviceIdentity with the given private key

        Example:
            >>> device = DeviceIdentity.from_hex("0x" + "ab" * 32)
            >>> device.did.startswith("did:key:z")
            True
        """
        if hex_key.startswith("0x"):
            hex_key = hex_key[2:]
        return cls.from_private_key(bytes.fromhex(hex_key))

    def sign(self, payload: dict) -> dict:
        """
        Sign a payload and return submission-ready data.

        Args:
            payload: Sensor data dictionary to sign

        Returns:
            Dictionary with did, payload, signature, and timestamp

        Example:
            >>> device = DeviceIdentity.generate()
            >>> signed = device.sign({"temperature": 23.4})
            >>> signed.keys()
            dict_keys(['did', 'payload', 'signature', 'timestamp'])
        """
        signature = create_jws(payload, self.private_key)
        timestamp = int(time.time())

        return {
            "did": self.did,
            "payload": payload,
            "signature": signature,
            "timestamp": timestamp,
        }

    def to_hex(self) -> str:
        """
        Export private key as hex string.

        Returns:
            64-character hex string (without 0x prefix)

        Example:
            >>> device = DeviceIdentity.generate()
            >>> len(device.to_hex())
            64
        """
        return self.private_key.hex()

    def save(self, path: str) -> None:
        """
        Save device identity to a JSON file.

        Args:
            path: File path to save to

        Example:
            >>> device = DeviceIdentity.generate()
            >>> device.save("/tmp/device.json")
        """
        data = {
            "private_key": self.to_hex(),
            "did": self.did,
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "DeviceIdentity":
        """
        Load device identity from a JSON file.

        Args:
            path: File path to load from

        Returns:
            DeviceIdentity loaded from file

        Example:
            >>> device = DeviceIdentity.load("/tmp/device.json")
            >>> device.did.startswith("did:key:z")
            True
        """
        with open(path) as f:
            data = json.load(f)
        return cls.from_hex(data["private_key"])
