"""
DID (Decentralized Identifier) utilities for L{CORE}

Implements did:key with secp256k1 and JWS (JSON Web Signature) for device attestation.
"""

import json
import hashlib
from typing import Optional

import base58
from coincurve import PrivateKey, PublicKey


# Multicodec prefix for secp256k1-pub (0xe7 0x01)
SECP256K1_MULTICODEC = bytes([0xe7, 0x01])


def public_key_to_did_key(public_key: bytes) -> str:
    """
    Convert a secp256k1 compressed public key to a did:key identifier.

    Args:
        public_key: 33-byte compressed secp256k1 public key

    Returns:
        did:key string (e.g., "did:key:zQ3sh...")

    Example:
        >>> from coincurve import PrivateKey
        >>> priv = PrivateKey()
        >>> pub = priv.public_key.format(compressed=True)
        >>> did = public_key_to_did_key(pub)
        >>> did.startswith("did:key:z")
        True
    """
    if len(public_key) != 33:
        raise ValueError(f"Expected 33-byte compressed public key, got {len(public_key)} bytes")

    # Prepend multicodec prefix
    multicodec_key = SECP256K1_MULTICODEC + public_key

    # Encode with base58btc (multibase 'z' prefix)
    encoded = base58.b58encode(multicodec_key).decode("ascii")

    return f"did:key:z{encoded}"


def parse_did_key(did: str) -> Optional[bytes]:
    """
    Parse a did:key identifier to extract the secp256k1 public key.

    Args:
        did: did:key string (e.g., "did:key:zQ3sh...")

    Returns:
        33-byte compressed secp256k1 public key, or None if invalid

    Example:
        >>> pub_key = parse_did_key("did:key:zQ3shv...")
        >>> len(pub_key)
        33
    """
    if not did or not did.startswith("did:key:z"):
        return None

    try:
        # Remove "did:key:z" prefix to get base58btc encoded data
        multibase_key = did[9:]  # len("did:key:z") = 9

        # Decode from base58btc
        decoded = base58.b58decode(multibase_key)

        # Check multicodec prefix (0xe7 0x01 for secp256k1-pub)
        if len(decoded) < 2:
            return None

        if decoded[0] != 0xe7 or decoded[1] != 0x01:
            return None

        # Return the public key (after 2-byte prefix)
        public_key = decoded[2:]

        if len(public_key) != 33:
            return None

        return bytes(public_key)

    except Exception:
        return None


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    import base64
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_jws(payload: dict, private_key: bytes) -> str:
    """
    Create a JWS (JSON Web Signature) compact serialization.

    Uses ES256K algorithm (ECDSA with secp256k1 and SHA-256).

    Args:
        payload: Dictionary to sign
        private_key: 32-byte secp256k1 private key

    Returns:
        JWS compact serialization (header.payload.signature)

    Example:
        >>> priv_key = bytes.fromhex("0" * 64)  # Example key
        >>> jws = create_jws({"temperature": 23.4}, priv_key)
        >>> len(jws.split("."))
        3
    """
    # Create header
    header = {"alg": "ES256K", "typ": "JWS"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())

    # Encode payload
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Create signing input
    signing_input = f"{header_b64}.{payload_b64}"

    # Hash and sign
    message_hash = hashlib.sha256(signing_input.encode()).digest()

    # Sign with coincurve
    priv = PrivateKey(private_key)
    signature = priv.sign_recoverable(message_hash, hasher=None)

    # Extract r and s (first 64 bytes, excluding recovery id)
    sig_bytes = signature[:64]

    # Encode signature
    sig_b64 = _base64url_encode(sig_bytes)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jws(jws: str, payload: dict, public_key: bytes) -> bool:
    """
    Verify a JWS signature against a payload and public key.

    Args:
        jws: JWS compact serialization
        payload: Expected payload dictionary
        public_key: 33-byte compressed secp256k1 public key

    Returns:
        True if signature is valid, False otherwise

    Example:
        >>> priv = PrivateKey()
        >>> pub = priv.public_key.format(compressed=True)
        >>> jws = create_jws({"temp": 23}, priv.secret)
        >>> verify_jws(jws, {"temp": 23}, pub)
        True
    """
    try:
        parts = jws.split(".")
        if len(parts) != 3:
            return False

        header_b64, _, sig_b64 = parts

        # Recreate signing input with the provided payload
        payload_b64 = _base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}"

        # Hash the signing input
        message_hash = hashlib.sha256(signing_input.encode()).digest()

        # Decode signature
        signature = _base64url_decode(sig_b64)

        if len(signature) != 64:
            return False

        # Verify with coincurve
        pub = PublicKey(public_key)

        # Try to verify (coincurve verify needs DER format, so we convert)
        # We need to try both recovery IDs since we don't store it
        for recovery_id in range(4):
            try:
                recoverable_sig = signature + bytes([recovery_id])
                recovered_pub = PublicKey.from_signature_and_message(
                    recoverable_sig, message_hash, hasher=None
                )
                if recovered_pub.format(compressed=True) == public_key:
                    return True
            except Exception:
                continue

        return False

    except Exception:
        return False
