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


def _jcs_number(value):
    """
    Serialize a number the way RFC 8785 (JCS) requires — i.e. the way ECMAScript
    Number::toString does, which is what the attestor's canonicalizer produces.

    Python's json.dumps does NOT match in two common cases:

        100.0   -> Python "100.0",  JavaScript "100"
        1e-7    -> Python "1e-07",  JavaScript "1e-7"

    The first matters a great deal in practice: a whole-number sensor reading
    (humidity 100.0, temperature 20.0) would otherwise hash differently on Python
    than on the attestor and be rejected with a 401.
    """
    if isinstance(value, bool):  # bool is a subclass of int — must come first
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity cannot be serialized as canonical JSON")

    # ECMAScript prints integral values without a fractional part, up to 1e21
    # where it switches to exponential form.
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))

    out = repr(float(value))

    # Normalize the exponent: Python zero-pads ("1e-07"), ECMAScript does not.
    if "e" in out:
        mantissa, exponent = out.split("e", 1)
        sign = ""
        if exponent[0] in "+-":
            sign, exponent = exponent[0], exponent[1:]
        exponent = exponent.lstrip("0") or "0"
        # ECMAScript keeps an explicit '+' on positive exponents
        out = f"{mantissa}e{sign if sign else '+'}{exponent}"

    return out


def _jcs_serialize(value) -> str:
    """Recursively serialize a value to RFC 8785 canonical JSON."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_jcs_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        # JCS sorts object keys by their UTF-16 code units
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + _jcs_serialize(v)
            for k, v in items
        ) + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def canonicalize_payload(payload: dict) -> str:
    """
    Produce RFC 8785 (JCS) canonical JSON for hashing.

    This byte-matches the attestor's canonicalizer, so the device and the attestor
    compute the same data_hash. Number formatting follows ECMAScript rules — see
    _jcs_number for why Python's json.dumps is not sufficient on its own.
    """
    return _jcs_serialize(payload)


def create_jws_over_hash(hash_hex: str, private_key: bytes) -> str:
    """
    Create a JWS (ES256K) whose payload segment is a raw hash string.

    The device signs the deterministic data_hash directly — this is what the
    attestor's verifyJWSOverHash checks — NOT the raw payload object.

    Args:
        hash_hex: The data_hash string to sign (64-char hex)
        private_key: 32-byte secp256k1 private key

    Returns:
        JWS compact serialization (header.payload.signature)
    """
    header = {"alg": "ES256K", "typ": "JWT"}
    header_b64 = _base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _base64url_encode(hash_hex.encode())

    signing_input = f"{header_b64}.{payload_b64}"
    message_hash = hashlib.sha256(signing_input.encode()).digest()

    priv = PrivateKey(private_key)
    signature = priv.sign_recoverable(message_hash, hasher=None)
    sig_bytes = signature[:64]  # r||s (coincurve emits low-s), drop recovery id
    sig_b64 = _base64url_encode(sig_bytes)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_jws_over_hash(jws: str, hash_hex: str, public_key: bytes) -> bool:
    """
    Verify a JWS whose payload segment is a raw hash string.

    This is the counterpart to create_jws_over_hash, and mirrors the attestor's
    verifyJWSOverHash: device submissions sign the deterministic data_hash, not
    the raw payload object.

    Args:
        jws: JWS compact serialization
        hash_hex: The expected data_hash (64-char hex)
        public_key: 33-byte compressed secp256k1 public key

    Returns:
        True if the signature is valid for that hash, False otherwise
    """
    try:
        parts = jws.split(".")
        if len(parts) != 3:
            return False

        header_b64, payload_b64, sig_b64 = parts

        # The payload segment must be exactly the expected hash
        if payload_b64 != _base64url_encode(hash_hex.encode()):
            return False

        signing_input = f"{header_b64}.{payload_b64}"
        message_hash = hashlib.sha256(signing_input.encode()).digest()

        signature = _base64url_decode(sig_b64)
        if len(signature) != 64:
            return False

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
