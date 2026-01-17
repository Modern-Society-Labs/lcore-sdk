"""
Tests for DID utilities
"""

import pytest
from coincurve import PrivateKey

from lcore.did import (
    public_key_to_did_key,
    parse_did_key,
    create_jws,
    verify_jws,
)


class TestPublicKeyToDIDKey:
    """Tests for public_key_to_did_key function."""

    def test_creates_valid_did_key(self):
        """Should create a valid did:key from public key."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)

        did = public_key_to_did_key(pub)

        assert did.startswith("did:key:z")
        assert len(did) > 20

    def test_different_keys_produce_different_dids(self):
        """Different keys should produce different DIDs."""
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        pub1 = priv1.public_key.format(compressed=True)
        pub2 = priv2.public_key.format(compressed=True)

        did1 = public_key_to_did_key(pub1)
        did2 = public_key_to_did_key(pub2)

        assert did1 != did2

    def test_rejects_invalid_key_length(self):
        """Should reject keys that aren't 33 bytes."""
        with pytest.raises(ValueError):
            public_key_to_did_key(b"too short")

        with pytest.raises(ValueError):
            public_key_to_did_key(b"x" * 65)


class TestParseDIDKey:
    """Tests for parse_did_key function."""

    def test_parses_valid_did_key(self):
        """Should parse a valid did:key back to public key."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)
        did = public_key_to_did_key(pub)

        parsed = parse_did_key(did)

        assert parsed == pub

    def test_rejects_did_web(self):
        """Should reject did:web format."""
        result = parse_did_key("did:web:example.com")
        assert result is None

    def test_rejects_did_ethr(self):
        """Should reject did:ethr format."""
        result = parse_did_key("did:ethr:0x1234567890abcdef")
        assert result is None

    def test_rejects_malformed_did(self):
        """Should reject malformed did:key."""
        assert parse_did_key("did:key:invalid!!!") is None
        assert parse_did_key("did:key:") is None
        assert parse_did_key("") is None
        assert parse_did_key("not-a-did") is None

    def test_rejects_empty_string(self):
        """Should reject empty string."""
        assert parse_did_key("") is None

    def test_roundtrip(self):
        """Should successfully roundtrip key -> DID -> key."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)

        did = public_key_to_did_key(pub)
        parsed = parse_did_key(did)

        assert parsed == pub


class TestCreateJWS:
    """Tests for create_jws function."""

    def test_creates_valid_jws_format(self):
        """JWS should have three dot-separated parts."""
        priv = PrivateKey()
        payload = {"temperature": 23.4}

        jws = create_jws(payload, priv.secret)

        parts = jws.split(".")
        assert len(parts) == 3
        assert all(len(p) > 0 for p in parts)

    def test_different_payloads_produce_different_signatures(self):
        """Different payloads should produce different JWS."""
        priv = PrivateKey()

        jws1 = create_jws({"temp": 23.4}, priv.secret)
        jws2 = create_jws({"temp": 99.9}, priv.secret)

        assert jws1 != jws2

    def test_different_keys_produce_different_signatures(self):
        """Different keys should produce different JWS."""
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        payload = {"temp": 23.4}

        jws1 = create_jws(payload, priv1.secret)
        jws2 = create_jws(payload, priv2.secret)

        assert jws1 != jws2


class TestVerifyJWS:
    """Tests for verify_jws function."""

    def test_verifies_valid_signature(self):
        """Should verify a valid signature."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)
        payload = {"temperature": 23.4, "humidity": 65}

        jws = create_jws(payload, priv.secret)
        result = verify_jws(jws, payload, pub)

        assert result is True

    def test_rejects_tampered_payload(self):
        """Should reject if payload was tampered."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)
        original = {"temperature": 23.4}
        tampered = {"temperature": 99.9}

        jws = create_jws(original, priv.secret)
        result = verify_jws(jws, tampered, pub)

        assert result is False

    def test_rejects_wrong_public_key(self):
        """Should reject if public key doesn't match."""
        priv1 = PrivateKey()
        priv2 = PrivateKey()
        pub2 = priv2.public_key.format(compressed=True)
        payload = {"temperature": 23.4}

        jws = create_jws(payload, priv1.secret)
        result = verify_jws(jws, payload, pub2)

        assert result is False

    def test_rejects_malformed_jws(self):
        """Should reject malformed JWS strings."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)
        payload = {"temperature": 23.4}

        assert verify_jws("not-a-jws", payload, pub) is False
        assert verify_jws("a.b", payload, pub) is False
        assert verify_jws("", payload, pub) is False

    def test_handles_complex_payloads(self):
        """Should handle nested and complex payloads."""
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)
        payload = {
            "sensors": {
                "temperature": 23.4,
                "humidity": 65,
            },
            "metadata": {
                "location": [37.7749, -122.4194],
                "tags": ["indoor", "office"],
            },
        }

        jws = create_jws(payload, priv.secret)
        result = verify_jws(jws, payload, pub)

        assert result is True


class TestRoundTrip:
    """End-to-end roundtrip tests."""

    def test_full_sign_verify_cycle(self):
        """Complete sign-verify cycle should work."""
        # Generate keypair
        priv = PrivateKey()
        pub = priv.public_key.format(compressed=True)

        # Create DID
        did = public_key_to_did_key(pub)
        assert did.startswith("did:key:z")

        # Parse DID back
        parsed_pub = parse_did_key(did)
        assert parsed_pub == pub

        # Sign payload
        payload = {"temperature": 23.4}
        jws = create_jws(payload, priv.secret)

        # Verify with parsed public key
        result = verify_jws(jws, payload, parsed_pub)
        assert result is True
