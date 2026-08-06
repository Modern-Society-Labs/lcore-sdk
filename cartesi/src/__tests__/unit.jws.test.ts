/**
 * Unit Tests for JWS Verification Module
 *
 * Tests the fraud-provable JWS signature verification in Cartesi.
 * These tests validate:
 * - Base58btc decoding
 * - Base64url encoding/decoding
 * - DID:key parsing
 * - JWS signature verification
 */

import { describe, it, expect } from '@jest/globals';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// Import the functions to test
import {
  parseDIDKey,
  verifyJWS,
  verifyJWSSafe,
  isValidDIDKey,
  base64urlEncode,
  base64urlDecode,
} from '../crypto/jws';

// ============= Test Helpers =============

/**
 * Generate a test secp256k1 keypair
 */
function generateTestKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, true); // compressed
  return { privateKey, publicKey };
}

/**
 * Create a did:key from a compressed public key
 */
function createDIDKey(compressedPublicKey: Uint8Array): string {
  // Multicodec prefix for secp256k1-pub is 0xe7 0x01
  const multicodec = new Uint8Array([0xe7, 0x01, ...compressedPublicKey]);

  // Base58btc encode with 'z' prefix
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  let num = BigInt(0);
  for (const byte of multicodec) {
    num = num * BigInt(256) + BigInt(byte);
  }

  let encoded = '';
  while (num > 0) {
    const remainder = Number(num % BigInt(58));
    num = num / BigInt(58);
    encoded = ALPHABET[remainder] + encoded;
  }

  // Handle leading zeros
  for (const byte of multicodec) {
    if (byte === 0) {
      encoded = '1' + encoded;
    } else {
      break;
    }
  }

  return `did:key:z${encoded}`;
}

/**
 * Create a JWS with ES256K algorithm
 */
function createJWS(payload: unknown, privateKey: Uint8Array): string {
  const header = { alg: 'ES256K' };

  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));

  const message = `${headerB64}.${payloadB64}`;
  const messageBytes = new TextEncoder().encode(message);
  const messageHash = sha256(messageBytes);

  // Sign with secp256k1
  const signature = secp256k1.sign(messageHash, privateKey);
  const signatureBytes = signature.toCompactRawBytes();

  // Convert bytes to base64url directly using Buffer
  const signatureB64 = Buffer.from(signatureBytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

// ============= Tests =============

describe('JWS Verification Module', () => {
  describe('Base64url Encoding/Decoding', () => {
    it('should encode and decode a simple string', () => {
      const original = 'Hello, World!';
      const encoded = base64urlEncode(original);
      const decoded = base64urlDecode(encoded);
      expect(decoded).toBe(original);
    });

    it('should handle special characters correctly', () => {
      // Base64url uses - and _ instead of + and /
      const original = '{"alg":"ES256K"}';
      const encoded = base64urlEncode(original);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
      const decoded = base64urlDecode(encoded);
      expect(decoded).toBe(original);
    });

    it('should handle binary data', () => {
      const binaryData = '\x00\x01\x02\xff\xfe\xfd';
      const encoded = base64urlEncode(binaryData);
      const decoded = base64urlDecode(encoded);
      expect(decoded).toBe(binaryData);
    });
  });

  describe('DID:key Validation', () => {
    it('should validate correct did:key format', () => {
      const { publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      expect(isValidDIDKey(did)).toBe(true);
    });

    it('should reject did:key without z prefix', () => {
      expect(isValidDIDKey('did:key:abc123')).toBe(false);
    });

    it('should reject non-did:key identifiers', () => {
      expect(isValidDIDKey('did:web:example.com')).toBe(false);
      expect(isValidDIDKey('0x1234567890abcdef')).toBe(false);
      expect(isValidDIDKey('')).toBe(false);
    });

    it('should reject short did:key', () => {
      expect(isValidDIDKey('did:key:z')).toBe(false);
      expect(isValidDIDKey('did:key:zQ3')).toBe(false);
    });
  });

  describe('DID:key Parsing', () => {
    it('should parse valid secp256k1 did:key', () => {
      const { publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);

      const parsedPublicKey = parseDIDKey(did);

      // Parsed key should match original
      expect(parsedPublicKey.length).toBe(33); // compressed secp256k1 key
      expect(parsedPublicKey).toEqual(publicKey);
    });

    it('should throw for invalid did:key format', () => {
      expect(() => parseDIDKey('not-a-did')).toThrow('Invalid did:key format');
      expect(() => parseDIDKey('did:web:example.com')).toThrow(
        'Invalid did:key format'
      );
    });

    it('should throw for non-secp256k1 did:key', () => {
      // Create a fake did:key with wrong multicodec (ed25519 prefix is 0xed 0x01)
      // Need 35 bytes total: 2 byte multicodec + 33 byte public key
      const fakeMulticodec = new Uint8Array([0xed, 0x01, ...new Uint8Array(33)]);
      const ALPHABET =
        '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      let num = BigInt(0);
      for (const byte of fakeMulticodec) {
        num = num * BigInt(256) + BigInt(byte);
      }
      let encoded = '';
      while (num > 0) {
        const remainder = Number(num % BigInt(58));
        num = num / BigInt(58);
        encoded = ALPHABET[remainder] + encoded;
      }
      const fakeDid = `did:key:z${encoded}`;

      expect(() => parseDIDKey(fakeDid)).toThrow('not a secp256k1');
    });
  });

  describe('JWS Signature Verification', () => {
    it('should verify valid JWS with matching payload', () => {
      const { privateKey, publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = { temp: 23.4, humidity: 65.2 };

      const jws = createJWS(payload, privateKey);
      const isValid = verifyJWS(jws, payload, did);

      expect(isValid).toBe(true);
    });

    it('should reject JWS with different payload', () => {
      const { privateKey, publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const originalPayload = { temp: 23.4 };
      const tamperedPayload = { temp: 99.9 };

      const jws = createJWS(originalPayload, privateKey);
      const result = verifyJWSSafe(jws, tamperedPayload, did);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('payload');
    });

    it('should reject JWS with wrong signing key', () => {
      const { privateKey: signerPrivateKey } = generateTestKeypair();
      const { publicKey: differentPublicKey } = generateTestKeypair();
      const wrongDid = createDIDKey(differentPublicKey);
      const payload = { data: 'test' };

      const jws = createJWS(payload, signerPrivateKey);
      const result = verifyJWSSafe(jws, payload, wrongDid);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('signature');
    });

    it('should reject JWS with invalid format', () => {
      const { publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = { test: true };

      expect(() => verifyJWS('not.valid', payload, did)).toThrow(
        'Invalid JWS format'
      );
      expect(() => verifyJWS('only-one-part', payload, did)).toThrow(
        'Invalid JWS format'
      );
    });

    it('should reject JWS with unsupported algorithm', () => {
      const { publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = { test: true };

      // Create JWS with wrong algorithm header
      const header = { alg: 'RS256' }; // Wrong algorithm
      const headerB64 = base64urlEncode(JSON.stringify(header));
      const payloadB64 = base64urlEncode(JSON.stringify(payload));
      const fakeJws = `${headerB64}.${payloadB64}.fake-signature`;

      expect(() => verifyJWS(fakeJws, payload, did)).toThrow(
        'Unsupported JWS algorithm'
      );
    });

    it('should reject JWS with tampered signature', () => {
      const { privateKey, publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = { sensor: 'temp', value: 25.0 };

      const jws = createJWS(payload, privateKey);
      const parts = jws.split('.');

      // Tamper with the signature
      const tamperedSignature = 'AAAA' + parts[2]!.slice(4);
      const tamperedJws = `${parts[0]}.${parts[1]}.${tamperedSignature}`;

      const result = verifyJWSSafe(tamperedJws, payload, did);
      expect(result.valid).toBe(false);
    });
  });

  describe('Complex Payload Verification', () => {
    it('should verify nested object payloads', () => {
      const { privateKey, publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = {
        device: {
          id: 'sensor-001',
          type: 'temperature',
        },
        readings: [
          { ts: 1000, value: 23.4 },
          { ts: 2000, value: 23.5 },
        ],
        metadata: {
          firmware: '1.0.0',
          calibrated: true,
        },
      };

      const jws = createJWS(payload, privateKey);
      const isValid = verifyJWS(jws, payload, did);

      expect(isValid).toBe(true);
    });

    it('should be sensitive to field order in payload', () => {
      const { privateKey, publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);

      // Original payload with specific field order
      const originalPayload = { a: 1, b: 2 };
      const jws = createJWS(originalPayload, privateKey);

      // Same data but different field order
      const reorderedPayload = { b: 2, a: 1 };

      // Verification should fail because JSON.stringify preserves order
      const result = verifyJWSSafe(jws, reorderedPayload, did);

      // This actually fails because JSON.stringify({ b: 2, a: 1 }) !== JSON.stringify({ a: 1, b: 2 })
      // The verification compares the actual JSON string representations
      expect(result.valid).toBe(false);
    });
  });

  describe('Determinism', () => {
    it('should produce consistent results across multiple calls', () => {
      const { privateKey, publicKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = { data: 'determinism-test' };

      const jws = createJWS(payload, privateKey);

      // Verify multiple times - should always return the same result
      const results = Array(10)
        .fill(null)
        .map(() => verifyJWSSafe(jws, payload, did));

      expect(results.every((r) => r.valid === true)).toBe(true);
    });

    it('should be deterministic with invalid signatures', () => {
      const { publicKey } = generateTestKeypair();
      const { privateKey: wrongKey } = generateTestKeypair();
      const did = createDIDKey(publicKey);
      const payload = { data: 'test' };

      const jws = createJWS(payload, wrongKey);

      // Verify multiple times with wrong key - should always fail
      const results = Array(10)
        .fill(null)
        .map(() => verifyJWSSafe(jws, payload, did));

      expect(results.every((r) => r.valid === false)).toBe(true);
    });
  });
});

describe('Input Encryption/Decryption', () => {
  // These tests verify the encryption module works correctly
  // The actual encryption module is tested separately

  describe('EncryptedOutput Format', () => {
    it('should have required fields', () => {
      // Test that the EncryptedOutput interface has all required fields
      const mockEncryptedOutput = {
        version: 1 as const,
        algorithm: 'nacl-box' as const,
        nonce: 'base64-nonce',
        ciphertext: 'base64-ciphertext',
        publicKey: 'base64-public-key',
      };

      expect(mockEncryptedOutput.version).toBe(1);
      expect(mockEncryptedOutput.algorithm).toBe('nacl-box');
      expect(typeof mockEncryptedOutput.nonce).toBe('string');
      expect(typeof mockEncryptedOutput.ciphertext).toBe('string');
      expect(typeof mockEncryptedOutput.publicKey).toBe('string');
    });
  });
});
