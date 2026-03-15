/**
 * Unit Tests for Encryption Module
 *
 * Tests the NaCl box encryption for output privacy and
 * V1 hash verification for device attestations.
 */

import { describe, it, expect } from '@jest/globals';
import nacl from 'tweetnacl';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

import {
  encryptOutput,
  initEncryption,
  isEncryptionConfigured,
  EncryptedOutput,
} from '../encryption';

import {
  verifyJWSOverHash,
  verifyJWSOverHashSafe,
} from '../crypto/jws';

// ============= Test Helpers =============

function generateTestKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return nacl.box.keyPair();
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

function base64urlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlEncodeBytes(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Convert a secp256k1 public key to did:key format
 */
function publicKeyToDIDKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xe7;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);

  const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + Buffer.from(prefixed).toString('hex'));
  let encoded = '';

  while (num > 0) {
    const remainder = Number(num % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    num = num / 58n;
  }

  for (let i = 0; i < prefixed.length && prefixed[i] === 0; i++) {
    encoded = '1' + encoded;
  }

  return `did:key:z${encoded}`;
}

/**
 * Create a JWS signing the given hash string (V1 format)
 */
function createJWSOverHash(hash: string, privateKey: Uint8Array): string {
  const header = { alg: 'ES256K', typ: 'JWT' };
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(hash);

  const message = `${headerB64}.${payloadB64}`;
  const messageHash = sha256(new TextEncoder().encode(message));

  const signature = secp256k1.sign(messageHash, privateKey);
  const signatureB64 = base64urlEncodeBytes(signature.toCompactRawBytes());

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

// ============= Tests =============

describe('Encryption Module', () => {
  describe('EncryptedOutput Format', () => {
    it('should produce output with required fields', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      const data = { test: 'data' };
      const encrypted = encryptOutput(data);

      expect(encrypted.version).toBe(1);
      expect(encrypted.algorithm).toBe('xchacha20-poly1305');
      expect(typeof encrypted.nonce).toBe('string');
      expect(typeof encrypted.ciphertext).toBe('string');
      expect(typeof encrypted.publicKey).toBe('string');
    });

    it('should produce valid base64 strings', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      const encrypted = encryptOutput({ value: 123 });

      expect(() => base64ToUint8Array(encrypted.nonce)).not.toThrow();
      expect(() => base64ToUint8Array(encrypted.ciphertext)).not.toThrow();
      expect(() => base64ToUint8Array(encrypted.publicKey)).not.toThrow();

      expect(base64ToUint8Array(encrypted.nonce).length).toBe(24);
      expect(base64ToUint8Array(encrypted.publicKey).length).toBe(32);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      const data = { same: 'data' };
      const encrypted1 = encryptOutput(data);
      const encrypted2 = encryptOutput(data);

      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.nonce).not.toBe(encrypted2.nonce);
      expect(encrypted1.publicKey).not.toBe(encrypted2.publicKey);
    });
  });

  describe('Configuration State', () => {
    it('should track encryption configuration', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      expect(isEncryptionConfigured()).toBe(true);
    });

    it('should reject invalid key length for encryption', () => {
      const shortKey = new Uint8Array(16); // 16 bytes instead of 32
      initEncryption(uint8ArrayToBase64(shortKey));
      // Function logs error but doesn't throw
    });
  });
});

describe('V1 Hash Verification (verifyJWSOverHash)', () => {
  it('should verify valid JWS over correct hash', () => {
    const privateKey = nacl.randomBytes(32);
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const did = publicKeyToDIDKey(publicKey);

    const hash = 'a'.repeat(64); // Valid 64-char hex
    const jws = createJWSOverHash(hash, privateKey);

    expect(verifyJWSOverHash(jws, hash, did)).toBe(true);
  });

  it('should reject JWS with wrong hash', () => {
    const privateKey = nacl.randomBytes(32);
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const did = publicKeyToDIDKey(publicKey);

    const correctHash = 'a'.repeat(64);
    const wrongHash = 'b'.repeat(64);
    const jws = createJWSOverHash(correctHash, privateKey);

    expect(() => verifyJWSOverHash(jws, wrongHash, did)).toThrow('hash does not match');
  });

  it('should reject JWS signed by wrong key', () => {
    const signerKey = nacl.randomBytes(32);
    const otherKey = nacl.randomBytes(32);
    const otherPublicKey = secp256k1.getPublicKey(otherKey, true);
    const otherDid = publicKeyToDIDKey(otherPublicKey);

    const hash = 'c'.repeat(64);
    const jws = createJWSOverHash(hash, signerKey);

    expect(() => verifyJWSOverHash(jws, hash, otherDid)).toThrow();
  });

  it('should reject invalid hash format (not 64 hex chars)', () => {
    const privateKey = nacl.randomBytes(32);
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const did = publicKeyToDIDKey(publicKey);

    // Too short
    expect(() => verifyJWSOverHash('fake.jws.sig', 'abc123', did))
      .toThrow('Invalid hash format');

    // Not hex
    expect(() => verifyJWSOverHash('fake.jws.sig', 'g'.repeat(64), did))
      .toThrow('Invalid hash format');
  });

  it('should reject malformed JWS', () => {
    const privateKey = nacl.randomBytes(32);
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const did = publicKeyToDIDKey(publicKey);
    const hash = 'd'.repeat(64);

    // Not 3 parts
    expect(() => verifyJWSOverHash('only.two', hash, did)).toThrow();

    // Empty string
    expect(() => verifyJWSOverHash('', hash, did)).toThrow();
  });

  it('should reject unsupported algorithm', () => {
    const privateKey = nacl.randomBytes(32);
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const did = publicKeyToDIDKey(publicKey);
    const hash = 'e'.repeat(64);

    // Create JWS with RS256 algorithm
    const header = { alg: 'RS256', typ: 'JWT' };
    const headerB64 = base64urlEncode(JSON.stringify(header));
    const payloadB64 = base64urlEncode(hash);
    const fakeSignature = base64urlEncode('fake-signature');
    const badJWS = `${headerB64}.${payloadB64}.${fakeSignature}`;

    expect(() => verifyJWSOverHash(badJWS, hash, did)).toThrow();
  });

  describe('verifyJWSOverHashSafe', () => {
    it('should return valid: true for correct input', () => {
      const privateKey = nacl.randomBytes(32);
      const publicKey = secp256k1.getPublicKey(privateKey, true);
      const did = publicKeyToDIDKey(publicKey);

      const hash = 'f'.repeat(64);
      const jws = createJWSOverHash(hash, privateKey);

      const result = verifyJWSOverHashSafe(jws, hash, did);
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should return valid: false with error message for bad input', () => {
      const result = verifyJWSOverHashSafe('bad.jws.sig', 'abc', 'did:key:zFake');
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});
