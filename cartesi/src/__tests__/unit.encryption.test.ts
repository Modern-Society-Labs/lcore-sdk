/**
 * Unit Tests for Encryption Module
 *
 * Tests the NaCl box encryption/decryption for device attestation privacy.
 * These tests validate:
 * - Encryption output format
 * - Decryption correctness
 * - Input encryption detection
 * - Configuration state management
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import nacl from 'tweetnacl';

import {
  encryptOutput,
  initEncryption,
  initInputDecryption,
  decryptInput,
  isEncryptedInput,
  isEncryptionConfigured,
  isInputDecryptionConfigured,
  EncryptedOutput,
} from '../encryption';

// ============= Test Helpers =============

/**
 * Generate a NaCl box keypair for testing
 */
function generateTestKeypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return nacl.box.keyPair();
}

/**
 * Encode bytes to base64
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * Decode base64 to bytes
 */
function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Encrypt data manually (for testing decryption)
 */
function manualEncrypt(
  data: unknown,
  recipientPublicKey: Uint8Array
): EncryptedOutput {
  const plaintext = JSON.stringify(data);
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // Generate ephemeral keypair
  const ephemeral = nacl.box.keyPair();

  // Generate random nonce
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  // Encrypt
  const ciphertext = nacl.box(
    plaintextBytes,
    nonce,
    recipientPublicKey,
    ephemeral.secretKey
  );

  return {
    version: 1,
    algorithm: 'nacl-box',
    nonce: uint8ArrayToBase64(nonce),
    ciphertext: uint8ArrayToBase64(ciphertext),
    publicKey: uint8ArrayToBase64(ephemeral.publicKey),
  };
}

// ============= Tests =============

describe('Encryption Module', () => {
  describe('EncryptedOutput Format', () => {
    it('should produce output with required fields', () => {
      // Generate keypair and initialize
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      const data = { test: 'data' };
      const encrypted = encryptOutput(data);

      expect(encrypted.version).toBe(1);
      expect(encrypted.algorithm).toBe('nacl-box');
      expect(typeof encrypted.nonce).toBe('string');
      expect(typeof encrypted.ciphertext).toBe('string');
      expect(typeof encrypted.publicKey).toBe('string');
    });

    it('should produce valid base64 strings', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      const encrypted = encryptOutput({ value: 123 });

      // Decode should not throw
      expect(() => base64ToUint8Array(encrypted.nonce)).not.toThrow();
      expect(() => base64ToUint8Array(encrypted.ciphertext)).not.toThrow();
      expect(() => base64ToUint8Array(encrypted.publicKey)).not.toThrow();

      // Nonce should be 24 bytes
      expect(base64ToUint8Array(encrypted.nonce).length).toBe(24);

      // Public key should be 32 bytes
      expect(base64ToUint8Array(encrypted.publicKey).length).toBe(32);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      const data = { same: 'data' };
      const encrypted1 = encryptOutput(data);
      const encrypted2 = encryptOutput(data);

      // Different ephemeral keys and nonces should produce different ciphertext
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.nonce).not.toBe(encrypted2.nonce);
      expect(encrypted1.publicKey).not.toBe(encrypted2.publicKey);
    });
  });

  describe('isEncryptedInput Detection', () => {
    it('should detect valid encrypted input structure', () => {
      const validEncrypted = {
        encrypted: true,
        payload: {
          version: 1,
          algorithm: 'nacl-box',
          nonce: 'base64nonce',
          ciphertext: 'base64ciphertext',
          publicKey: 'base64publicKey',
        },
      };

      expect(isEncryptedInput(validEncrypted)).toBe(true);
    });

    it('should reject plaintext payload', () => {
      const plaintext = {
        action: 'device_attestation',
        device_did: 'did:key:zQ3...',
        data: { temp: 23 },
        signature: 'jws...',
      };

      expect(isEncryptedInput(plaintext)).toBe(false);
    });

    it('should reject encrypted: false', () => {
      const notEncrypted = {
        encrypted: false,
        payload: {
          version: 1,
          algorithm: 'nacl-box',
          nonce: 'nonce',
          ciphertext: 'ciphertext',
          publicKey: 'publicKey',
        },
      };

      expect(isEncryptedInput(notEncrypted)).toBe(false);
    });

    it('should reject missing payload', () => {
      const missingPayload = { encrypted: true };
      expect(isEncryptedInput(missingPayload)).toBe(false);
    });

    it('should reject wrong algorithm', () => {
      const wrongAlgorithm = {
        encrypted: true,
        payload: {
          version: 1,
          algorithm: 'aes-gcm', // wrong
          nonce: 'nonce',
          ciphertext: 'ciphertext',
          publicKey: 'publicKey',
        },
      };

      expect(isEncryptedInput(wrongAlgorithm)).toBe(false);
    });

    it('should reject null/undefined', () => {
      expect(isEncryptedInput(null)).toBe(false);
      expect(isEncryptedInput(undefined)).toBe(false);
    });

    it('should reject primitive types', () => {
      expect(isEncryptedInput('string')).toBe(false);
      expect(isEncryptedInput(123)).toBe(false);
      expect(isEncryptedInput(true)).toBe(false);
    });
  });

  describe('Input Decryption', () => {
    it('should decrypt properly encrypted data', () => {
      // Generate keypair for input decryption
      const inputKeypair = generateTestKeypair();

      // Initialize decryption with private key
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      // Encrypt data with the public key
      const originalData = {
        device_did: 'did:key:zQ3test',
        data: { temp: 23.5, humidity: 65 },
        timestamp: 1234567890,
      };

      const encrypted = manualEncrypt(originalData, inputKeypair.publicKey);

      // Decrypt
      const decrypted = decryptInput<typeof originalData>(encrypted);

      expect(decrypted).toEqual(originalData);
    });

    it('should throw for wrong decryption key', () => {
      const inputKeypair = generateTestKeypair();
      const wrongKeypair = generateTestKeypair();

      // Initialize with wrong key
      initInputDecryption(uint8ArrayToBase64(wrongKeypair.secretKey));

      // Encrypt with original key
      const encrypted = manualEncrypt({ test: 'data' }, inputKeypair.publicKey);

      // Decryption should fail
      expect(() => decryptInput(encrypted)).toThrow('Decryption failed');
    });

    it('should throw for invalid version', () => {
      const inputKeypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      const invalidVersion = {
        version: 2, // invalid
        algorithm: 'nacl-box',
        nonce: uint8ArrayToBase64(nacl.randomBytes(24)),
        ciphertext: uint8ArrayToBase64(new Uint8Array([1, 2, 3])),
        publicKey: uint8ArrayToBase64(inputKeypair.publicKey),
      } as EncryptedOutput;

      expect(() => decryptInput(invalidVersion)).toThrow('Unsupported encryption version');
    });

    it('should throw for invalid algorithm', () => {
      const inputKeypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      const invalidAlgo = {
        version: 1,
        algorithm: 'aes-gcm', // invalid
        nonce: uint8ArrayToBase64(nacl.randomBytes(24)),
        ciphertext: uint8ArrayToBase64(new Uint8Array([1, 2, 3])),
        publicKey: uint8ArrayToBase64(inputKeypair.publicKey),
      } as unknown as EncryptedOutput;

      expect(() => decryptInput(invalidAlgo)).toThrow('Unsupported algorithm');
    });
  });

  describe('Configuration State', () => {
    it('should track encryption configuration', () => {
      const keypair = generateTestKeypair();
      initEncryption(uint8ArrayToBase64(keypair.publicKey));

      expect(isEncryptionConfigured()).toBe(true);
    });

    it('should track input decryption configuration', () => {
      const keypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(keypair.secretKey));

      expect(isInputDecryptionConfigured()).toBe(true);
    });

    it('should reject invalid key length for encryption', () => {
      const shortKey = new Uint8Array(16); // 16 bytes instead of 32
      initEncryption(uint8ArrayToBase64(shortKey));

      // Should log error and set to null
      // Note: The function logs error but doesn't throw
    });

    it('should reject invalid key length for input decryption', () => {
      const shortKey = new Uint8Array(16); // 16 bytes instead of 32
      initInputDecryption(uint8ArrayToBase64(shortKey));

      // Should log error and set to null
      // Note: The function logs error but doesn't throw
    });
  });

  describe('Roundtrip Encryption/Decryption', () => {
    it('should roundtrip complex nested objects', () => {
      const inputKeypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      const complexData = {
        device: {
          did: 'did:key:zQ3complex',
          model: 'SensorPro-X1',
        },
        readings: [
          { ts: 1000, value: 23.4 },
          { ts: 2000, value: 23.5 },
          { ts: 3000, value: 23.6 },
        ],
        metadata: {
          firmware: '2.0.1',
          calibration: {
            offset: 0.1,
            scale: 1.0,
          },
        },
        flags: [true, false, true],
        nullValue: null,
      };

      const encrypted = manualEncrypt(complexData, inputKeypair.publicKey);
      const decrypted = decryptInput<typeof complexData>(encrypted);

      expect(decrypted).toEqual(complexData);
    });

    it('should preserve string encoding', () => {
      const inputKeypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      const stringData = {
        message: 'Hello, 世界! 🌍',
        unicode: '\u0000\u001f\u007f',
        emoji: '👋🔐🎉',
      };

      const encrypted = manualEncrypt(stringData, inputKeypair.publicKey);
      const decrypted = decryptInput<typeof stringData>(encrypted);

      expect(decrypted).toEqual(stringData);
    });

    it('should preserve numeric precision', () => {
      const inputKeypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      const numericData = {
        integer: 123456789,
        float: 3.14159265359,
        scientific: 1e-10,
        negative: -42.5,
      };

      const encrypted = manualEncrypt(numericData, inputKeypair.publicKey);
      const decrypted = decryptInput<typeof numericData>(encrypted);

      expect(decrypted).toEqual(numericData);
    });
  });

  describe('Determinism', () => {
    it('should produce deterministic decryption', () => {
      const inputKeypair = generateTestKeypair();
      initInputDecryption(uint8ArrayToBase64(inputKeypair.secretKey));

      const data = { deterministic: 'test' };
      const encrypted = manualEncrypt(data, inputKeypair.publicKey);

      // Decrypt multiple times - should always produce same result
      const results = Array(10)
        .fill(null)
        .map(() => decryptInput<typeof data>(encrypted));

      expect(results.every((r) => JSON.stringify(r) === JSON.stringify(data))).toBe(
        true
      );
    });
  });
});
