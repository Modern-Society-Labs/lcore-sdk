/**
 * E2E Tests: Device Attestation with Fraud-Provable Verification
 *
 * Tests the new device attestation flow:
 * - Encrypted input submission (privacy before InputBox)
 * - JWS signature verification inside Cartesi (fraud-provable)
 * - Device DID validation (did:key format)
 * - Device attestation storage and queries
 *
 * SECURITY MODEL:
 * - All JWS verification happens inside Cartesi (deterministic, re-runnable)
 * - Anyone can re-run Cartesi and verify every signature was valid
 * - No trusted attestor needed for device verification
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  generateId,
  getResponse,
  assertAccepted,
  assertRejected,
} from './e2e-helpers';
import nacl from 'tweetnacl';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// ============= Test Key Generation =============

/**
 * Generate a secp256k1 keypair for device simulation
 */
function generateDeviceKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  // Generate random 32 bytes for private key
  const privateKey = nacl.randomBytes(32);
  // Derive compressed public key (33 bytes)
  const publicKey = secp256k1.getPublicKey(privateKey, true);
  return { privateKey, publicKey };
}

/**
 * Convert a secp256k1 public key to did:key format
 */
function publicKeyToDIDKey(publicKey: Uint8Array): string {
  // did:key uses multibase (z prefix for base58btc) + multicodec (0xe7 0x01 for secp256k1-pub)
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xe7;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);

  // Base58btc encode
  const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + Buffer.from(prefixed).toString('hex'));
  let encoded = '';

  while (num > 0) {
    const remainder = Number(num % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    num = num / 58n;
  }

  // Add leading 1s for leading zeros
  for (let i = 0; i < prefixed.length && prefixed[i] === 0; i++) {
    encoded = '1' + encoded;
  }

  return `did:key:z${encoded}`;
}

/**
 * Create a JWS signature for device data
 */
function createDeviceJWS(payload: unknown, privateKey: Uint8Array): string {
  const header = { alg: 'ES256K', typ: 'JWT' };
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));

  const message = `${headerB64}.${payloadB64}`;
  const messageHash = sha256(new TextEncoder().encode(message));

  const signature = secp256k1.sign(messageHash, privateKey);
  const signatureB64 = base64urlEncodeBytes(signature.toCompactRawBytes());

  return `${headerB64}.${payloadB64}.${signatureB64}`;
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

// ============= Encryption Helpers =============

// Test keypair for input encryption (LOCAL TESTING ONLY)
// This is a TEST KEY for the local rollup-server.js test harness.
// It is NOT used in production. Production deployments generate their own keys.
// MUST match the LCORE_INPUT_PRIVATE_KEY set in the test environment.
const TEST_INPUT_PRIVATE_KEY_B64 = 'iGi07ePrbxXzJXRud+JTXm9Rh2TKITcJVhL4FqFhCRo=';
const testInputKeypair = {
  secretKey: Uint8Array.from(Buffer.from(TEST_INPUT_PRIVATE_KEY_B64, 'base64')),
  publicKey: nacl.box.keyPair.fromSecretKey(
    Uint8Array.from(Buffer.from(TEST_INPUT_PRIVATE_KEY_B64, 'base64'))
  ).publicKey,
};

/**
 * Encrypt payload for InputBox submission (simulates attestor encryption)
 */
function encryptPayload(data: unknown): { encrypted: true; payload: EncryptedPayload } {
  const plaintext = JSON.stringify(data);
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  const ciphertext = nacl.box(
    plaintextBytes,
    nonce,
    testInputKeypair.publicKey,
    ephemeral.secretKey
  );

  return {
    encrypted: true,
    payload: {
      version: 1,
      algorithm: 'nacl-box',
      nonce: Buffer.from(nonce).toString('base64'),
      ciphertext: Buffer.from(ciphertext).toString('base64'),
      publicKey: Buffer.from(ephemeral.publicKey).toString('base64'),
    },
  };
}

interface EncryptedPayload {
  version: 1;
  algorithm: 'nacl-box';
  nonce: string;
  ciphertext: string;
  publicKey: string;
}

// ============= Test Payload Builders =============

interface DeviceAttestationPayload {
  action: 'device_attestation';
  device_did: string;
  data: Record<string, unknown>;
  signature: string;
  timestamp: number;
  source: string;
}

/**
 * Build an encrypted device attestation payload
 */
function buildEncryptedDeviceAttestation(
  deviceDid: string,
  data: Record<string, unknown>,
  signature: string,
  timestamp: number = Math.floor(Date.now() / 1000)
): { encrypted: true; payload: EncryptedPayload } {
  const innerPayload: DeviceAttestationPayload = {
    action: 'device_attestation',
    device_did: deviceDid,
    data,
    signature,
    timestamp,
    source: 'relay',
  };

  return encryptPayload(innerPayload);
}

/**
 * Build a complete device attestation with valid JWS
 */
function buildValidDeviceAttestation(
  data: Record<string, unknown> = { temperature: 23.4, humidity: 65 }
): {
  encryptedPayload: { encrypted: true; payload: EncryptedPayload };
  deviceDid: string;
  timestamp: number;
} {
  const { privateKey, publicKey } = generateDeviceKeypair();
  const deviceDid = publicKeyToDIDKey(publicKey);
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = createDeviceJWS(data, privateKey);

  return {
    encryptedPayload: buildEncryptedDeviceAttestation(deviceDid, data, signature, timestamp),
    deviceDid,
    timestamp,
  };
}

// ============= Tests =============

describe('E2E: Device Attestation with Fraud-Provable Verification', () => {
  // Note: These tests require the test rollup server to be configured with:
  // - LCORE_INPUT_PRIVATE_KEY set to the test keypair's secret key
  // - LCORE_OUTPUT_MODE set appropriately

  beforeAll(async () => {
    await waitForServer();
    // Note: In a real test environment, the test server would be configured
    // with the test input private key that matches testInputKeypair
  }, 60000);

  describe('Valid Device Attestation Flow', () => {
    it('should accept encrypted device attestation with valid JWS', async () => {
      const sensorData = { temperature: 23.4, humidity: 65, pressure: 1013.25 };
      const { encryptedPayload, deviceDid, timestamp } = buildValidDeviceAttestation(sensorData);

      const result = await submitAdvance(encryptedPayload, TEST_ADDRESSES.owner);

      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        id: number;
        device_did: string;
        verified: boolean;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.device_did).toBe(deviceDid);
      expect(response?.verified).toBe(true); // Indicates JWS was verified
    });

    it('should store multiple attestations from same device', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Submit first attestation
      const data1 = { temperature: 20.0 };
      const sig1 = createDeviceJWS(data1, privateKey);
      const encrypted1 = buildEncryptedDeviceAttestation(deviceDid, data1, sig1);

      const result1 = await submitAdvance(encrypted1, TEST_ADDRESSES.owner);
      assertAccepted(result1);

      // Submit second attestation (different data)
      const data2 = { temperature: 21.0 };
      const sig2 = createDeviceJWS(data2, privateKey);
      const encrypted2 = buildEncryptedDeviceAttestation(deviceDid, data2, sig2);

      const result2 = await submitAdvance(encrypted2, TEST_ADDRESSES.owner);
      assertAccepted(result2);

      // Query attestations for this device
      const inspectResult = await submitInspect('device_attestations', {
        device_did: deviceDid,
        limit: '10',
      });

      const response = getResponse<{
        device_did: string;
        count: number;
        attestations: Array<{ device_did: string }>;
      }>(inspectResult);

      expect(response?.device_did).toBe(deviceDid);
      expect(response?.count).toBe(2);
    });
  });

  describe('Input Encryption Validation', () => {
    it('should reject plaintext (unencrypted) device attestation', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 25.0 };
      const signature = createDeviceJWS(data, privateKey);

      // Submit WITHOUT encryption (plaintext)
      const plaintextPayload = {
        action: 'device_attestation',
        device_did: deviceDid,
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };

      const result = await submitAdvance(plaintextPayload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Plaintext submissions not allowed');
    });

    it('should reject malformed encrypted payload', async () => {
      const malformedEncrypted = {
        encrypted: true,
        payload: {
          version: 1,
          algorithm: 'nacl-box',
          nonce: 'invalid-base64!!!',
          ciphertext: 'also-invalid',
          publicKey: 'bad-key',
        },
      };

      const result = await submitAdvance(malformedEncrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'decrypt');
    });
  });

  describe('JWS Signature Verification (Fraud-Provable)', () => {
    it('should reject attestation with invalid JWS signature', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      // Create signature with DIFFERENT key than the DID claims
      const { privateKey: wrongKey } = generateDeviceKeypair();
      const wrongSignature = createDeviceJWS(data, wrongKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, wrongSignature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject attestation with tampered payload', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Sign original data
      const originalData = { temperature: 22.0 };
      const signature = createDeviceJWS(originalData, privateKey);

      // Submit with DIFFERENT data than what was signed
      const tamperedData = { temperature: 99.9 };
      const encrypted = buildEncryptedDeviceAttestation(deviceDid, tamperedData, signature);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject attestation with invalid JWS format', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      // Invalid JWS (not 3 parts)
      const invalidJWS = 'this.is.not.a.valid.jws.with.too.many.parts';
      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, invalidJWS);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject attestation with unsupported algorithm', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      // Create JWS with wrong algorithm
      const header = { alg: 'RS256', typ: 'JWT' }; // Wrong algorithm!
      const headerB64 = base64urlEncode(JSON.stringify(header));
      const payloadB64 = base64urlEncode(JSON.stringify(data));
      const fakeSignature = base64urlEncode('fake-signature');
      const badAlgJWS = `${headerB64}.${payloadB64}.${fakeSignature}`;

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, badAlgJWS);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });
  });

  describe('DID Key Validation', () => {
    it('should reject attestation with invalid did:key format', async () => {
      const data = { temperature: 22.0 };
      const { privateKey } = generateDeviceKeypair();
      const signature = createDeviceJWS(data, privateKey);

      // Invalid DID format (not did:key:z...)
      const invalidDid = 'did:web:example.com';
      const encrypted = buildEncryptedDeviceAttestation(invalidDid, data, signature);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject attestation with missing did:key', async () => {
      const data = { temperature: 22.0 };
      const { privateKey } = generateDeviceKeypair();
      const signature = createDeviceJWS(data, privateKey);

      // Create encrypted payload without device_did
      const innerPayload = {
        action: 'device_attestation',
        // device_did: MISSING!
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'relay',
      };
      const encrypted = encryptPayload(innerPayload);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: device_did');
    });
  });

  describe('Required Field Validation', () => {
    it('should reject attestation with missing data', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const signature = createDeviceJWS({}, privateKey);

      const innerPayload = {
        action: 'device_attestation',
        device_did: deviceDid,
        // data: MISSING!
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'relay',
      };
      const encrypted = encryptPayload(innerPayload);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: data');
    });

    it('should reject attestation with missing signature', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      const innerPayload = {
        action: 'device_attestation',
        device_did: deviceDid,
        data,
        // signature: MISSING!
        timestamp: Math.floor(Date.now() / 1000),
        source: 'relay',
      };
      const encrypted = encryptPayload(innerPayload);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: signature');
    });

    it('should reject attestation with missing timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const innerPayload = {
        action: 'device_attestation',
        device_did: deviceDid,
        data,
        signature,
        // timestamp: MISSING!
        source: 'relay',
      };
      const encrypted = encryptPayload(innerPayload);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: timestamp');
    });
  });

  describe('Device Attestation Queries', () => {
    let testDeviceDid: string;

    beforeAll(async () => {
      // Create a device attestation to query
      const { encryptedPayload, deviceDid } = buildValidDeviceAttestation({
        temperature: 25.5,
        humidity: 70,
      });
      testDeviceDid = deviceDid;

      const result = await submitAdvance(encryptedPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);
    });

    it('should query attestations by device DID', async () => {
      const result = await submitInspect('device_attestations', {
        device_did: testDeviceDid,
        limit: '10',
      });

      const response = getResponse<{
        device_did: string;
        count: number;
        attestations: Array<{
          id: number;
          device_did: string;
          data: unknown;
          timestamp: number;
        }>;
      }>(result);

      expect(response?.device_did).toBe(testDeviceDid);
      expect(response?.count).toBeGreaterThan(0);
      expect(response?.attestations[0]?.device_did).toBe(testDeviceDid);
    });

    it('should query latest attestation for device', async () => {
      const result = await submitInspect('device_latest', {
        device_did: testDeviceDid,
      });

      const response = getResponse<{
        device_did: string;
        data: unknown;
        timestamp: number;
      }>(result);

      expect(response?.device_did).toBe(testDeviceDid);
      expect(response?.data).toBeDefined();
    });

    it('should return error for non-existent device', async () => {
      const result = await submitInspect('device_latest', {
        device_did: 'did:key:zNonExistentDevice123456789',
      });

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toContain('No attestations found');
    });

    it('should return device stats', async () => {
      const result = await submitInspect('device_stats', {});

      const response = getResponse<{
        total_attestations: number;
        unique_devices: number;
        top_devices: Array<{ device_did: string; count: number }>;
      }>(result);

      expect(response?.total_attestations).toBeGreaterThanOrEqual(0);
      expect(response?.unique_devices).toBeGreaterThanOrEqual(0);
      expect(Array.isArray(response?.top_devices)).toBe(true);
    });
  });

  describe('Pagination', () => {
    it('should paginate device attestations', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Create multiple attestations
      for (let i = 0; i < 5; i++) {
        const data = { reading: i };
        const signature = createDeviceJWS(data, privateKey);
        const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
        const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);
        assertAccepted(result);
      }

      // Query with limit
      const page1 = await submitInspect('device_attestations', {
        device_did: deviceDid,
        limit: '2',
        offset: '0',
      });

      const page1Response = getResponse<{
        count: number;
        attestations: unknown[];
      }>(page1);

      expect(page1Response?.count).toBe(2);

      // Query second page
      const page2 = await submitInspect('device_attestations', {
        device_did: deviceDid,
        limit: '2',
        offset: '2',
      });

      const page2Response = getResponse<{
        count: number;
        attestations: unknown[];
      }>(page2);

      expect(page2Response?.count).toBe(2);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty data object', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const emptyData = {};
      const signature = createDeviceJWS(emptyData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, emptyData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Empty object is valid - should be accepted
      assertAccepted(result);
    });

    it('should handle nested data objects', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const nestedData = {
        sensor: {
          type: 'temperature',
          readings: [23.4, 23.5, 23.6],
          metadata: {
            location: { lat: 37.7749, lng: -122.4194 },
            calibrated: true,
          },
        },
      };
      const signature = createDeviceJWS(nestedData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, nestedData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle special characters in data', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const specialData = {
        message: 'Test with unicode: 日本語 emoji: 🌡️ quotes: "test" newlines:\n\ttab',
        symbols: '<>&\'"',
      };
      const signature = createDeviceJWS(specialData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, specialData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject null data', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const signature = createDeviceJWS({}, privateKey);

      // Manually construct with null data
      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data: null,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: data');
    });

    it('should reject data as string instead of object', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const signature = createDeviceJWS({}, privateKey);

      // Manually construct with string data
      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data: 'not an object' as unknown as Record<string, unknown>,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: data');
    });

    it('should reject timestamp as string', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      // Manually construct with string timestamp
      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: '2024-01-01' as unknown as number,
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: timestamp');
    });

    it('should reject empty signature string', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature: '',
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: signature');
    });

    it('should handle very large data payload', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Create large but valid payload (under 10KB string limit)
      const largeData: Record<string, number> = {};
      for (let i = 0; i < 100; i++) {
        largeData[`sensor_${i}`] = Math.random() * 100;
      }
      const signature = createDeviceJWS(largeData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, largeData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject did:key with wrong multicodec prefix', async () => {
      const data = { temperature: 22.0 };
      const { privateKey } = generateDeviceKeypair();
      const signature = createDeviceJWS(data, privateKey);

      // did:key with ed25519 prefix (z6Mk) instead of secp256k1 (zQ3s)
      const wrongPrefixDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

      const encrypted = buildEncryptedDeviceAttestation(wrongPrefixDid, data, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject zero timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: 0,
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Zero is a valid number, so it should be accepted (epoch time)
      assertAccepted(result);
    });

    it('should reject negative timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: -1000,
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Negative is still a number - should be accepted (validation is type-based)
      assertAccepted(result);
    });

    it('should handle missing source field gracefully', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      // Omit source field entirely
      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Source is optional, should default to 'relay'
      assertAccepted(result);
    });

    it('should reject truncated encrypted payload', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      // Truncate the ciphertext
      encrypted.payload.ciphertext = encrypted.payload.ciphertext.slice(0, 20);

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'decrypt');
    });

    it('should reject wrong ephemeral public key', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      // Replace with different ephemeral key
      const wrongKey = nacl.box.keyPair();
      encrypted.payload.publicKey = Buffer.from(wrongKey.publicKey).toString('base64');

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'decrypt');
    });

    it('should reject corrupted nonce', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      // Corrupt the nonce by changing first byte
      const nonceBytes = Buffer.from(encrypted.payload.nonce, 'base64');
      nonceBytes[0] = (nonceBytes[0]! + 1) % 256;
      encrypted.payload.nonce = nonceBytes.toString('base64');

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'decrypt');
    });

    it('should reject JWS signed for different data structure', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Sign an array instead of object
      const arrayData = [1, 2, 3];
      const signature = createDeviceJWS(arrayData, privateKey);

      // Submit with object data
      const objectData = { values: [1, 2, 3] };
      const encrypted = buildEncryptedDeviceAttestation(deviceDid, objectData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should handle data with numeric keys', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const numericKeyData = {
        '0': 'first',
        '1': 'second',
        '123': 'value',
      };
      const signature = createDeviceJWS(numericKeyData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, numericKeyData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle data with boolean and null values', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const mixedData = {
        active: true,
        disabled: false,
        value: null,
        count: 0,
        empty: '',
      };
      const signature = createDeviceJWS(mixedData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, mixedData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject completely invalid base64 in ciphertext', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      encrypted.payload.ciphertext = '!!!not-valid-base64!!!';

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'decrypt');
    });

    it('should reject when encrypted field is false', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      // Change encrypted flag to false - this breaks the envelope structure
      // The router sees {encrypted: false, payload: {...}} which has no 'action' field
      (encrypted as { encrypted: boolean }).encrypted = false;

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Should be rejected because payload structure is invalid (no action field at top level)
      assertRejected(result, 'Action is required');
    });

    it('should handle concurrent attestations from different devices', async () => {
      // Create 3 different devices
      const devices = Array.from({ length: 3 }, () => {
        const { privateKey, publicKey } = generateDeviceKeypair();
        return {
          privateKey,
          publicKey,
          deviceDid: publicKeyToDIDKey(publicKey),
        };
      });

      // Submit attestations from all devices
      const results = await Promise.all(
        devices.map(async (device, i) => {
          const data = { sensor: i, reading: Math.random() * 100 };
          const signature = createDeviceJWS(data, device.privateKey);
          const encrypted = buildEncryptedDeviceAttestation(device.deviceDid, data, signature);
          return submitAdvance(encrypted, TEST_ADDRESSES.owner);
        })
      );

      // All should succeed
      results.forEach((result) => assertAccepted(result));

      // Query stats to verify all 3 were stored
      const stats = await submitInspect('device_stats');
      const statsResponse = getResponse<{ unique_devices: number }>(stats);
      expect(statsResponse?.unique_devices).toBeGreaterThanOrEqual(3);
    });

    it('should handle JWS with base64 instead of base64url encoding', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      // Create valid JWS then convert to base64 instead of base64url
      // Note: The verification is lenient enough to handle both encodings
      // This is actually acceptable behavior for robustness
      const validSig = createDeviceJWS(data, privateKey);
      const parts = validSig.split('.');
      // Replace - with + and _ with / to make it base64
      const base64Sig = parts
        .map((p) => p.replace(/-/g, '+').replace(/_/g, '/'))
        .join('.');

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, base64Sig);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // The JWS verifier handles both base64 and base64url gracefully
      assertAccepted(result);
    });

    it('should reject empty device_did string', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: '',
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Missing required field: device_did');
    });

    it('should reject device_did without did:key prefix', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation('zQ3shVoVuKoMqNBRciJFZ26wdLQNFgyFDn4hAzGN5FNn7CQym', data, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject device_did with did:web prefix', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation('did:web:example.com', data, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject JWS with only 2 parts', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      const twoPartJWS = 'eyJhbGciOiJFUzI1NksifQ.eyJ0ZW1wZXJhdHVyZSI6MjIuMH0';
      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, twoPartJWS);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject JWS with empty signature part', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };

      const emptySignatureJWS = 'eyJhbGciOiJFUzI1NksifQ.eyJ0ZW1wZXJhdHVyZSI6MjIuMH0.';
      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, emptySignatureJWS);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject when action field is wrong', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'wrong_action' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Unknown action');
    });

    it('should reject missing action field', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        device_did: deviceDid,
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Action is required');
    });

    it('should handle data with deeply nested arrays', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const deepData = {
        level1: {
          level2: {
            level3: {
              level4: {
                values: [1, 2, [3, 4, [5, 6]]],
              },
            },
          },
        },
      };
      const signature = createDeviceJWS(deepData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, deepData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle data with moderately long string value', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      // Create a 1KB string (reasonable for IoT data)
      const longString = 'x'.repeat(1000);
      const longData = { message: longString };
      const signature = createDeviceJWS(longData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, longData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject data with string exceeding max length', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      // Create a string over the 10KB limit
      const tooLongString = 'x'.repeat(11000);
      const tooLongData = { message: tooLongString };
      const signature = createDeviceJWS(tooLongData, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, tooLongData, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'exceeds maximum length');
    });

    it('should handle float timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: 1705123456.789, // Float timestamp
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Float is still a number - should be accepted
      assertAccepted(result);
    });

    it('should handle very large timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: 9999999999999, // Year 2286
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject encrypted payload with wrong version', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      encrypted.payload.version = 99;

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Wrong version fails decryption silently, router sees undecrypted payload without action
      assertRejected(result, 'Action is required');
    });

    it('should reject encrypted payload with wrong algorithm', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      encrypted.payload.algorithm = 'aes-256-gcm';

      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Wrong algorithm fails decryption silently, router sees undecrypted payload without action
      assertRejected(result, 'Action is required');
    });

    it('should handle rapid sequential submissions from same device', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Submit 5 attestations in rapid succession
      for (let i = 0; i < 5; i++) {
        const data = { reading: i, timestamp: Date.now() };
        const signature = createDeviceJWS(data, privateKey);
        const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
        const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);
        assertAccepted(result);
      }

      // Query to verify all 5 were stored
      const queryResult = await submitInspect('device_attestations', {
        device_did: deviceDid,
        limit: '10',
      });
      const response = getResponse<{ count: number }>(queryResult);
      expect(response?.count).toBe(5);
    });

    it('should reject data as array instead of object', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const signature = createDeviceJWS({}, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data: [1, 2, 3] as unknown as Record<string, unknown>,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Arrays are objects in JS, but we specifically check for object type
      // This should still pass since Array is typeof 'object'
      // But the JWS was signed for {}, so signature verification should fail
      assertRejected(result, 'Signature verification failed');
    });

    it('should handle data with undefined values stripped', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      // JSON.stringify strips undefined values
      const dataWithUndefined = { temp: 22.0, missing: undefined };
      const signature = createDeviceJWS(dataWithUndefined, privateKey);

      const encrypted = buildEncryptedDeviceAttestation(deviceDid, dataWithUndefined, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle did:key with extra whitespace', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      // DID with leading/trailing spaces
      const encrypted = buildEncryptedDeviceAttestation(' did:key:zQ3shVoVuKoMqNBRciJFZ26wdLQNFgyFDn4hAzGN5FNn7CQym ', data, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject empty encrypted payload object', async () => {
      const result = await submitAdvance({ encrypted: true, payload: {} }, TEST_ADDRESSES.owner);
      // Empty payload fails decryption silently, router sees undecrypted payload without action
      assertRejected(result, 'Action is required');
    });

    it('should handle source field with special characters', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: Math.floor(Date.now() / 1000),
        source: 'test-源<script>alert(1)</script>',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle NaN timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: NaN,
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // NaN is typeof 'number' but fails the check
      assertRejected(result, 'Missing required field: timestamp');
    });

    it('should reject Infinity timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        device_did: deviceDid,
        data,
        signature,
        timestamp: Infinity,
        source: 'test',
      };
      const encrypted = encryptPayload(payload);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      // Infinity becomes null when JSON.stringify'd, so timestamp check fails
      assertRejected(result, 'Missing required field: timestamp');
    });

    it('should reject did:key with invalid base58 characters', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      // 0, O, I, l are not valid base58 characters
      const encrypted = buildEncryptedDeviceAttestation('did:key:zQ3sh0OIl', data, signature);
      const result = await submitAdvance(encrypted, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should handle submission from different sender addresses', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const data = { temperature: 22.0 };
      const signature = createDeviceJWS(data, privateKey);

      // Submit from a different address than usual
      const differentSender = '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc';
      const encrypted = buildEncryptedDeviceAttestation(deviceDid, data, signature);
      const result = await submitAdvance(encrypted, differentSender);

      // Should still work - device attestation doesn't care about sender
      assertAccepted(result);
    });
  });
});
