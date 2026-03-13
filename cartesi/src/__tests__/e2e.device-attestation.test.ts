/**
 * E2E Tests: Device Attestation with Fraud-Provable Verification (V1 Format)
 *
 * Tests the V1 device attestation flow:
 * - V1 submission format: data_hash + encrypted_data + JWS over hash
 * - JWS signature verification over hash inside Cartesi (fraud-provable)
 * - Device DID validation (did:key format)
 * - Device attestation storage and queries
 *
 * SECURITY MODEL:
 * - Node stores encrypted blobs + salted hashes WITHOUT decrypting
 * - JWS verification is over the data_hash (not plaintext data)
 * - Anyone can re-run Cartesi and verify every signature was valid
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  getResponse,
  assertAccepted,
  assertRejected,
  bootstrapAdmin,
} from './e2e-helpers';
import canonicalize from 'canonicalize';
import nacl from 'tweetnacl';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

// ============= Test Key Generation =============

function generateDeviceKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = nacl.randomBytes(32);
  const publicKey = secp256k1.getPublicKey(privateKey, true);
  return { privateKey, publicKey };
}

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

// ============= V1 Helpers =============

/**
 * Compute salted hash using RFC 8785 JCS (matches attestor's computeDataHash)
 */
function computeDataHash(data: unknown, salt: Uint8Array): string {
  const canonical = typeof data === 'string' ? data : canonicalize(data);
  const saltBase64 = Buffer.from(salt).toString('base64');
  const combined = canonical + saltBase64;
  const hash = sha256(new TextEncoder().encode(combined));
  return bytesToHex(hash);
}

/**
 * Create a JWS signing the hash string (V1 format)
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
 * Build a V1 device attestation payload
 */
interface V1DevicePayload {
  action: 'device_attestation';
  data_hash: string;
  jws: string;
  encrypted_data: string;
  device_did: string;
  timestamp: number;
  encryption_key_id: string;
  source?: string;
}

function buildV1DeviceAttestation(
  deviceDid: string,
  data: Record<string, unknown>,
  privateKey: Uint8Array,
  timestamp: number = Math.floor(Date.now() / 1000)
): V1DevicePayload {
  // Generate salt
  const salt = nacl.randomBytes(16);

  // Compute salted hash
  const dataHash = computeDataHash(data, salt);

  // Create JWS over hash
  const jws = createJWSOverHash(dataHash, privateKey);

  // Create dummy encrypted data (node doesn't decrypt)
  // In production, this would be NaCl box encrypted { data, salt }
  const dummyEncrypted = Buffer.from(JSON.stringify({ data, salt: Buffer.from(salt).toString('base64') })).toString('base64');

  return {
    action: 'device_attestation',
    data_hash: dataHash,
    jws,
    encrypted_data: dummyEncrypted,
    device_did: deviceDid,
    timestamp,
    encryption_key_id: 'lcore_key_v1',
    source: 'relay',
  };
}

/**
 * Build a V1 payload with a pre-made JWS (for testing wrong signatures)
 */
function buildV1WithJWS(
  deviceDid: string,
  dataHash: string,
  jws: string,
  timestamp: number = Math.floor(Date.now() / 1000)
): V1DevicePayload {
  return {
    action: 'device_attestation',
    data_hash: dataHash,
    jws,
    encrypted_data: Buffer.from('dummy-encrypted-data').toString('base64'),
    device_did: deviceDid,
    timestamp,
    encryption_key_id: 'lcore_key_v1',
    source: 'relay',
  };
}

// ============= Tests =============

describe('E2E: Device Attestation V1 Format', () => {
  beforeAll(async () => {
    await waitForServer();
  }, 60000);

  describe('Valid Device Attestation Flow', () => {
    it('should accept V1 device attestation with valid JWS over hash', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const sensorData = { temperature: 23.4, humidity: 65, pressure: 1013.25 };

      const payload = buildV1DeviceAttestation(deviceDid, sensorData, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        id: number;
        device_did: string;
        verified: boolean;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.device_did).toBe(deviceDid);
      expect(response?.verified).toBe(true);
    });

    it('should store multiple attestations from same device', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const result1 = await submitAdvance(
        buildV1DeviceAttestation(deviceDid, { temperature: 20.0 }, privateKey),
        TEST_ADDRESSES.owner
      );
      assertAccepted(result1);

      const result2 = await submitAdvance(
        buildV1DeviceAttestation(deviceDid, { temperature: 21.0 }, privateKey),
        TEST_ADDRESSES.owner
      );
      assertAccepted(result2);

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

  describe('V1 Hash Validation', () => {
    it('should reject malformed data_hash (not 64 hex chars)', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload: V1DevicePayload = {
        action: 'device_attestation',
        data_hash: 'too-short',
        jws: 'fake.jws.sig',
        encrypted_data: Buffer.from('test').toString('base64'),
        device_did: deviceDid,
        timestamp: Math.floor(Date.now() / 1000),
        encryption_key_id: 'lcore_key_v1',
        source: 'relay',
      };

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Invalid data_hash');
    });

    it('should reject when JWS signs wrong hash', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Compute correct hash
      const data = { temperature: 22.0 };
      const salt = nacl.randomBytes(16);
      const correctHash = computeDataHash(data, salt);

      // Sign a DIFFERENT hash
      const wrongHash = 'a'.repeat(64);
      const jws = createJWSOverHash(wrongHash, privateKey);

      const payload = buildV1WithJWS(deviceDid, correctHash, jws);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'hash does not match');
    });
  });

  describe('JWS Signature Verification (Fraud-Provable)', () => {
    it('should reject attestation with JWS signed by wrong key', async () => {
      const { publicKey } = generateDeviceKeypair();
      const { privateKey: wrongKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const data = { temperature: 22.0 };
      const salt = nacl.randomBytes(16);
      const dataHash = computeDataHash(data, salt);

      // Sign with WRONG key
      const jws = createJWSOverHash(dataHash, wrongKey);
      const payload = buildV1WithJWS(deviceDid, dataHash, jws);

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Signature verification failed');
    });

    it('should reject attestation with invalid JWS format', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const dataHash = 'a'.repeat(64);

      const payload = buildV1WithJWS(deviceDid, dataHash, 'this.is.not.a.valid.jws.with.too.many.parts');
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject attestation with unsupported algorithm', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const dataHash = 'a'.repeat(64);

      const header = { alg: 'RS256', typ: 'JWT' };
      const headerB64 = base64urlEncode(JSON.stringify(header));
      const payloadB64 = base64urlEncode(dataHash);
      const fakeSignature = base64urlEncode('fake-signature');
      const badAlgJWS = `${headerB64}.${payloadB64}.${fakeSignature}`;

      const payload = buildV1WithJWS(deviceDid, dataHash, badAlgJWS);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });
  });

  describe('DID Key Validation', () => {
    it('should reject attestation with invalid did:key format', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };

      const payload = buildV1DeviceAttestation('did:web:example.com', data, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject attestation with missing did:key', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };
      const salt = nacl.randomBytes(16);
      const dataHash = computeDataHash(data, salt);
      const jws = createJWSOverHash(dataHash, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        data_hash: dataHash,
        jws,
        encrypted_data: Buffer.from('test').toString('base64'),
        // device_did: MISSING!
        timestamp: Math.floor(Date.now() / 1000),
        encryption_key_id: 'lcore_key_v1',
        source: 'relay',
      };

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Missing required field: device_did');
    });
  });

  describe('Required Field Validation', () => {
    it('should reject attestation with missing data_hash', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = {
        action: 'device_attestation' as const,
        // data_hash: MISSING!
        jws: 'fake.jws.sig',
        encrypted_data: Buffer.from('test').toString('base64'),
        device_did: deviceDid,
        timestamp: Math.floor(Date.now() / 1000),
        encryption_key_id: 'lcore_key_v1',
        source: 'relay',
      };

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'data_hash');
    });

    it('should reject attestation with missing jws', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = {
        action: 'device_attestation' as const,
        data_hash: 'a'.repeat(64),
        // jws: MISSING!
        encrypted_data: Buffer.from('test').toString('base64'),
        device_did: deviceDid,
        timestamp: Math.floor(Date.now() / 1000),
        encryption_key_id: 'lcore_key_v1',
        source: 'relay',
      };

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'jws');
    });

    it('should reject attestation with missing encrypted_data', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const salt = nacl.randomBytes(16);
      const dataHash = computeDataHash({ temp: 22 }, salt);
      const jws = createJWSOverHash(dataHash, privateKey);

      const payload = {
        action: 'device_attestation' as const,
        data_hash: dataHash,
        jws,
        // encrypted_data: MISSING!
        device_did: deviceDid,
        timestamp: Math.floor(Date.now() / 1000),
        encryption_key_id: 'lcore_key_v1',
        source: 'relay',
      };

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'encrypted_data');
    });

    it('should reject attestation with missing timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(deviceDid, { temp: 22 }, privateKey);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (payload as any).timestamp;

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Missing required field: timestamp');
    });
  });

  describe('Device Attestation Queries', () => {
    let testDeviceDid: string;

    beforeAll(async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      testDeviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(testDeviceDid, {
        temperature: 25.5,
        humidity: 70,
      }, privateKey);

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
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
          data_hash: string;
          encrypted_data: string;
          jws: string;
          encryption_key_id: string;
          timestamp: number;
        }>;
      }>(result);

      expect(response?.device_did).toBe(testDeviceDid);
      expect(response?.count).toBeGreaterThan(0);
      expect(response?.attestations[0]?.device_did).toBe(testDeviceDid);
      // V1: verify stored fields
      expect(response?.attestations[0]?.data_hash).toBeDefined();
      expect(response?.attestations[0]?.encrypted_data).toBeDefined();
      expect(response?.attestations[0]?.jws).toBeDefined();
      expect(response?.attestations[0]?.encryption_key_id).toBeDefined();
    });

    it('should query latest attestation for device', async () => {
      const result = await submitInspect('device_latest', {
        device_did: testDeviceDid,
      });

      const response = getResponse<{
        device_did: string;
        data_hash: string;
        encrypted_data: string;
        timestamp: number;
      }>(result);

      expect(response?.device_did).toBe(testDeviceDid);
      expect(response?.data_hash).toBeDefined();
      expect(response?.encrypted_data).toBeDefined();
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

      for (let i = 0; i < 5; i++) {
        const payload = buildV1DeviceAttestation(deviceDid, { reading: i }, privateKey);
        const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
        assertAccepted(result);
      }

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

      const payload = buildV1DeviceAttestation(deviceDid, {}, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

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

      const payload = buildV1DeviceAttestation(deviceDid, nestedData, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle special characters in data', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const specialData = {
        message: 'Test with unicode: 日本語 emoji: 🌡️ quotes: "test" newlines:\n\ttab',
        symbols: '<>&\'"',
      };

      const payload = buildV1DeviceAttestation(deviceDid, specialData, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject did:key with wrong multicodec prefix', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };

      const wrongPrefixDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
      const payload = buildV1DeviceAttestation(wrongPrefixDid, data, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should handle zero timestamp', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(deviceDid, { temp: 22 }, privateKey, 0);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle concurrent attestations from different devices', async () => {
      const devices = Array.from({ length: 3 }, () => {
        const { privateKey, publicKey } = generateDeviceKeypair();
        return {
          privateKey,
          deviceDid: publicKeyToDIDKey(publicKey),
        };
      });

      const results = await Promise.all(
        devices.map(async (device, i) => {
          const payload = buildV1DeviceAttestation(
            device.deviceDid,
            { sensor: i, reading: Math.random() * 100 },
            device.privateKey
          );
          return submitAdvance(payload, TEST_ADDRESSES.owner);
        })
      );

      results.forEach((result) => assertAccepted(result));

      const stats = await submitInspect('device_stats');
      const statsResponse = getResponse<{ unique_devices: number }>(stats);
      expect(statsResponse?.unique_devices).toBeGreaterThanOrEqual(3);
    });

    it('should handle rapid sequential submissions from same device', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      for (let i = 0; i < 5; i++) {
        const payload = buildV1DeviceAttestation(
          deviceDid,
          { reading: i, timestamp: Date.now() },
          privateKey
        );
        const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
        assertAccepted(result);
      }

      const queryResult = await submitInspect('device_attestations', {
        device_did: deviceDid,
        limit: '10',
      });
      const response = getResponse<{ count: number }>(queryResult);
      expect(response?.count).toBe(5);
    });

    it('should handle submission from different sender addresses', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(deviceDid, { temperature: 22.0 }, privateKey);
      const differentSender = '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc';
      const result = await submitAdvance(payload, differentSender);

      assertAccepted(result);
    });

    it('should reject when action field is wrong', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(deviceDid, { temp: 22 }, privateKey);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (payload as any).action = 'wrong_action';

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Unknown action');
    });

    it('should reject missing action field', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(deviceDid, { temp: 22 }, privateKey);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (payload as any).action;

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Action is required');
    });

    it('should reject empty device_did string', async () => {
      const { privateKey } = generateDeviceKeypair();
      const salt = nacl.randomBytes(16);
      const dataHash = computeDataHash({ temp: 22 }, salt);
      const jws = createJWSOverHash(dataHash, privateKey);

      const payload: V1DevicePayload = {
        action: 'device_attestation',
        data_hash: dataHash,
        jws,
        encrypted_data: Buffer.from('test').toString('base64'),
        device_did: '',
        timestamp: Math.floor(Date.now() / 1000),
        encryption_key_id: 'lcore_key_v1',
        source: 'relay',
      };

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'Missing required field: device_did');
    });

    it('should reject device_did without did:key prefix', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };

      const payload = buildV1DeviceAttestation('zQ3shVoVuKoMqNBRciJFZ26wdLQNFgyFDn4hAzGN5FNn7CQym', data, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should reject JWS with only 2 parts', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const dataHash = 'a'.repeat(64);

      const twoPartJWS = 'eyJhbGciOiJFUzI1NksifQ.eyJ0ZW1wZXJhdHVyZSI6MjIuMH0';
      const payload = buildV1WithJWS(deviceDid, dataHash, twoPartJWS);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
    });

    it('should reject JWS with empty signature part', async () => {
      const { publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const dataHash = 'a'.repeat(64);

      const emptySignatureJWS = 'eyJhbGciOiJFUzI1NksifQ.eyJ0ZW1wZXJhdHVyZSI6MjIuMH0.';
      const payload = buildV1WithJWS(deviceDid, dataHash, emptySignatureJWS);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Signature verification failed');
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

      const payload = buildV1DeviceAttestation(deviceDid, mixedData, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should handle deeply nested arrays', async () => {
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

      const payload = buildV1DeviceAttestation(deviceDid, deepData, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertAccepted(result);
    });

    it('should reject did:key with invalid base58 characters', async () => {
      const { privateKey } = generateDeviceKeypair();
      const data = { temperature: 22.0 };

      // 0, O, I, l are not valid base58 characters
      const payload = buildV1DeviceAttestation('did:key:zQ3sh0OIl', data, privateKey);
      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);

      assertRejected(result, 'Invalid device_did format');
    });

    it('should handle missing encryption_key_id', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const payload = buildV1DeviceAttestation(deviceDid, { temp: 22 }, privateKey);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      delete (payload as any).encryption_key_id;

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertRejected(result, 'encryption_key_id');
    });
  });

  describe('Key Rotation', () => {
    it('should rotate encryption key (admin only)', async () => {
      // Bootstrap admin first
      await bootstrapAdmin();

      // Generate a new NaCl keypair for the new key
      const newKeypair = nacl.box.keyPair();
      const newPublicKeyBase64 = Buffer.from(newKeypair.publicKey).toString('base64');

      const uniqueKeyId = `lcore_key_dev_${Date.now()}`;
      const rotatePayload = {
        action: 'rotate_encryption_key',
        new_public_key: newPublicKeyBase64,
        key_id: uniqueKeyId,
      };

      const result = await submitAdvance(rotatePayload, TEST_ADDRESSES.admin);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        old_key_id: string;
        new_key_id: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.new_key_id).toBe(uniqueKeyId);
    });

    it('should reject key rotation from non-admin', async () => {
      const newKeypair = nacl.box.keyPair();
      const newPublicKeyBase64 = Buffer.from(newKeypair.publicKey).toString('base64');

      const rotatePayload = {
        action: 'rotate_encryption_key',
        new_public_key: newPublicKeyBase64,
        key_id: 'lcore_key_v3',
      };

      const result = await submitAdvance(rotatePayload, TEST_ADDRESSES.unauthorized);
      assertRejected(result);
    });

    it('should accept attestation with new encryption_key_id after rotation', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      // Submit with new key ID (assuming rotation happened above)
      const payload = buildV1DeviceAttestation(deviceDid, { temp: 22 }, privateKey);
      payload.encryption_key_id = `lcore_key_post_rotation_${Date.now()}`;

      const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertAccepted(result);
    });
  });

  // ============= Batch Submission Tests =============

  describe('Batch Device Attestation', () => {
    it('should accept a batch of valid submissions', async () => {
      const submissions = [];
      for (let i = 0; i < 3; i++) {
        const { privateKey, publicKey } = generateDeviceKeypair();
        const deviceDid = publicKeyToDIDKey(publicKey);
        const sub = buildV1DeviceAttestation(deviceDid, { sensor: i, temp: 20 + i }, privateKey);
        submissions.push(sub);
      }

      const batchPayload = {
        action: 'batch_device_attestation',
        submissions,
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        batch_size: number;
        results: Array<{ index: number; id: number; device_did: string; data_hash: string }>;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.batch_size).toBe(3);
      expect(response?.results).toHaveLength(3);
      expect(response?.results[0].index).toBe(0);
      expect(response?.results[1].index).toBe(1);
      expect(response?.results[2].index).toBe(2);
    });

    it('should reject entire batch if one submission has invalid JWS', async () => {
      const { privateKey: pk1, publicKey: pub1 } = generateDeviceKeypair();
      const did1 = publicKeyToDIDKey(pub1);
      const valid = buildV1DeviceAttestation(did1, { ok: true }, pk1);

      // Create a submission with a JWS signed by a different key
      const { publicKey: pub2 } = generateDeviceKeypair();
      const { privateKey: wrongPk } = generateDeviceKeypair();
      const did2 = publicKeyToDIDKey(pub2);
      const invalid = buildV1DeviceAttestation(did2, { bad: true }, wrongPk);
      // Override device_did to mismatch the signing key
      invalid.device_did = did2;

      const batchPayload = {
        action: 'batch_device_attestation',
        submissions: [valid, invalid],
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertRejected(result);

      const response = getResponse<{ error: string; index: number }>(result);
      expect(response?.index).toBe(1);
    });

    it('should reject batch with empty submissions array', async () => {
      const batchPayload = {
        action: 'batch_device_attestation',
        submissions: [],
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertRejected(result);

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toContain('non-empty array');
    });

    it('should reject batch with missing submissions field', async () => {
      const batchPayload = {
        action: 'batch_device_attestation',
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertRejected(result);
    });

    it('should store all attestations from a batch and query them', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);

      const submissions = [];
      for (let i = 0; i < 5; i++) {
        submissions.push(
          buildV1DeviceAttestation(deviceDid, { reading: i * 10 }, privateKey)
        );
      }

      const batchPayload = {
        action: 'batch_device_attestation',
        submissions,
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      // Query attestations for this device
      const inspectResult = await submitInspect('device_attestations', {
        device_did: deviceDid,
      });

      const inspectResponse = getResponse<{
        device_did: string;
        count: number;
        attestations: Array<{ data_hash: string }>;
      }>(inspectResult);

      expect(inspectResponse?.count).toBe(5);
      expect(inspectResponse?.attestations).toHaveLength(5);
    });

    it('should handle single-item batch', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const sub = buildV1DeviceAttestation(deviceDid, { single: true }, privateKey);

      const batchPayload = {
        action: 'batch_device_attestation',
        submissions: [sub],
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{ batch_size: number }>(result);
      expect(response?.batch_size).toBe(1);
    });

    it('should reject batch where a submission has malformed data_hash', async () => {
      const { privateKey, publicKey } = generateDeviceKeypair();
      const deviceDid = publicKeyToDIDKey(publicKey);
      const sub = buildV1DeviceAttestation(deviceDid, { x: 1 }, privateKey);
      sub.data_hash = 'not-a-valid-hash';

      const batchPayload = {
        action: 'batch_device_attestation',
        submissions: [sub],
      };

      const result = await submitAdvance(batchPayload, TEST_ADDRESSES.owner);
      assertRejected(result);

      const response = getResponse<{ index: number }>(result);
      expect(response?.index).toBe(0);
    });
  });
});
