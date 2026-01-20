/**
 * L{CORE} SDK - Device Attestation Handler
 *
 * Fraud-provable handler for IoT device attestation via did:key.
 *
 * SECURITY MODEL:
 * - All inputs MUST be encrypted (privacy before InputBox)
 * - All JWS signatures are verified HERE in Cartesi (fraud-provable)
 * - Anyone can re-run Cartesi and verify every signature was valid
 * - No trusted attestor needed for verification
 *
 * This enables lightweight device attestation for IoT sensors that sign their
 * own data with secp256k1 keys (did:key format).
 */

import {
  AdvanceRequestData,
  RequestHandlerResult,
  InspectQuery,
} from '../router';
import { getDatabase } from '../db';
import type { EncryptedOutput } from '../encryption';
import { verifyJWS, isValidDIDKey } from '../crypto/jws';

// ============= Types =============

/**
 * Encrypted envelope from the attestor/relay.
 */
interface EncryptedDevicePayload {
  encrypted: true;
  payload: EncryptedOutput;
}

/**
 * Decrypted device attestation payload.
 * This is what's inside the encrypted envelope.
 */
interface DecryptedDevicePayload {
  action: 'device_attestation';
  device_did: string;
  data: Record<string, unknown>;
  signature: string;  // JWS to verify (FRAUD-PROVABLE)
  timestamp: number;
  source: string;
}

/**
 * Legacy plaintext payload (for backward compatibility during transition).
 * TODO: Remove after transition period.
 */
interface LegacyDeviceAttestationPayload {
  action: 'device_attestation';
  device_did: string;
  data: Record<string, unknown>;
  timestamp: number;
  source: string;
}

export interface DeviceAttestation {
  id: number;
  device_did: string;
  data: string;
  timestamp: number;
  source: string | null;
  input_index: number;
  created_at: string;
}

// ============= Advance Handlers =============

/**
 * Handle device attestation from IoT devices
 *
 * ENCRYPTED PAYLOAD FORMAT (required):
 * {
 *   encrypted: true,
 *   payload: {
 *     version: 1,
 *     algorithm: 'nacl-box',
 *     nonce: '...',
 *     ciphertext: '...',
 *     publicKey: '...'
 *   }
 * }
 *
 * DECRYPTED CONTENTS:
 * {
 *   action: 'device_attestation',
 *   device_did: 'did:key:z...',  // secp256k1 public key
 *   data: { temperature: 23.4, humidity: 65 },  // sensor data
 *   signature: 'eyJhbGc...',  // JWS over data (verified here!)
 *   timestamp: 1705123456,  // unix timestamp
 *   source: 'relay'  // submission source
 * }
 */
export const handleDeviceAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {

  // Note: Router already handles decryption at router.ts:204-219
  // The payload we receive here is already decrypted
  const decrypted = payload as DecryptedDevicePayload;

  // Step 1: Validate required fields
  if (!decrypted.device_did) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: device_did' },
    };
  }

  if (!decrypted.data || typeof decrypted.data !== 'object') {
    return {
      status: 'reject',
      response: { error: 'Missing required field: data (must be an object)' },
    };
  }

  if (!decrypted.signature) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: signature (JWS required for verification)' },
    };
  }

  if (typeof decrypted.timestamp !== 'number') {
    return {
      status: 'reject',
      response: { error: 'Missing required field: timestamp (must be a number)' },
    };
  }

  // Validate did:key format
  if (!isValidDIDKey(decrypted.device_did)) {
    return {
      status: 'reject',
      response: { error: 'Invalid device_did format. Expected did:key:z... with secp256k1 key' },
    };
  }

  // Step 3: Verify JWS signature (FRAUD-PROVABLE)
  // This is the key security property - verification happens in Cartesi
  // Anyone can re-run Cartesi and verify this was done correctly
  try {
    const isValid = verifyJWS(
      decrypted.signature,
      decrypted.data,
      decrypted.device_did
    );

    if (!isValid) {
      return {
        status: 'reject',
        response: { error: 'Invalid device signature - JWS verification failed' },
      };
    }
  } catch (e) {
    return {
      status: 'reject',
      response: {
        error: 'Signature verification failed',
        details: e instanceof Error ? e.message : String(e),
      },
    };
  }

  // Step 4: Store the verified attestation
  try {
    const db = getDatabase();

    // Insert into device_attestations table
    db.run(
      `INSERT INTO device_attestations (device_did, data, timestamp, source, input_index, created_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [
        decrypted.device_did,
        JSON.stringify(decrypted.data),
        decrypted.timestamp,
        decrypted.source || 'relay',
        requestData.metadata.input_index,
      ]
    );

    // Get the inserted row ID
    const result = db.exec('SELECT last_insert_rowid()');
    const id = result[0]?.values[0]?.[0] as number ?? 0;

    return {
      status: 'accept',
      response: {
        success: true,
        id,
        device_did: decrypted.device_did,
        timestamp: decrypted.timestamp,
        input_index: requestData.metadata.input_index,
        verified: true,  // Indicates JWS was verified
      },
    };
  } catch (error) {
    return {
      status: 'reject',
      response: {
        error: 'Failed to store device attestation',
        details: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

// ============= Inspect Handlers =============

/**
 * Query device attestations by device DID
 *
 * Query parameters:
 * - device_did: The device's did:key identifier (required)
 * - limit: Maximum number of results (default: 50)
 * - offset: Pagination offset (default: 0)
 */
export const handleInspectDeviceAttestations = async (
  query: InspectQuery
): Promise<unknown> => {
  const { device_did, limit, offset } = query.params;

  if (!device_did) {
    return { error: 'device_did parameter required' };
  }

  try {
    const db = getDatabase();
    const limitNum = limit ? parseInt(limit, 10) : 50;
    const offsetNum = offset ? parseInt(offset, 10) : 0;

    const result = db.exec(
      `SELECT id, device_did, data, timestamp, source, input_index, created_at
       FROM device_attestations
       WHERE device_did = ?
       ORDER BY timestamp DESC
       LIMIT ? OFFSET ?`,
      [device_did, limitNum, offsetNum]
    );

    const rows = result[0]?.values ?? [];

    const attestations = rows.map((row) => ({
      id: row[0] as number,
      device_did: row[1] as string,
      data: JSON.parse(row[2] as string),
      timestamp: row[3] as number,
      source: row[4] as string | null,
      input_index: row[5] as number,
      created_at: row[6] as string,
    }));

    return {
      device_did,
      count: attestations.length,
      attestations,
    };
  } catch (error) {
    return {
      error: 'Failed to query device attestations',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};

/**
 * Query latest attestation for a device
 *
 * Query parameters:
 * - device_did: The device's did:key identifier (required)
 */
export const handleInspectDeviceLatest = async (
  query: InspectQuery
): Promise<unknown> => {
  const { device_did } = query.params;

  if (!device_did) {
    return { error: 'device_did parameter required' };
  }

  try {
    const db = getDatabase();

    const result = db.exec(
      `SELECT id, device_did, data, timestamp, source, input_index, created_at
       FROM device_attestations
       WHERE device_did = ?
       ORDER BY timestamp DESC
       LIMIT 1`,
      [device_did]
    );

    const row = result[0]?.values[0];

    if (!row) {
      return { error: 'No attestations found for device', device_did };
    }

    return {
      id: row[0] as number,
      device_did: row[1] as string,
      data: JSON.parse(row[2] as string),
      timestamp: row[3] as number,
      source: row[4] as string | null,
      input_index: row[5] as number,
      created_at: row[6] as string,
    };
  } catch (error) {
    return {
      error: 'Failed to query device attestation',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};

/**
 * Get device attestation statistics
 *
 * Returns aggregate counts by device and overall totals.
 */
export const handleInspectDeviceStats = async (
  _query: InspectQuery
): Promise<unknown> => {
  try {
    const db = getDatabase();

    // Total count
    const totalResult = db.exec('SELECT COUNT(*) FROM device_attestations');
    const totalCount = (totalResult[0]?.values[0]?.[0] as number) ?? 0;

    // Unique devices
    const uniqueResult = db.exec('SELECT COUNT(DISTINCT device_did) FROM device_attestations');
    const uniqueDevices = (uniqueResult[0]?.values[0]?.[0] as number) ?? 0;

    // Attestations per device (top 10)
    const perDeviceResult = db.exec(
      `SELECT device_did, COUNT(*) as count
       FROM device_attestations
       GROUP BY device_did
       ORDER BY count DESC
       LIMIT 10`
    );

    const perDevice = (perDeviceResult[0]?.values ?? []).map((row) => ({
      device_did: row[0] as string,
      count: row[1] as number,
    }));

    return {
      total_attestations: totalCount,
      unique_devices: uniqueDevices,
      top_devices: perDevice,
    };
  } catch (error) {
    return {
      error: 'Failed to get device stats',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};
