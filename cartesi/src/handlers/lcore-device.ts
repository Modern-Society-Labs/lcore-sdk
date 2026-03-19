/**
 * L{CORE} SDK - Device Attestation Handler
 *
 * Fraud-provable handler for IoT device attestation via did:key.
 *
 * V1 SECURITY MODEL:
 * - Node NEVER decrypts device data (no private key in Cartesi)
 * - Attestor encrypts data + salt, submits encrypted blob + salted hash
 * - JWS is verified over the salted hash (fraud-provable)
 * - Only the attestor TEE can decrypt the data
 * - Anyone can re-run Cartesi and verify JWS was valid over the hash
 */

import {
  AdvanceRequestData,
  RequestHandlerResult,
  InspectQuery,
} from '../router';
import { getDatabase } from '../db';
import { verifyJWSOverHash, isValidDIDKey } from '../crypto/jws';

// ============= Types =============

/**
 * V1 device attestation payload.
 * The node stores encrypted blobs + hashes without decrypting.
 */
interface V1DevicePayload {
  action: 'device_attestation';
  data_hash: string;           // hex sha256(canonical_json(data) + device_did + timestamp)
  jws: string;                 // JWS over data_hash
  encrypted_data: string;      // base64 encrypted blob (opaque to node)
  device_did: string;
  timestamp: number;
  encryption_key_id: string;
  source?: string;
}

export interface DeviceAttestation {
  id: number;
  device_did: string;
  data_hash: string;
  encrypted_data: string;
  jws: string;
  encryption_key_id: string;
  timestamp: number;
  source: string | null;
  input_index: number;
  created_at: string;
}

// ============= Advance Handlers =============

/**
 * Handle device attestation from IoT devices (V1 format)
 *
 * V1 PAYLOAD FORMAT:
 * {
 *   action: 'device_attestation',
 *   data_hash: '...',           // sha256(canonical_json(data) + salt)
 *   jws: 'eyJhbGc...',         // JWS over data_hash (verified here!)
 *   encrypted_data: '...',      // base64 encrypted blob (opaque to node)
 *   device_did: 'did:key:z...', // secp256k1 public key
 *   timestamp: 1705123456,
 *   encryption_key_id: 'lcore_key_v1',
 *   source: 'relay'
 * }
 */
export const handleDeviceAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {

  const p = payload as V1DevicePayload;

  // Step 1: Validate required fields
  if (!p.device_did) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: device_did' },
    };
  }

  if (!p.data_hash) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: data_hash' },
    };
  }

  if (!p.jws) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: jws' },
    };
  }

  if (!p.encrypted_data) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: encrypted_data' },
    };
  }

  if (!p.encryption_key_id) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: encryption_key_id' },
    };
  }

  if (typeof p.timestamp !== 'number') {
    return {
      status: 'reject',
      response: { error: 'Missing required field: timestamp (must be a number)' },
    };
  }

  // Validate data_hash format (64-char hex = SHA-256)
  if (!/^[0-9a-f]{64}$/i.test(p.data_hash)) {
    return {
      status: 'reject',
      response: { error: 'Invalid data_hash format - expected 64-character hex string (SHA-256)' },
    };
  }

  // Validate did:key format
  if (!isValidDIDKey(p.device_did)) {
    return {
      status: 'reject',
      response: { error: 'Invalid device_did format. Expected did:key:z... with secp256k1 key' },
    };
  }

  // Step 2: Verify JWS over hash (FRAUD-PROVABLE)
  // The device signs: sha256(canonical_json(payload) + device_did + timestamp)
  // This is deterministic — both device and Cartesi compute the same hash.
  // Anyone can re-run Cartesi and verify every device signature was valid.
  try {
    const isValid = verifyJWSOverHash(
      p.jws,
      p.data_hash,
      p.device_did
    );

    if (!isValid) {
      return {
        status: 'reject',
        response: { error: 'Invalid device signature - JWS verification over hash failed' },
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

  // Step 3: Store the verified attestation (encrypted blob, never decrypted)
  try {
    const db = getDatabase();

    db.run(
      `INSERT INTO device_attestations
       (device_did, data_hash, encrypted_data, jws, encryption_key_id, timestamp, source, input_index, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        p.device_did,
        p.data_hash,
        p.encrypted_data,
        p.jws,
        p.encryption_key_id,
        p.timestamp,
        p.source || 'relay',
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
        device_did: p.device_did,
        data_hash: p.data_hash,
        timestamp: p.timestamp,
        input_index: requestData.metadata.input_index,
        verified: true,  // Indicates JWS over hash was verified
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

// ============= Batch Handler =============

/**
 * Handle batched device attestations from the attestor.
 *
 * Unpacks a submissions array and processes each one through the
 * standard device attestation logic. All-or-nothing: if any submission
 * fails validation, the entire batch is rejected.
 *
 * PAYLOAD FORMAT:
 * {
 *   action: 'batch_device_attestation',
 *   submissions: V1DevicePayload[]
 * }
 */
export const handleBatchDeviceAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {

  const p = payload as { action: string; submissions: unknown[] };

  if (!Array.isArray(p.submissions) || p.submissions.length === 0) {
    return {
      status: 'reject',
      response: { error: 'submissions must be a non-empty array' },
    };
  }

  const results: Array<{ index: number; id: number; device_did: string; data_hash: string }> = [];

  for (let i = 0; i < p.submissions.length; i++) {
    const sub = p.submissions[i] as V1DevicePayload;

    // Delegate to the single-item handler logic
    const result = await handleDeviceAttestation(requestData, sub);

    if (result.status === 'reject') {
      return {
        status: 'reject',
        response: {
          error: `Submission ${i} failed`,
          index: i,
          details: result.response,
        },
      };
    }

    const resp = result.response as { id: number; device_did: string; data_hash: string };
    results.push({ index: i, id: resp.id, device_did: resp.device_did, data_hash: resp.data_hash });
  }

  return {
    status: 'accept',
    response: {
      success: true,
      batch_size: results.length,
      results,
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Query device attestations by device DID
 *
 * Returns encrypted data blobs + hashes (node never decrypts).
 * The attestor TEE proxy decrypts for authorized requesters.
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
      `SELECT id, device_did, data_hash, encrypted_data, jws, encryption_key_id,
              timestamp, source, input_index, created_at
       FROM device_attestations
       WHERE device_did = ?
       ORDER BY timestamp DESC
       LIMIT ? OFFSET ?`,
      [device_did, limitNum, offsetNum]
    );

    const rows = result[0]?.values ?? [];

    const attestations = rows.map((row: unknown[]) => ({
      id: row[0] as number,
      device_did: row[1] as string,
      data_hash: row[2] as string,
      encrypted_data: row[3] as string,
      jws: row[4] as string,
      encryption_key_id: row[5] as string,
      timestamp: row[6] as number,
      source: row[7] as string | null,
      input_index: row[8] as number,
      created_at: row[9] as string,
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
      `SELECT id, device_did, data_hash, encrypted_data, jws, encryption_key_id,
              timestamp, source, input_index, created_at
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
      data_hash: row[2] as string,
      encrypted_data: row[3] as string,
      jws: row[4] as string,
      encryption_key_id: row[5] as string,
      timestamp: row[6] as number,
      source: row[7] as string | null,
      input_index: row[8] as number,
      created_at: row[9] as string,
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
 * No PII - safe to return unencrypted.
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

    const perDevice = (perDeviceResult[0]?.values ?? []).map((row: unknown[]) => ({
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
