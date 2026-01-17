/**
 * L{CORE} SDK - Device Attestation Handler
 *
 * Simple handler for IoT device attestation via did:key.
 * Stores device data directly without requiring provider schema infrastructure.
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

// ============= Types =============

interface DeviceAttestationPayload {
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
 * Payload format (from attestor /api/device/submit):
 * {
 *   action: 'device_attestation',
 *   device_did: 'did:key:z...',  // secp256k1 public key
 *   data: { temperature: 23.4, humidity: 65 },  // sensor data
 *   timestamp: 1705123456,  // unix timestamp
 *   source: 'direct'  // submission source
 * }
 */
export const handleDeviceAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as DeviceAttestationPayload;

  // Validate required fields
  if (!p.device_did) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: device_did' },
    };
  }

  if (!p.data || typeof p.data !== 'object') {
    return {
      status: 'reject',
      response: { error: 'Missing required field: data (must be an object)' },
    };
  }

  if (typeof p.timestamp !== 'number') {
    return {
      status: 'reject',
      response: { error: 'Missing required field: timestamp (must be a number)' },
    };
  }

  // Validate did:key format (basic check)
  if (!p.device_did.startsWith('did:key:z')) {
    return {
      status: 'reject',
      response: { error: 'Invalid device_did format. Expected did:key:z...' },
    };
  }

  try {
    const db = getDatabase();

    // Insert into device_attestations table
    db.run(
      `INSERT INTO device_attestations (device_did, data, timestamp, source, input_index, created_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [
        p.device_did,
        JSON.stringify(p.data),
        p.timestamp,
        p.source || 'direct',
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
        timestamp: p.timestamp,
        input_index: requestData.metadata.input_index,
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
