/**
 * L{CORE} SDK - Embedding Commitment Handler
 *
 * Stores fraud-provable commitments binding attested inputs to embedding outputs.
 * Embeddings are computed in the attestor TEE — the node stores only the commitment hash.
 *
 * Commitment: sha256(attested_input_ref || model_id || embedding || nonce)
 *
 * ADVANCE HANDLERS:
 * - submit_embedding_commitment: Store a new embedding commitment (admin only)
 *
 * INSPECT HANDLERS:
 * - embedding_commitment: Query commitment by ID
 * - embedding_commitments_by_ref: Query commitments by attested_input_ref
 * - embedding_commitments_by_model: Query commitments by model_id
 * - embedding_commitment_stats: Aggregate statistics
 */

import {
  AdvanceRequestData,
  RequestHandlerResult,
  InspectQuery,
} from '../router';
import { getDatabase } from '../db';
import { getAttestationById, isSchemaAdmin } from '../lcore-db';

// ============= Types =============

interface SubmitEmbeddingCommitmentPayload {
  action: 'submit_embedding_commitment';
  attested_input_ref: string;    // attestation ID
  model_id: string;              // e.g. "text-embedding-3-large"
  embedding_hash: string;        // sha256(embedding_bytes), 64-char hex
  nonce: string;                 // random nonce, hex string
  commitment: string;            // sha256(attested_input_ref || model_id || embedding || nonce), 64-char hex
}

export interface EmbeddingCommitment {
  id: number;
  attested_input_ref: string;
  model_id: string;
  embedding_hash: string;
  nonce: string;
  commitment: string;
  submitted_by: string;
  input_index: number;
  created_at: string;
}

// ============= Validation =============

const HEX_64_REGEX = /^[0-9a-f]{64}$/i;

// ============= Advance Handlers =============

export const handleSubmitEmbeddingCommitment = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {

  const p = payload as SubmitEmbeddingCommitmentPayload;

  // Validate required fields
  if (!p.attested_input_ref) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: attested_input_ref' },
    };
  }

  if (!p.model_id) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: model_id' },
    };
  }

  if (!p.embedding_hash) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: embedding_hash' },
    };
  }

  if (!p.nonce) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: nonce' },
    };
  }

  if (!p.commitment) {
    return {
      status: 'reject',
      response: { error: 'Missing required field: commitment' },
    };
  }

  // Validate hex formats
  if (!HEX_64_REGEX.test(p.embedding_hash)) {
    return {
      status: 'reject',
      response: { error: 'Invalid embedding_hash format - expected 64-character hex string (SHA-256)' },
    };
  }

  if (!HEX_64_REGEX.test(p.commitment)) {
    return {
      status: 'reject',
      response: { error: 'Invalid commitment format - expected 64-character hex string (SHA-256)' },
    };
  }

  // Access control: admin only
  const sender = requestData.metadata.msg_sender.toLowerCase();
  if (!isSchemaAdmin(sender)) {
    return {
      status: 'reject',
      response: {
        error: 'Not authorized to submit embedding commitments - admin only',
        sender,
      },
    };
  }

  // Verify referenced attestation exists
  const attestation = getAttestationById(p.attested_input_ref);
  if (!attestation) {
    return {
      status: 'reject',
      response: { error: 'Referenced attestation not found', attested_input_ref: p.attested_input_ref },
    };
  }

  // Verify attestation is active
  if (attestation.status !== 'active') {
    return {
      status: 'reject',
      response: {
        error: 'Referenced attestation is not active',
        attested_input_ref: p.attested_input_ref,
        status: attestation.status,
      },
    };
  }

  // Store the commitment
  try {
    const db = getDatabase();

    db.run(
      `INSERT INTO embedding_commitments
       (attested_input_ref, model_id, embedding_hash, nonce, commitment, submitted_by, input_index, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        p.attested_input_ref,
        p.model_id,
        p.embedding_hash,
        p.nonce,
        p.commitment,
        sender,
        requestData.metadata.input_index,
      ]
    );

    const result = db.exec('SELECT last_insert_rowid()');
    const id = result[0]?.values[0]?.[0] as number ?? 0;

    return {
      status: 'accept',
      response: {
        success: true,
        id,
        attested_input_ref: p.attested_input_ref,
        model_id: p.model_id,
        commitment: p.commitment,
        input_index: requestData.metadata.input_index,
      },
    };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    if (msg.includes('UNIQUE constraint failed')) {
      return {
        status: 'reject',
        response: {
          error: 'Duplicate embedding commitment',
          details: 'A commitment with this attested_input_ref, model_id, and nonce already exists',
        },
      };
    }
    return {
      status: 'reject',
      response: {
        error: 'Failed to store embedding commitment',
        details: msg,
      },
    };
  }
};

// ============= Inspect Handlers =============

function mapRow(row: unknown[]): EmbeddingCommitment {
  return {
    id: row[0] as number,
    attested_input_ref: row[1] as string,
    model_id: row[2] as string,
    embedding_hash: row[3] as string,
    nonce: row[4] as string,
    commitment: row[5] as string,
    submitted_by: row[6] as string,
    input_index: row[7] as number,
    created_at: row[8] as string,
  };
}

const SELECT_COLS = `id, attested_input_ref, model_id, embedding_hash, nonce, commitment, submitted_by, input_index, created_at`;

/**
 * Query embedding commitment by ID
 */
export const handleInspectEmbeddingCommitment = async (
  query: InspectQuery
): Promise<unknown> => {
  const { id } = query.params;

  if (!id) {
    return { error: 'id parameter required' };
  }

  try {
    const db = getDatabase();
    const result = db.exec(
      `SELECT ${SELECT_COLS} FROM embedding_commitments WHERE id = ?`,
      [parseInt(id, 10)]
    );

    const row = result[0]?.values[0];
    if (!row) {
      return { error: 'Embedding commitment not found', id };
    }

    return { commitment: mapRow(row) };
  } catch (error) {
    return {
      error: 'Failed to query embedding commitment',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};

/**
 * Query embedding commitments by attested_input_ref
 */
export const handleInspectEmbeddingCommitmentsByRef = async (
  query: InspectQuery
): Promise<unknown> => {
  const { attested_input_ref, limit, offset } = query.params;

  if (!attested_input_ref) {
    return { error: 'attested_input_ref parameter required' };
  }

  try {
    const db = getDatabase();
    const limitNum = limit ? parseInt(limit, 10) : 50;
    const offsetNum = offset ? parseInt(offset, 10) : 0;

    const result = db.exec(
      `SELECT ${SELECT_COLS} FROM embedding_commitments
       WHERE attested_input_ref = ?
       ORDER BY id DESC
       LIMIT ? OFFSET ?`,
      [attested_input_ref, limitNum, offsetNum]
    );

    const rows = result[0]?.values ?? [];

    return {
      attested_input_ref,
      count: rows.length,
      commitments: rows.map(mapRow),
    };
  } catch (error) {
    return {
      error: 'Failed to query embedding commitments',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};

/**
 * Query embedding commitments by model_id
 */
export const handleInspectEmbeddingCommitmentsByModel = async (
  query: InspectQuery
): Promise<unknown> => {
  const { model_id, limit, offset } = query.params;

  if (!model_id) {
    return { error: 'model_id parameter required' };
  }

  try {
    const db = getDatabase();
    const limitNum = limit ? parseInt(limit, 10) : 50;
    const offsetNum = offset ? parseInt(offset, 10) : 0;

    const result = db.exec(
      `SELECT ${SELECT_COLS} FROM embedding_commitments
       WHERE model_id = ?
       ORDER BY id DESC
       LIMIT ? OFFSET ?`,
      [model_id, limitNum, offsetNum]
    );

    const rows = result[0]?.values ?? [];

    return {
      model_id,
      count: rows.length,
      commitments: rows.map(mapRow),
    };
  } catch (error) {
    return {
      error: 'Failed to query embedding commitments',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};

/**
 * Get embedding commitment statistics.
 * No PII — safe to return unencrypted.
 */
export const handleInspectEmbeddingCommitmentStats = async (
  _query: InspectQuery
): Promise<unknown> => {
  try {
    const db = getDatabase();

    const totalResult = db.exec('SELECT COUNT(*) FROM embedding_commitments');
    const totalCount = (totalResult[0]?.values[0]?.[0] as number) ?? 0;

    const uniqueModelsResult = db.exec('SELECT COUNT(DISTINCT model_id) FROM embedding_commitments');
    const uniqueModels = (uniqueModelsResult[0]?.values[0]?.[0] as number) ?? 0;

    const uniqueRefsResult = db.exec('SELECT COUNT(DISTINCT attested_input_ref) FROM embedding_commitments');
    const uniqueRefs = (uniqueRefsResult[0]?.values[0]?.[0] as number) ?? 0;

    const topModelsResult = db.exec(
      `SELECT model_id, COUNT(*) as count
       FROM embedding_commitments
       GROUP BY model_id
       ORDER BY count DESC
       LIMIT 10`
    );

    const topModels = (topModelsResult[0]?.values ?? []).map((row: unknown[]) => ({
      model_id: row[0] as string,
      count: row[1] as number,
    }));

    return {
      total_commitments: totalCount,
      unique_models: uniqueModels,
      unique_attestations: uniqueRefs,
      top_models: topModels,
    };
  } catch (error) {
    return {
      error: 'Failed to get embedding commitment stats',
      details: error instanceof Error ? error.message : String(error),
    };
  }
};
