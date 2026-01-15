/**
 * L{CORE} SDK - Attestation Handlers
 *
 * Handles attestation ingestion, status updates, and revocation.
 *
 * PRIVACY NOTE: Inspect handlers that return PII (owner_address, attestation details)
 * use the encryption module to encrypt sensitive outputs. Only aggregate data
 * (counts) is returned unencrypted.
 */

import {
  AdvanceRequestData,
  RequestHandlerResult,
  InspectQuery,
} from '../router';
import {
  createAttestation,
  getAttestationById,
  getAttestationByHash,
  getAttestationsByOwner,
  updateAttestationStatus,
  getAttestationBuckets,
  getProviderSchema,
  AttestationInput,
  BucketInput,
  DataInput,
} from '../lcore-db';
import { createResponse, isEncryptionConfigured } from '../encryption';

// ============= Advance Handlers =============

interface IngestAttestationPayload {
  action: 'ingest_attestation';
  id: string;
  attestation_hash: string;
  owner_address: string;
  provider: string;
  flow_type: string;
  valid_from: number;
  valid_until?: number;
  tee_signature: string;
  buckets: Array<{ key: string; value: string }>;
  data: Array<{ key: string; value: string; encryption_key_id: string }>; // value is base64 encoded
}

/**
 * Handle attestation ingestion from the Attestor TEE
 */
export const handleIngestAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as IngestAttestationPayload;

  // Validate required fields
  if (!p.id || !p.attestation_hash || !p.owner_address || !p.provider || !p.flow_type) {
    return {
      status: 'reject',
      response: { error: 'Missing required fields' },
    };
  }

  // Check if attestation already exists
  const existing = getAttestationById(p.id);
  if (existing) {
    return {
      status: 'reject',
      response: { error: 'Attestation already exists', id: p.id },
    };
  }

  // Validate provider schema exists
  const schema = getProviderSchema(p.provider, p.flow_type);
  if (!schema) {
    return {
      status: 'reject',
      response: {
        error: 'Provider schema not registered',
        provider: p.provider,
        flow_type: p.flow_type,
      },
    };
  }

  // Prepare attestation input
  const attestationInput: AttestationInput = {
    id: p.id,
    attestation_hash: p.attestation_hash,
    owner_address: p.owner_address,
    domain: schema.domain,
    provider: p.provider,
    flow_type: p.flow_type,
    attested_at_input: requestData.metadata.input_index,
    valid_from: p.valid_from,
    valid_until: p.valid_until,
    tee_signature: p.tee_signature,
    created_input: requestData.metadata.input_index,
  };

  // Prepare buckets
  const buckets: BucketInput[] = (p.buckets || []).map(b => ({
    bucket_key: b.key,
    bucket_value: b.value,
  }));

  // Prepare encrypted data (decode base64)
  const data: DataInput[] = (p.data || []).map(d => ({
    data_key: d.key,
    encrypted_value: base64ToUint8Array(d.value),
    encryption_key_id: d.encryption_key_id,
  }));

  try {
    const attestation = createAttestation(attestationInput, buckets, data);

    return {
      status: 'accept',
      response: {
        success: true,
        attestation_id: attestation.id,
        attestation_hash: attestation.attestation_hash,
        domain: attestation.domain,
        provider: attestation.provider,
        flow_type: attestation.flow_type,
        buckets_count: buckets.length,
        data_keys_count: data.length,
      },
    };
  } catch (error) {
    return {
      status: 'reject',
      response: {
        error: 'Failed to create attestation',
        details: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

interface RevokeAttestationPayload {
  action: 'revoke_attestation';
  attestation_id: string;
}

/**
 * Handle attestation revocation by owner
 */
export const handleRevokeAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as RevokeAttestationPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  if (!p.attestation_id) {
    return {
      status: 'reject',
      response: { error: 'attestation_id required' },
    };
  }

  const attestation = getAttestationById(p.attestation_id);
  if (!attestation) {
    return {
      status: 'reject',
      response: { error: 'Attestation not found', attestation_id: p.attestation_id },
    };
  }

  // Only owner can revoke
  if (attestation.owner_address.toLowerCase() !== sender) {
    return {
      status: 'reject',
      response: { error: 'Only owner can revoke attestation' },
    };
  }

  if (attestation.status !== 'active') {
    return {
      status: 'reject',
      response: {
        error: 'Attestation is not active',
        current_status: attestation.status,
      },
    };
  }

  const success = updateAttestationStatus(p.attestation_id, 'revoked');

  return {
    status: success ? 'accept' : 'reject',
    response: {
      success,
      attestation_id: p.attestation_id,
      new_status: 'revoked',
    },
  };
};

interface SupersedeAttestationPayload {
  action: 'supersede_attestation';
  old_attestation_id: string;
  new_attestation_id: string;
}

/**
 * Handle attestation supersession (replace old with new)
 */
export const handleSupersedeAttestation = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as SupersedeAttestationPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  if (!p.old_attestation_id || !p.new_attestation_id) {
    return {
      status: 'reject',
      response: { error: 'old_attestation_id and new_attestation_id required' },
    };
  }

  const oldAttestation = getAttestationById(p.old_attestation_id);
  const newAttestation = getAttestationById(p.new_attestation_id);

  if (!oldAttestation) {
    return {
      status: 'reject',
      response: { error: 'Old attestation not found' },
    };
  }

  if (!newAttestation) {
    return {
      status: 'reject',
      response: { error: 'New attestation not found' },
    };
  }

  // Verify ownership
  if (oldAttestation.owner_address.toLowerCase() !== sender) {
    return {
      status: 'reject',
      response: { error: 'Only owner can supersede attestation' },
    };
  }

  if (newAttestation.owner_address.toLowerCase() !== sender) {
    return {
      status: 'reject',
      response: { error: 'New attestation must have same owner' },
    };
  }

  // Verify same provider/flow_type
  if (
    oldAttestation.provider !== newAttestation.provider ||
    oldAttestation.flow_type !== newAttestation.flow_type
  ) {
    return {
      status: 'reject',
      response: { error: 'Attestations must have same provider and flow_type' },
    };
  }

  const success = updateAttestationStatus(p.old_attestation_id, 'superseded', p.new_attestation_id);

  return {
    status: success ? 'accept' : 'reject',
    response: {
      success,
      old_attestation_id: p.old_attestation_id,
      new_attestation_id: p.new_attestation_id,
      old_status: 'superseded',
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Query attestation by ID or hash
 *
 * PRIVACY: This returns PII (owner_address, attestation details).
 * Output is encrypted if encryption is configured.
 */
export const handleInspectAttestation = async (
  query: InspectQuery
): Promise<unknown> => {
  const { id, hash } = query.params;

  if (!id && !hash) {
    return { error: 'id or hash parameter required' };
  }

  const attestation = id
    ? getAttestationById(id)
    : hash
      ? getAttestationByHash(hash)
      : null;

  if (!attestation) {
    return { error: 'Attestation not found' };
  }

  // Get buckets
  const buckets = getAttestationBuckets(attestation.id);

  // Build response data (contains PII)
  const responseData = {
    attestation: {
      id: attestation.id,
      attestation_hash: attestation.attestation_hash,
      owner_address: attestation.owner_address,
      domain: attestation.domain,
      provider: attestation.provider,
      flow_type: attestation.flow_type,
      status: attestation.status,
      freshness_score: attestation.freshness_score,
      valid_from: attestation.valid_from,
      valid_until: attestation.valid_until,
      attested_at_input: attestation.attested_at_input,
    },
    buckets: buckets.map(b => ({
      key: b.bucket_key,
      value: b.bucket_value,
    })),
  };

  // Encrypt if configured (this data contains PII)
  return createResponse(responseData, true);
};

/**
 * Query attestations by owner
 *
 * PRIVACY: This returns PII (owner_address, attestation details).
 * Output is encrypted if encryption is configured.
 */
export const handleInspectAttestationsByOwner = async (
  query: InspectQuery
): Promise<unknown> => {
  const { owner, domain, provider, status, limit, offset } = query.params;

  if (!owner) {
    return { error: 'owner parameter required' };
  }

  const attestations = getAttestationsByOwner(owner, {
    domain,
    provider,
    status: status || 'active',
    limit: limit ? parseInt(limit, 10) : 50,
    offset: offset ? parseInt(offset, 10) : 0,
  });

  // Get buckets for each attestation
  const results = attestations.map(att => {
    const buckets = getAttestationBuckets(att.id);
    return {
      id: att.id,
      attestation_hash: att.attestation_hash,
      domain: att.domain,
      provider: att.provider,
      flow_type: att.flow_type,
      status: att.status,
      freshness_score: att.freshness_score,
      valid_from: att.valid_from,
      valid_until: att.valid_until,
      buckets: buckets.map(b => ({ key: b.bucket_key, value: b.bucket_value })),
    };
  });

  // Build response data (contains PII)
  const responseData = {
    owner,
    count: results.length,
    attestations: results,
  };

  // Encrypt if configured (this data contains PII)
  return createResponse(responseData, true);
};

// ============= Helpers =============

function base64ToUint8Array(base64: string): Uint8Array {
  // Handle both browser and Node.js environments
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  }
  // Fallback for browser
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
