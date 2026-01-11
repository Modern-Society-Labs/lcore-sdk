/**
 * Proof Handlers
 *
 * Handlers for data proof submission and verification.
 * Proofs attest to the authenticity and integrity of external data.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Implement your signature verification logic in verifySignature()
 * 2. Add proof type-specific validation as needed
 * 3. Customize proof expiration handling
 */

import { createHmac } from 'crypto';
import { AdvanceHandler, InspectHandler, InspectQuery, AdvanceRequestData } from '../router';
import {
  getEntityById,
  createEntity,
  saveDataProof,
  getDataProofById,
  getProofsByEntity,
  markProofVerified,
  isProofValid,
  DataProofInput,
} from '../db';
import { getProofSigningKey } from '../config';

// ============= Payload Types =============

interface SubmitProofPayload {
  action: 'submit_proof';
  proof: {
    proof_id: string;
    proof_type: string;
    entity_id: string;
    data_hash: string;
    signature: string;
    expires_at?: number; // Unix timestamp
    metadata?: Record<string, unknown>;
  };
}

// ============= Proof Types =============

/**
 * Supported proof types.
 * CUSTOMIZE: Add your proof types here
 */
const PROOF_TYPES = ['transactions', 'identity', 'ownership', 'custom'];

// ============= Signature Verification =============

/**
 * Verify an HMAC signature.
 * CUSTOMIZE: Replace with your signature verification logic
 * (e.g., ECDSA, zkProof verification, etc.)
 */
function verifySignature(data: string, signature: string): boolean {
  const signingKey = getProofSigningKey();
  const expectedSignature = createHmac('sha256', signingKey)
    .update(data)
    .digest('hex');
  return expectedSignature === signature;
}

/**
 * Verify proof-specific requirements.
 * CUSTOMIZE: Add validation for different proof types
 */
function validateProofType(proofType: string, metadata?: Record<string, unknown>): void {
  switch (proofType) {
    case 'transactions':
      // Transaction proofs might require specific metadata
      break;

    case 'identity':
      // Identity proofs might require verification level
      break;

    case 'ownership':
      // Ownership proofs might require asset details
      break;

    case 'custom':
      // Custom proofs have no additional requirements
      break;

    default:
      throw new Error(`Unknown proof type: ${proofType}`);
  }
}

// ============= Advance Handlers =============

/**
 * Handle proof submission.
 */
export const handleSubmitProof: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { proof } = payload as SubmitProofPayload;

  // Validate required fields
  if (!proof.proof_id || typeof proof.proof_id !== 'string') {
    throw new Error('Valid proof_id is required');
  }

  if (!proof.proof_type || typeof proof.proof_type !== 'string') {
    throw new Error('Valid proof_type is required');
  }

  if (!PROOF_TYPES.includes(proof.proof_type)) {
    throw new Error(`Unknown proof_type. Must be one of: ${PROOF_TYPES.join(', ')}`);
  }

  if (!proof.entity_id || typeof proof.entity_id !== 'string') {
    throw new Error('Valid entity_id is required');
  }

  if (!proof.data_hash || typeof proof.data_hash !== 'string') {
    throw new Error('Valid data_hash is required');
  }

  if (!proof.signature || typeof proof.signature !== 'string') {
    throw new Error('Valid signature is required');
  }

  // Validate proof type-specific requirements
  validateProofType(proof.proof_type, proof.metadata);

  // Verify signature
  const dataToVerify = JSON.stringify({
    proof_id: proof.proof_id,
    proof_type: proof.proof_type,
    entity_id: proof.entity_id,
    data_hash: proof.data_hash,
    expires_at: proof.expires_at,
  });

  const isValidSignature = verifySignature(dataToVerify, proof.signature);
  if (!isValidSignature) {
    throw new Error('Invalid proof signature');
  }

  // Check expiration
  if (proof.expires_at) {
    const expiresAt = proof.expires_at * 1000; // Convert to milliseconds if unix timestamp
    if (expiresAt < Date.now()) {
      throw new Error('Proof has expired');
    }
  }

  // Get or create entity
  let entity = getEntityById(proof.entity_id);
  if (!entity) {
    entity = createEntity({ id: proof.entity_id });
  }

  // Prepare proof input
  const proofInput: DataProofInput = {
    proof_id: proof.proof_id,
    proof_type: proof.proof_type,
    entity_id: proof.entity_id,
    data_hash: proof.data_hash,
    signature: proof.signature,
    expires_at: proof.expires_at
      ? new Date(proof.expires_at * 1000).toISOString()
      : undefined,
    metadata: proof.metadata,
  };

  // Save proof
  const savedProof = saveDataProof(proofInput);

  // Mark as verified since signature was validated
  markProofVerified(savedProof.proof_id);

  console.log(
    `Proof ${savedProof.proof_id} (${proof.proof_type}) verified and stored for entity ${proof.entity_id}`
  );

  return {
    status: 'accept',
    response: {
      action: 'submit_proof',
      success: true,
      proof_id: savedProof.proof_id,
      proof_type: savedProof.proof_type,
      entity_id: savedProof.entity_id,
      verified: true,
      expires_at: savedProof.expires_at,
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Handle inspect query for proof data.
 */
export const handleInspectProof: InspectHandler = async (query: InspectQuery) => {
  const { params } = query;

  // Get specific proof by ID
  if (params.proof_id) {
    const proof = getDataProofById(params.proof_id);
    if (!proof) {
      return { error: 'Proof not found', proof_id: params.proof_id };
    }

    return {
      proof_id: proof.proof_id,
      proof_type: proof.proof_type,
      entity_id: proof.entity_id,
      data_hash: proof.data_hash,
      verified: proof.verified,
      verified_at: proof.verified_at,
      expires_at: proof.expires_at,
      is_valid: isProofValid(proof.proof_id),
      created_at: proof.created_at,
    };
  }

  // Get proofs by entity
  if (params.entity_id) {
    const entity = getEntityById(params.entity_id);
    if (!entity) {
      return { error: 'Entity not found', entity_id: params.entity_id };
    }

    const proofs = getProofsByEntity(entity.id);

    return {
      entity_id: entity.id,
      proof_count: proofs.length,
      proofs: proofs.map(p => ({
        proof_id: p.proof_id,
        proof_type: p.proof_type,
        verified: p.verified,
        is_valid: isProofValid(p.proof_id),
        created_at: p.created_at,
        expires_at: p.expires_at,
      })),
    };
  }

  return { error: 'proof_id or entity_id parameter required' };
};
