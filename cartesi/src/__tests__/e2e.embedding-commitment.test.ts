/**
 * E2E Tests: Embedding Commitment Handler
 *
 * Tests the submit_embedding_commitment advance handler and
 * inspect query handlers for embedding commitments.
 */

import { describe, it, expect, beforeAll } from '@jest/globals';

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  assertAccepted,
  assertRejected,
  getResponse,
  fullSetup,
  buildEmbeddingCommitmentPayload,
  generateHash,
  TEST_ADDRESSES,
} from './e2e-helpers';

// ============= Tests =============

describe('E2E: Embedding Commitments', () => {
  let attestationId: string;

  beforeAll(async () => {
    await waitForServer();
    const setup = await fullSetup();
    assertAccepted(setup.adminResult);
    assertAccepted(setup.schemaResult);
    assertAccepted(setup.attestationResult);
    attestationId = setup.attestationId;
  }, 60000);

  describe('Valid Submission Flow', () => {
    it('should accept embedding commitment with valid fields', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);

      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        id: number;
        attested_input_ref: string;
        model_id: string;
        commitment: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.id).toBeGreaterThan(0);
      expect(response?.attested_input_ref).toBe(attestationId);
      expect(response?.model_id).toBe('text-embedding-3-large');
      expect(response?.commitment).toBe(payload.commitment);
    });

    it('should accept multiple commitments for same attestation with different models', async () => {
      const payload1 = buildEmbeddingCommitmentPayload(attestationId, {
        model_id: 'text-embedding-ada-002',
      });
      const payload2 = buildEmbeddingCommitmentPayload(attestationId, {
        model_id: 'all-MiniLM-L6-v2',
      });

      const result1 = await submitAdvance(payload1, TEST_ADDRESSES.admin);
      const result2 = await submitAdvance(payload2, TEST_ADDRESSES.admin);

      assertAccepted(result1);
      assertAccepted(result2);
    });

    it('should accept multiple commitments for same model with different nonces', async () => {
      const payload1 = buildEmbeddingCommitmentPayload(attestationId, {
        model_id: 'nonce-test-model',
        nonce: 'a'.repeat(64),
      });
      const payload2 = buildEmbeddingCommitmentPayload(attestationId, {
        model_id: 'nonce-test-model',
        nonce: 'b'.repeat(64),
      });

      const result1 = await submitAdvance(payload1, TEST_ADDRESSES.admin);
      const result2 = await submitAdvance(payload2, TEST_ADDRESSES.admin);

      assertAccepted(result1);
      assertAccepted(result2);
    });
  });

  describe('Validation', () => {
    it('should reject missing attested_input_ref', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      (payload as Record<string, unknown>).attested_input_ref = '';

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'attested_input_ref');
    });

    it('should reject missing model_id', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      (payload as Record<string, unknown>).model_id = '';

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'model_id');
    });

    it('should reject missing embedding_hash', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      (payload as Record<string, unknown>).embedding_hash = '';

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'embedding_hash');
    });

    it('should reject missing nonce', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      (payload as Record<string, unknown>).nonce = '';

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'nonce');
    });

    it('should reject missing commitment', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      (payload as Record<string, unknown>).commitment = '';

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'commitment');
    });

    it('should reject invalid embedding_hash format', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId, {
        embedding_hash: 'not-a-hex-hash',
      });

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'embedding_hash format');
    });

    it('should reject invalid commitment format', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId, {
        commitment: 'zzz-bad-format',
      });

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result, 'commitment format');
    });
  });

  describe('Access Control', () => {
    it('should reject submission from non-admin', async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId);
      const result = await submitAdvance(payload, TEST_ADDRESSES.unauthorized);

      assertRejected(result, 'Not authorized');
    });
  });

  describe('Foreign Key Validation', () => {
    it('should reject commitment for non-existent attestation', async () => {
      const payload = buildEmbeddingCommitmentPayload('non-existent-attestation-id');
      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);

      assertRejected(result, 'not found');
    });
  });

  describe('Duplicate Prevention', () => {
    it('should reject duplicate commitment (same ref + model + nonce)', async () => {
      const fixedNonce = 'c'.repeat(64);
      const payload = buildEmbeddingCommitmentPayload(attestationId, {
        model_id: 'dedup-test-model',
        nonce: fixedNonce,
      });

      const result1 = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertAccepted(result1);

      const result2 = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertRejected(result2, 'Duplicate');
    });
  });

  describe('Inspect Queries', () => {
    let commitmentId: number;
    const queryModelId = 'query-test-model';

    beforeAll(async () => {
      const payload = buildEmbeddingCommitmentPayload(attestationId, {
        model_id: queryModelId,
      });
      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertAccepted(result);

      const response = getResponse<{ id: number }>(result);
      commitmentId = response!.id;
    });

    it('should query commitment by ID', async () => {
      const result = await submitInspect('embedding_commitment', { id: String(commitmentId) });

      const response = getResponse<{
        commitment: {
          id: number;
          attested_input_ref: string;
          model_id: string;
          embedding_hash: string;
          nonce: string;
          commitment: string;
          submitted_by: string;
        };
      }>(result);

      expect(response?.commitment.id).toBe(commitmentId);
      expect(response?.commitment.attested_input_ref).toBe(attestationId);
      expect(response?.commitment.model_id).toBe(queryModelId);
      expect(response?.commitment.submitted_by).toBe(TEST_ADDRESSES.admin);
    });

    it('should return error for non-existent commitment ID', async () => {
      const result = await submitInspect('embedding_commitment', { id: '99999' });

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toContain('not found');
    });

    it('should query commitments by attested_input_ref', async () => {
      const result = await submitInspect('embedding_commitments_by_ref', {
        attested_input_ref: attestationId,
      });

      const response = getResponse<{
        attested_input_ref: string;
        count: number;
        commitments: Array<{ model_id: string }>;
      }>(result);

      expect(response?.attested_input_ref).toBe(attestationId);
      expect(response?.count).toBeGreaterThan(0);
      expect(response?.commitments.length).toBeGreaterThan(0);
    });

    it('should return empty results for non-existent ref', async () => {
      const result = await submitInspect('embedding_commitments_by_ref', {
        attested_input_ref: 'non-existent',
      });

      const response = getResponse<{ count: number; commitments: unknown[] }>(result);
      expect(response?.count).toBe(0);
      expect(response?.commitments).toHaveLength(0);
    });

    it('should query commitments by model_id', async () => {
      const result = await submitInspect('embedding_commitments_by_model', {
        model_id: queryModelId,
      });

      const response = getResponse<{
        model_id: string;
        count: number;
        commitments: Array<{ attested_input_ref: string }>;
      }>(result);

      expect(response?.model_id).toBe(queryModelId);
      expect(response?.count).toBeGreaterThan(0);
    });

    it('should paginate results', async () => {
      const result = await submitInspect('embedding_commitments_by_ref', {
        attested_input_ref: attestationId,
        limit: '2',
        offset: '0',
      });

      const response = getResponse<{
        count: number;
        commitments: unknown[];
      }>(result);

      expect(response?.count).toBeLessThanOrEqual(2);
    });

    it('should return embedding commitment stats', async () => {
      const result = await submitInspect('embedding_commitment_stats', {});

      const response = getResponse<{
        total_commitments: number;
        unique_models: number;
        unique_attestations: number;
        top_models: Array<{ model_id: string; count: number }>;
      }>(result);

      expect(response?.total_commitments).toBeGreaterThan(0);
      expect(response?.unique_models).toBeGreaterThan(0);
      expect(response?.unique_attestations).toBeGreaterThan(0);
      expect(response?.top_models.length).toBeGreaterThan(0);
    });
  });
});
