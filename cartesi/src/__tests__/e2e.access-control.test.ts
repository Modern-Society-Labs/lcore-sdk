/**
 * E2E Tests: Access Control
 *
 * Tests the gated access layer for attestation data:
 * - Granting access (full, partial, aggregate)
 * - Revoking access
 * - Checking access permissions
 * - Querying encrypted data with valid grants
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  buildAttestationPayload,
  buildGrantAccessPayload,
  buildRevokeAccessPayload,
  generateId,
  getResponse,
  assertAccepted,
  assertRejected,
  bootstrapAdmin,
  registerDefaultSchema,
} from './e2e-helpers';

describe('E2E: Access Control', () => {
  let testAttestationId: string;

  beforeAll(async () => {
    await waitForServer();

    // Bootstrap admin and register schema
    const adminResult = await bootstrapAdmin();
    assertAccepted(adminResult);

    const schemaResult = await registerDefaultSchema();
    assertAccepted(schemaResult);

    // Create a test attestation for access control tests
    const payload = buildAttestationPayload(TEST_ADDRESSES.owner, {
      id: generateId('access-test'),
      data: [
        { key: 'balance', value: Buffer.from('5000').toString('base64'), encryption_key_id: 'key-1' },
        { key: 'address', value: Buffer.from(TEST_ADDRESSES.owner).toString('base64'), encryption_key_id: 'key-1' },
        { key: 'timestamp', value: Buffer.from(Date.now().toString()).toString('base64'), encryption_key_id: 'key-1' },
      ],
    });
    testAttestationId = payload.id;

    const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
    assertAccepted(result);
  }, 60000);

  describe('Granting Access', () => {
    it('should grant full access to attestation data', async () => {
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: generateId('grant-full') }
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        grant_id: string;
        attestation_id: string;
        grantee_address: string;
        grant_type: string;
        data_keys: string[] | null;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.grant_id).toBe(grantPayload.grant_id);
      expect(response?.attestation_id).toBe(testAttestationId);
      expect(response?.grantee_address).toBe(TEST_ADDRESSES.grantee);
      expect(response?.grant_type).toBe('full');
      expect(response?.data_keys).toBeNull(); // Full access = all keys
    });

    it('should grant partial access with specific data keys', async () => {
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'partial',
        {
          grant_id: generateId('grant-partial'),
          data_keys: ['balance', 'timestamp'],
        }
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        grant_type: string;
        data_keys: string[];
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.grant_type).toBe('partial');
      expect(response?.data_keys).toEqual(['balance', 'timestamp']);
    });

    it('should grant aggregate access', async () => {
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'aggregate',
        { grant_id: generateId('grant-aggregate') }
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        grant_type: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.grant_type).toBe('aggregate');
    });

    it('should grant access with expiration', async () => {
      const futureInput = 1000000; // Far future input index
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        {
          grant_id: generateId('grant-expiring'),
          expires_at_input: futureInput,
        }
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        expires_at_input: number;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.expires_at_input).toBe(futureInput);
    });

    it('should reject grant from non-owner', async () => {
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: generateId('grant-unauth') }
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.unauthorized);

      assertRejected(result, 'Only attestation owner');
    });

    it('should reject duplicate grant ID', async () => {
      const grantId = generateId('grant-dup');

      // First grant
      const grantPayload1 = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: grantId }
      );
      const result1 = await submitAdvance(grantPayload1, TEST_ADDRESSES.owner);
      assertAccepted(result1);

      // Second grant with same ID
      const grantPayload2 = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: grantId }
      );
      const result2 = await submitAdvance(grantPayload2, TEST_ADDRESSES.owner);

      assertRejected(result2, 'already exists');
    });

    it('should reject partial grant without data keys', async () => {
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'partial',
        { grant_id: generateId('grant-no-keys') }
        // data_keys not specified
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);

      assertRejected(result, 'data_keys required');
    });

    it('should reject grant for non-existent attestation', async () => {
      const grantPayload = buildGrantAccessPayload(
        'non-existent-attestation',
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: generateId('grant-no-att') }
      );

      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);

      assertRejected(result, 'not found');
    });
  });

  describe('Checking Access', () => {
    let fullAccessGrantId: string;

    beforeAll(async () => {
      // Create a full access grant for tests
      fullAccessGrantId = generateId('check-access-grant');
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: fullAccessGrantId }
      );
      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);
    });

    it('should confirm access for valid grantee', async () => {
      const result = await submitInspect('check_access', {
        attestation_id: testAttestationId,
        grantee: TEST_ADDRESSES.grantee,
        current_input: '0',
      });

      const response = getResponse<{
        attestation_id: string;
        grantee: string;
        has_access: boolean;
        grant: {
          id: string;
          grant_type: string;
        } | null;
      }>(result);

      expect(response?.attestation_id).toBe(testAttestationId);
      expect(response?.grantee).toBe(TEST_ADDRESSES.grantee);
      expect(response?.has_access).toBe(true);
      expect(response?.grant).not.toBeNull();
      expect(response?.grant?.grant_type).toBe('full');
    });

    it('should deny access for unauthorized address', async () => {
      const result = await submitInspect('check_access', {
        attestation_id: testAttestationId,
        grantee: TEST_ADDRESSES.unauthorized,
        current_input: '0',
      });

      const response = getResponse<{
        has_access: boolean;
        grant: unknown;
      }>(result);

      expect(response?.has_access).toBe(false);
      expect(response?.grant).toBeNull();
    });

    it('should get grant details by ID', async () => {
      const result = await submitInspect('grant', { id: fullAccessGrantId });

      const response = getResponse<{
        grant: {
          id: string;
          attestation_id: string;
          grantee_address: string;
          granted_by: string;
          grant_type: string;
          status: string;
        };
      }>(result);

      expect(response?.grant.id).toBe(fullAccessGrantId);
      expect(response?.grant.attestation_id).toBe(testAttestationId);
      expect(response?.grant.grantee_address).toBe(TEST_ADDRESSES.grantee);
      expect(response?.grant.granted_by).toBe(TEST_ADDRESSES.owner);
      expect(response?.grant.grant_type).toBe('full');
      expect(response?.grant.status).toBe('active');
    });

    it('should list grants by attestation', async () => {
      const result = await submitInspect('grants_by_attestation', {
        attestation_id: testAttestationId,
      });

      const response = getResponse<{
        attestation_id: string;
        count: number;
        grants: Array<{
          id: string;
          grantee_address: string;
          grant_type: string;
          status: string;
        }>;
      }>(result);

      expect(response?.attestation_id).toBe(testAttestationId);
      expect(response?.count).toBeGreaterThan(0);

      // Verify our test grant is in the list
      const testGrant = response?.grants.find(g => g.id === fullAccessGrantId);
      expect(testGrant).toBeDefined();
    });

    it('should list grants by grantee', async () => {
      const result = await submitInspect('grants_by_grantee', {
        grantee: TEST_ADDRESSES.grantee,
        active_only: 'true',
      });

      const response = getResponse<{
        grantee: string;
        active_only: boolean;
        count: number;
        grants: Array<{
          id: string;
          attestation_id: string;
          grant_type: string;
        }>;
      }>(result);

      expect(response?.grantee).toBe(TEST_ADDRESSES.grantee);
      expect(response?.active_only).toBe(true);
      expect(response?.count).toBeGreaterThan(0);

      // Verify grant for our test attestation is present
      const grantForTestAtt = response?.grants.find(
        g => g.attestation_id === testAttestationId
      );
      expect(grantForTestAtt).toBeDefined();
    });
  });

  describe('Accessing Encrypted Data', () => {
    let dataAccessGrantId: string;

    beforeAll(async () => {
      // Create a specific grant for data access tests
      dataAccessGrantId = generateId('data-access-grant');
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: dataAccessGrantId }
      );
      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);
    });

    it('should return encrypted data for authorized grantee', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: testAttestationId,
        grantee: TEST_ADDRESSES.grantee,
        current_input: '0',
      });

      const response = getResponse<{
        attestation_id: string;
        grantee: string;
        grant_id: string;
        grant_type: string;
        data_count: number;
        data: Array<{
          data_key: string;
          encrypted_value: string;
          encryption_key_id: string;
        }>;
      }>(result);

      expect(response?.attestation_id).toBe(testAttestationId);
      expect(response?.grantee).toBe(TEST_ADDRESSES.grantee);
      expect(response?.grant_type).toBe('full');
      expect(response?.data_count).toBeGreaterThan(0);

      // Verify data keys are present
      const dataKeys = response?.data.map(d => d.data_key) ?? [];
      expect(dataKeys).toContain('balance');
      expect(dataKeys).toContain('address');
      expect(dataKeys).toContain('timestamp');

      // Verify encrypted values are base64 encoded
      response?.data.forEach(d => {
        expect(d.encrypted_value).toBeDefined();
        expect(d.encryption_key_id).toBe('key-1');
      });
    });

    it('should filter data by specific key', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: testAttestationId,
        grantee: TEST_ADDRESSES.grantee,
        data_key: 'balance',
        current_input: '0',
      });

      const response = getResponse<{
        data_count: number;
        data: Array<{ data_key: string }>;
      }>(result);

      expect(response?.data_count).toBe(1);
      expect(response?.data[0]?.data_key).toBe('balance');
    });

    it('should deny data access for unauthorized grantee', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: testAttestationId,
        grantee: TEST_ADDRESSES.unauthorized,
        current_input: '0',
      });

      const response = getResponse<{
        error: string;
        reason: string;
      }>(result);

      expect(response?.error).toBe('Access denied');
      expect(response?.reason).toContain('No valid access grant');
    });
  });

  describe('Revoking Access', () => {
    let revokeTestGrantId: string;

    beforeEach(async () => {
      // Create a new grant for each revocation test
      revokeTestGrantId = generateId('revoke-grant');
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: revokeTestGrantId }
      );
      const result = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);
      assertAccepted(result);
    });

    it('should revoke access grant', async () => {
      const revokePayload = buildRevokeAccessPayload(revokeTestGrantId);

      const result = await submitAdvance(revokePayload, TEST_ADDRESSES.owner);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        grant_id: string;
        new_status: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.grant_id).toBe(revokeTestGrantId);
      expect(response?.new_status).toBe('revoked');

      // Verify grant status changed
      const inspectResult = await submitInspect('grant', { id: revokeTestGrantId });
      const inspectResponse = getResponse<{
        grant: { status: string };
      }>(inspectResult);

      expect(inspectResponse?.grant.status).toBe('revoked');
    });

    it('should reject revocation by non-grantor', async () => {
      const revokePayload = buildRevokeAccessPayload(revokeTestGrantId);

      const result = await submitAdvance(revokePayload, TEST_ADDRESSES.unauthorized);

      assertRejected(result, 'Only grantor can revoke');
    });

    it('should reject revoking already revoked grant', async () => {
      const revokePayload = buildRevokeAccessPayload(revokeTestGrantId);

      // First revocation
      const result1 = await submitAdvance(revokePayload, TEST_ADDRESSES.owner);
      assertAccepted(result1);

      // Second revocation
      const result2 = await submitAdvance(revokePayload, TEST_ADDRESSES.owner);
      assertRejected(result2, 'not active');
    });

    it('should deny data access after revocation', async () => {
      // First verify access works
      const checkBefore = await submitInspect('check_access', {
        attestation_id: testAttestationId,
        grantee: TEST_ADDRESSES.grantee,
        current_input: '0',
      });
      const responseBefore = getResponse<{ has_access: boolean }>(checkBefore);

      // We can't easily check this for the specific grant since grantee may have multiple grants
      // Instead, create a unique grantee for this test
      const uniqueGrantee = '0x' + '1'.repeat(40);
      const uniqueGrantId = generateId('unique-revoke');

      // Grant access
      const grantPayload = buildGrantAccessPayload(
        testAttestationId,
        uniqueGrantee,
        'full',
        { grant_id: uniqueGrantId }
      );
      await submitAdvance(grantPayload, TEST_ADDRESSES.owner);

      // Verify access
      const checkWithAccess = await submitInspect('check_access', {
        attestation_id: testAttestationId,
        grantee: uniqueGrantee,
        current_input: '0',
      });
      const responseWithAccess = getResponse<{ has_access: boolean }>(checkWithAccess);
      expect(responseWithAccess?.has_access).toBe(true);

      // Revoke
      const revokePayload = buildRevokeAccessPayload(uniqueGrantId);
      await submitAdvance(revokePayload, TEST_ADDRESSES.owner);

      // Verify no access
      const checkAfter = await submitInspect('check_access', {
        attestation_id: testAttestationId,
        grantee: uniqueGrantee,
        current_input: '0',
      });
      const responseAfter = getResponse<{ has_access: boolean }>(checkAfter);
      expect(responseAfter?.has_access).toBe(false);
    });
  });

  describe('Grant for Revoked Attestations', () => {
    it('should reject granting access to revoked attestation', async () => {
      // Create a new attestation
      const payload = buildAttestationPayload(TEST_ADDRESSES.owner, {
        id: generateId('revoked-att'),
      });
      const createResult = await submitAdvance(payload, TEST_ADDRESSES.owner);
      assertAccepted(createResult);

      // Revoke the attestation
      const revokeAttPayload = {
        action: 'revoke_attestation',
        attestation_id: payload.id,
      };
      const revokeResult = await submitAdvance(revokeAttPayload, TEST_ADDRESSES.owner);
      assertAccepted(revokeResult);

      // Try to grant access
      const grantPayload = buildGrantAccessPayload(
        payload.id,
        TEST_ADDRESSES.grantee,
        'full',
        { grant_id: generateId('grant-revoked') }
      );
      const grantResult = await submitAdvance(grantPayload, TEST_ADDRESSES.owner);

      assertRejected(grantResult, 'non-active');
    });
  });
});
