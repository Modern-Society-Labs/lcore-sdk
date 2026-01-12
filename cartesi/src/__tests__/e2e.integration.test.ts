/**
 * E2E Integration Tests: Full Attestor-Cartesi Flow
 *
 * Tests the complete lifecycle from attestation creation to data access:
 * 1. Bootstrap admin and register schema
 * 2. Ingest attestation (simulating TEE attestor)
 * 3. Verify storage via queries
 * 4. Grant access to third party
 * 5. Third party retrieves encrypted data
 * 6. Revoke access and verify denial
 * 7. Supersede attestation with fresh data
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  buildProviderSchemaPayload,
  buildAttestationPayload,
  buildGrantAccessPayload,
  buildAddAdminPayload,
  generateId,
  generateHash,
  generateSignature,
  getResponse,
  assertAccepted,
  assertRejected,
} from './e2e-helpers';

describe('E2E Integration: Complete Attestor-Cartesi Flow', () => {
  // Test state shared across the integration test
  let attestationId: string;
  let attestationHash: string;
  let accessGrantId: string;

  const OWNER = TEST_ADDRESSES.owner;
  const ADMIN = TEST_ADDRESSES.admin;
  const DAPP = TEST_ADDRESSES.grantee;
  const VERIFIER = '0x' + 'a'.repeat(40);

  beforeAll(async () => {
    await waitForServer();
  }, 30000);

  describe('Phase 1: System Setup', () => {
    it('Step 1.1: Bootstrap schema admin', async () => {
      // Check if admin already exists
      const checkResult = await submitInspect('all_schema_admins', {});
      const checkResponse = getResponse<{ count: number }>(checkResult);

      if (checkResponse?.count === 0) {
        const payload = buildAddAdminPayload(ADMIN, true, true);
        const result = await submitAdvance(payload, ADMIN);
        assertAccepted(result);
      }

      // Verify admin exists
      const verifyResult = await submitInspect('schema_admin', { wallet: ADMIN });
      const verifyResponse = getResponse<{ is_admin: boolean }>(verifyResult);
      expect(verifyResponse?.is_admin).toBe(true);
    });

    it('Step 1.2: Register DeFi balance verification schema', async () => {
      const schemaPayload = buildProviderSchemaPayload(
        'defi_balance',
        'rpc_attestation',
        'defi',
        {
          bucket_definitions: {
            balance_tier: {
              boundaries: [0, 100, 1000, 10000, 100000, 1000000000],
              labels: ['dust', 'small', 'medium', 'large', 'whale'],
            },
            chain: {
              boundaries: [0, 1, 2, 3],
              labels: ['ethereum', 'polygon', 'arbitrum'],
            },
          },
          data_keys: ['exact_balance', 'token_address', 'block_number', 'timestamp'],
          freshness_half_life: 3600, // 1 hour for DeFi data
          min_freshness: 50,
        }
      );

      const result = await submitAdvance(schemaPayload, ADMIN);
      assertAccepted(result);

      // Verify schema
      const verifyResult = await submitInspect('provider_schema', {
        provider: 'defi_balance',
        flow_type: 'rpc_attestation',
      });
      const verifyResponse = getResponse<{
        schema: { domain: string; bucket_definitions: unknown };
      }>(verifyResult);

      expect(verifyResponse?.schema.domain).toBe('defi');
    });
  });

  describe('Phase 2: Attestation Ingestion (TEE Simulation)', () => {
    it('Step 2.1: TEE attestor ingests balance verification', async () => {
      attestationId = generateId('defi-att');
      attestationHash = generateHash();

      const attestationPayload = buildAttestationPayload(OWNER, {
        id: attestationId,
        attestation_hash: attestationHash,
        provider: 'defi_balance',
        flow_type: 'rpc_attestation',
        valid_from: Math.floor(Date.now() / 1000),
        valid_until: Math.floor(Date.now() / 1000) + 86400, // 24h validity
        tee_signature: generateSignature(),
        buckets: [
          { key: 'balance_tier', value: 'large' },
          { key: 'chain', value: 'ethereum' },
        ],
        data: [
          {
            key: 'exact_balance',
            value: Buffer.from('50000.123456').toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
          {
            key: 'token_address',
            value: Buffer.from('0xdac17f958d2ee523a2206206994597c13d831ec7').toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
          {
            key: 'block_number',
            value: Buffer.from('18500000').toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
          {
            key: 'timestamp',
            value: Buffer.from(Date.now().toString()).toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
        ],
      });

      const result = await submitAdvance(attestationPayload, OWNER);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        attestation_id: string;
        domain: string;
        buckets_count: number;
        data_keys_count: number;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.attestation_id).toBe(attestationId);
      expect(response?.domain).toBe('defi');
      expect(response?.buckets_count).toBe(2);
      expect(response?.data_keys_count).toBe(4);
    });

    it('Step 2.2: Verify attestation stored correctly', async () => {
      const result = await submitInspect('attestation', { id: attestationId });

      const response = getResponse<{
        attestation: {
          id: string;
          attestation_hash: string;
          owner_address: string;
          domain: string;
          provider: string;
          status: string;
        };
        buckets: Array<{ key: string; value: string }>;
      }>(result);

      expect(response?.attestation.id).toBe(attestationId);
      expect(response?.attestation.attestation_hash).toBe(attestationHash);
      expect(response?.attestation.owner_address).toBe(OWNER);
      expect(response?.attestation.domain).toBe('defi');
      expect(response?.attestation.status).toBe('active');

      // Verify buckets
      const balanceTier = response?.buckets.find(b => b.key === 'balance_tier');
      expect(balanceTier?.value).toBe('large');
    });
  });

  describe('Phase 3: Privacy-Preserving Discovery', () => {
    it('Step 3.1: DApp discovers "large" balance holders on Ethereum', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'defi',
        bucket_key: 'balance_tier',
        bucket_value: 'large',
      });

      const response = getResponse<{
        count: number;
        attestations: Array<{
          id: string;
          owner_address: string;
          buckets: Array<{ key: string; value: string }>;
        }>;
      }>(result);

      expect(response?.count).toBeGreaterThan(0);

      // Our attestation should be in the results
      const ourAttestation = response?.attestations.find(a => a.id === attestationId);
      expect(ourAttestation).toBeDefined();
      expect(ourAttestation?.owner_address).toBe(OWNER);
    });

    it('Step 3.2: DApp checks distribution of balance tiers', async () => {
      const result = await submitInspect('count_by_bucket', {
        domain: 'defi',
        bucket_key: 'balance_tier',
      });

      const response = getResponse<{
        total: number;
        distribution: Array<{
          bucket_value: string;
          count: number;
        }>;
      }>(result);

      expect(response?.total).toBeGreaterThan(0);

      // "large" tier should have at least 1
      const largeTier = response?.distribution.find(d => d.bucket_value === 'large');
      expect(largeTier?.count).toBeGreaterThan(0);
    });
  });

  describe('Phase 4: Access Control & Data Retrieval', () => {
    it('Step 4.1: Owner grants full access to DApp', async () => {
      accessGrantId = generateId('dapp-access');

      const grantPayload = buildGrantAccessPayload(
        attestationId,
        DAPP,
        'full',
        { grant_id: accessGrantId }
      );

      const result = await submitAdvance(grantPayload, OWNER);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        grant_id: string;
        grant_type: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.grant_type).toBe('full');
    });

    it('Step 4.2: DApp verifies it has access', async () => {
      const result = await submitInspect('check_access', {
        attestation_id: attestationId,
        grantee: DAPP,
        current_input: '0',
      });

      const response = getResponse<{
        has_access: boolean;
        grant: { grant_type: string };
      }>(result);

      expect(response?.has_access).toBe(true);
      expect(response?.grant.grant_type).toBe('full');
    });

    it('Step 4.3: DApp retrieves encrypted data', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: attestationId,
        grantee: DAPP,
        current_input: '0',
      });

      const response = getResponse<{
        attestation_id: string;
        grant_type: string;
        data_count: number;
        data: Array<{
          data_key: string;
          encrypted_value: string;
          encryption_key_id: string;
        }>;
      }>(result);

      expect(response?.attestation_id).toBe(attestationId);
      expect(response?.data_count).toBe(4);

      // Verify all data keys present
      const dataKeys = response?.data.map(d => d.data_key) ?? [];
      expect(dataKeys).toContain('exact_balance');
      expect(dataKeys).toContain('token_address');
      expect(dataKeys).toContain('block_number');
      expect(dataKeys).toContain('timestamp');

      // Verify encrypted values are base64
      const balanceData = response?.data.find(d => d.data_key === 'exact_balance');
      expect(balanceData?.encryption_key_id).toBe('owner-key-1');

      // Decode and verify (DApp would decrypt with owner's key)
      const decodedBalance = Buffer.from(
        balanceData?.encrypted_value ?? '',
        'base64'
      ).toString('utf8');
      expect(decodedBalance).toBe('50000.123456');
    });

    it('Step 4.4: Unauthorized verifier cannot access data', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: attestationId,
        grantee: VERIFIER,
        current_input: '0',
      });

      const response = getResponse<{
        error: string;
        reason: string;
      }>(result);

      expect(response?.error).toBe('Access denied');
    });

    it('Step 4.5: Owner grants partial access to verifier', async () => {
      const partialGrantId = generateId('verifier-partial');

      const grantPayload = buildGrantAccessPayload(
        attestationId,
        VERIFIER,
        'partial',
        {
          grant_id: partialGrantId,
          data_keys: ['exact_balance'], // Only balance, not full details
        }
      );

      const result = await submitAdvance(grantPayload, OWNER);
      assertAccepted(result);

      // Verifier can now access only balance
      const dataResult = await submitInspect('attestation_data', {
        attestation_id: attestationId,
        grantee: VERIFIER,
        current_input: '0',
      });

      const dataResponse = getResponse<{
        data_count: number;
        data: Array<{ data_key: string }>;
      }>(dataResult);

      expect(dataResponse?.data_count).toBe(1);
      expect(dataResponse?.data[0]?.data_key).toBe('exact_balance');
    });
  });

  describe('Phase 5: Access Revocation', () => {
    it('Step 5.1: Owner revokes DApp access', async () => {
      const revokePayload = {
        action: 'revoke_access',
        grant_id: accessGrantId,
      };

      const result = await submitAdvance(revokePayload, OWNER);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        new_status: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.new_status).toBe('revoked');
    });

    it('Step 5.2: DApp no longer has access', async () => {
      const result = await submitInspect('check_access', {
        attestation_id: attestationId,
        grantee: DAPP,
        current_input: '0',
      });

      const response = getResponse<{ has_access: boolean }>(result);
      expect(response?.has_access).toBe(false);
    });

    it('Step 5.3: DApp cannot retrieve data', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: attestationId,
        grantee: DAPP,
        current_input: '0',
      });

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toBe('Access denied');
    });
  });

  describe('Phase 6: Attestation Supersession', () => {
    let newAttestationId: string;

    it('Step 6.1: TEE creates fresh attestation with updated balance', async () => {
      newAttestationId = generateId('defi-att-v2');

      const newAttestationPayload = buildAttestationPayload(OWNER, {
        id: newAttestationId,
        attestation_hash: generateHash(),
        provider: 'defi_balance',
        flow_type: 'rpc_attestation',
        valid_from: Math.floor(Date.now() / 1000),
        tee_signature: generateSignature(),
        buckets: [
          { key: 'balance_tier', value: 'whale' }, // Balance increased!
          { key: 'chain', value: 'ethereum' },
        ],
        data: [
          {
            key: 'exact_balance',
            value: Buffer.from('1500000.00').toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
          {
            key: 'token_address',
            value: Buffer.from('0xdac17f958d2ee523a2206206994597c13d831ec7').toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
          {
            key: 'block_number',
            value: Buffer.from('18600000').toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
          {
            key: 'timestamp',
            value: Buffer.from(Date.now().toString()).toString('base64'),
            encryption_key_id: 'owner-key-1',
          },
        ],
      });

      const result = await submitAdvance(newAttestationPayload, OWNER);
      assertAccepted(result);
    });

    it('Step 6.2: Owner supersedes old attestation', async () => {
      const supersedePayload = {
        action: 'supersede_attestation',
        old_attestation_id: attestationId,
        new_attestation_id: newAttestationId,
      };

      const result = await submitAdvance(supersedePayload, OWNER);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        old_status: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.old_status).toBe('superseded');
    });

    it('Step 6.3: Old attestation marked as superseded', async () => {
      const result = await submitInspect('attestation', { id: attestationId });

      const response = getResponse<{
        attestation: { status: string };
      }>(result);

      expect(response?.attestation.status).toBe('superseded');
    });

    it('Step 6.4: New attestation is active', async () => {
      const result = await submitInspect('attestation', { id: newAttestationId });

      const response = getResponse<{
        attestation: { status: string };
        buckets: Array<{ key: string; value: string }>;
      }>(result);

      expect(response?.attestation.status).toBe('active');

      // Verify updated balance tier
      const balanceTier = response?.buckets.find(b => b.key === 'balance_tier');
      expect(balanceTier?.value).toBe('whale');
    });

    it('Step 6.5: Discovery now shows whale tier', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'defi',
        bucket_key: 'balance_tier',
        bucket_value: 'whale',
      });

      const response = getResponse<{
        count: number;
        attestations: Array<{ id: string }>;
      }>(result);

      expect(response?.count).toBeGreaterThan(0);

      // New attestation should be discoverable
      const newAtt = response?.attestations.find(a => a.id === newAttestationId);
      expect(newAtt).toBeDefined();
    });
  });

  describe('Phase 7: System Statistics', () => {
    it('Step 7.1: View domain statistics', async () => {
      const result = await submitInspect('count_by_domain', {});

      const response = getResponse<{
        total: number;
        domains: Array<{ domain: string; count: number }>;
      }>(result);

      expect(response?.total).toBeGreaterThan(0);

      const defiDomain = response?.domains.find(d => d.domain === 'defi');
      expect(defiDomain?.count).toBeGreaterThan(0);
    });

    it('Step 7.2: View provider statistics', async () => {
      const result = await submitInspect('count_by_provider', {
        domain: 'defi',
      });

      const response = getResponse<{
        domain: string;
        total: number;
        providers: Array<{
          provider: string;
          flow_type: string;
          count: number;
        }>;
      }>(result);

      expect(response?.domain).toBe('defi');

      const defiBalance = response?.providers.find(
        p => p.provider === 'defi_balance'
      );
      expect(defiBalance?.count).toBeGreaterThan(0);
    });

    it('Step 7.3: View freshness statistics', async () => {
      const result = await submitInspect('freshness_stats', {
        domain: 'defi',
      });

      const response = getResponse<{
        statistics: {
          total_count: number;
          avg_freshness: number;
        };
        tiers: Array<{ tier: string; count: number }>;
      }>(result);

      expect(response?.statistics.total_count).toBeGreaterThan(0);
      // Fresh attestations should have high freshness scores
      expect(response?.statistics.avg_freshness).toBeGreaterThan(50);
    });
  });
});
