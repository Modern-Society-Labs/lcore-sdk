/**
 * E2E Tests: Discovery & Aggregate Queries
 *
 * Tests the privacy-preserving discovery layer:
 * - Bucket-based queries
 * - Domain queries
 * - Count aggregations
 * - Freshness statistics
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  buildAttestationPayload,
  generateId,
  getResponse,
  assertAccepted,
  bootstrapAdmin,
  registerDefaultSchema,
} from './e2e-helpers';

describe('E2E: Discovery & Aggregate Queries', () => {
  // Track created attestations for cleanup/verification
  const createdAttestationIds: string[] = [];

  beforeAll(async () => {
    await waitForServer();

    // Bootstrap admin and register schema
    const adminResult = await bootstrapAdmin();
    assertAccepted(adminResult);

    const schemaResult = await registerDefaultSchema();
    assertAccepted(schemaResult);

    // Create multiple attestations with different bucket values for testing
    const bucketValues = ['<1K', '1K-10K', '10K-100K', '>100K'];

    for (let i = 0; i < bucketValues.length; i++) {
      for (let j = 0; j <= i; j++) {
        // Create more attestations in higher brackets
        const payload = buildAttestationPayload(TEST_ADDRESSES.owner, {
          id: generateId(`discovery-${bucketValues[i]}-${j}`),
          buckets: [{ key: 'balance_range', value: bucketValues[i]! }],
        });

        const result = await submitAdvance(payload, TEST_ADDRESSES.owner);
        assertAccepted(result);
        createdAttestationIds.push(payload.id);
      }
    }
  }, 120000);

  describe('Bucket-Based Queries', () => {
    it('should query attestations by specific bucket value', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'finance',
        bucket_key: 'balance_range',
        bucket_value: '1K-10K',
      });

      const response = getResponse<{
        query: {
          domain: string;
          bucket_key: string;
          bucket_value: string;
        };
        count: number;
        attestations: Array<{
          id: string;
          owner_address: string;
          freshness_score: number;
          buckets: Array<{ key: string; value: string }>;
        }>;
      }>(result);

      expect(response?.query.domain).toBe('finance');
      expect(response?.query.bucket_key).toBe('balance_range');
      expect(response?.query.bucket_value).toBe('1K-10K');
      expect(response?.count).toBeGreaterThan(0);

      // Verify all returned attestations have the correct bucket value
      response?.attestations.forEach(att => {
        const hasBucket = att.buckets.some(
          b => b.key === 'balance_range' && b.value === '1K-10K'
        );
        expect(hasBucket).toBe(true);
      });
    });

    it('should filter by provider within bucket query', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'finance',
        provider: 'http',
        bucket_key: 'balance_range',
        bucket_value: '10K-100K',
      });

      const response = getResponse<{
        count: number;
        attestations: Array<{ provider: string }>;
      }>(result);

      expect(response?.count).toBeGreaterThan(0);
      response?.attestations.forEach(att => {
        expect(att.provider).toBe('http');
      });
    });

    it('should respect limit and offset in bucket queries', async () => {
      // First page
      const result1 = await submitInspect('query_by_bucket', {
        domain: 'finance',
        bucket_key: 'balance_range',
        bucket_value: '>100K',
        limit: '2',
        offset: '0',
      });

      const response1 = getResponse<{
        count: number;
        attestations: Array<{ id: string }>;
      }>(result1);

      expect(response1?.attestations.length).toBeLessThanOrEqual(2);

      // Second page
      const result2 = await submitInspect('query_by_bucket', {
        domain: 'finance',
        bucket_key: 'balance_range',
        bucket_value: '>100K',
        limit: '2',
        offset: '2',
      });

      const response2 = getResponse<{
        attestations: Array<{ id: string }>;
      }>(result2);

      // IDs should not overlap between pages
      if (response1?.attestations && response2?.attestations) {
        const ids1 = new Set(response1.attestations.map(a => a.id));
        response2.attestations.forEach(att => {
          expect(ids1.has(att.id)).toBe(false);
        });
      }
    });

    it('should return empty for non-existent bucket values', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'finance',
        bucket_key: 'balance_range',
        bucket_value: 'non-existent-value',
      });

      const response = getResponse<{ count: number }>(result);
      expect(response?.count).toBe(0);
    });

    it('should require domain parameter', async () => {
      const result = await submitInspect('query_by_bucket', {
        bucket_key: 'balance_range',
        bucket_value: '1K-10K',
      });

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toContain('domain');
    });
  });

  describe('Domain Queries', () => {
    it('should query attestations by domain', async () => {
      const result = await submitInspect('query_by_domain', {
        domain: 'finance',
      });

      const response = getResponse<{
        query: { domain: string };
        count: number;
        attestations: Array<{ id: string; domain?: string }>;
      }>(result);

      expect(response?.query.domain).toBe('finance');
      expect(response?.count).toBeGreaterThan(0);
    });

    it('should filter by provider and flow type', async () => {
      const result = await submitInspect('query_by_domain', {
        domain: 'finance',
        provider: 'http',
        flow_type: 'web3_rpc',
      });

      const response = getResponse<{
        query: { provider: string; flow_type: string };
        attestations: Array<{ provider: string; flow_type: string }>;
      }>(result);

      response?.attestations.forEach(att => {
        expect(att.provider).toBe('http');
        expect(att.flow_type).toBe('web3_rpc');
      });
    });

    it('should filter by status', async () => {
      const result = await submitInspect('query_by_domain', {
        domain: 'finance',
        status: 'active',
      });

      const response = getResponse<{
        query: { status: string };
        count: number;
      }>(result);

      expect(response?.query.status).toBe('active');
      expect(response?.count).toBeGreaterThan(0);
    });
  });

  describe('Count Aggregations', () => {
    it('should count attestations by bucket value', async () => {
      const result = await submitInspect('count_by_bucket', {
        domain: 'finance',
        bucket_key: 'balance_range',
      });

      const response = getResponse<{
        query: { domain: string; bucket_key: string };
        total: number;
        distribution: Array<{
          bucket_value: string;
          label: string;
          count: number;
        }>;
      }>(result);

      expect(response?.query.domain).toBe('finance');
      expect(response?.query.bucket_key).toBe('balance_range');
      expect(response?.total).toBeGreaterThan(0);

      // Verify distribution adds up to total
      const distributionSum = response?.distribution.reduce((sum, d) => sum + d.count, 0);
      expect(distributionSum).toBe(response?.total);

      // Verify we have distribution for known bucket values
      const bucketValues = response?.distribution.map(d => d.bucket_value) ?? [];
      expect(bucketValues.length).toBeGreaterThan(0);
    });

    it('should filter count by provider', async () => {
      const result = await submitInspect('count_by_bucket', {
        domain: 'finance',
        provider: 'http',
        bucket_key: 'balance_range',
      });

      const response = getResponse<{
        query: { provider: string };
        total: number;
      }>(result);

      expect(response?.query.provider).toBe('http');
      expect(response?.total).toBeGreaterThan(0);
    });

    it('should count attestations by domain', async () => {
      const result = await submitInspect('count_by_domain', {});

      const response = getResponse<{
        total: number;
        domains: Array<{ domain: string; count: number }>;
      }>(result);

      expect(response?.total).toBeGreaterThan(0);

      // Verify finance domain has attestations
      const financeDomain = response?.domains.find(d => d.domain === 'finance');
      expect(financeDomain?.count).toBeGreaterThan(0);
    });

    it('should count attestations by provider within domain', async () => {
      const result = await submitInspect('count_by_provider', {
        domain: 'finance',
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

      expect(response?.domain).toBe('finance');
      expect(response?.total).toBeGreaterThan(0);

      // Verify http provider exists
      const httpProvider = response?.providers.find(p => p.provider === 'http');
      expect(httpProvider?.count).toBeGreaterThan(0);
    });
  });

  describe('Freshness Statistics', () => {
    it('should return freshness statistics for domain', async () => {
      const result = await submitInspect('freshness_stats', {
        domain: 'finance',
      });

      const response = getResponse<{
        query: { domain: string };
        statistics: {
          total_count: number;
          avg_freshness: number;
          min_freshness: number;
          max_freshness: number;
        };
        tiers: Array<{
          tier: string;
          range: string;
          count: number;
        }>;
      }>(result);

      expect(response?.query.domain).toBe('finance');
      expect(response?.statistics.total_count).toBeGreaterThan(0);

      // Freshness scores should be between 0-100
      expect(response?.statistics.avg_freshness).toBeGreaterThanOrEqual(0);
      expect(response?.statistics.avg_freshness).toBeLessThanOrEqual(100);

      // Verify tier structure
      expect(response?.tiers).toHaveLength(5); // excellent, good, fair, stale, expired
      const tierNames = response?.tiers.map(t => t.tier) ?? [];
      expect(tierNames).toContain('excellent');
      expect(tierNames).toContain('good');
      expect(tierNames).toContain('fair');
      expect(tierNames).toContain('stale');
      expect(tierNames).toContain('expired');
    });

    it('should filter freshness stats by provider', async () => {
      const result = await submitInspect('freshness_stats', {
        domain: 'finance',
        provider: 'http',
      });

      const response = getResponse<{
        query: { provider: string };
        statistics: { total_count: number };
      }>(result);

      expect(response?.query.provider).toBe('http');
    });
  });

  describe('Schema Discovery', () => {
    it('should list available providers', async () => {
      const result = await submitInspect('available_providers', {});

      const response = getResponse<{
        active_only: boolean;
        total_schemas: number;
        domains: Array<{
          domain: string;
          provider_count: number;
          providers: Array<{
            provider: string;
            flow_type: string;
            version: number;
            bucket_keys: string[];
            data_keys: string[];
          }>;
        }>;
      }>(result);

      expect(response?.total_schemas).toBeGreaterThan(0);

      // Verify finance domain exists
      const financeDomain = response?.domains.find(d => d.domain === 'finance');
      expect(financeDomain).toBeDefined();
      expect(financeDomain?.provider_count).toBeGreaterThan(0);

      // Verify http provider
      const httpProvider = financeDomain?.providers.find(p => p.provider === 'http');
      expect(httpProvider?.flow_type).toBe('web3_rpc');
      expect(httpProvider?.bucket_keys).toContain('balance_range');
    });

    it('should filter available providers by domain', async () => {
      const result = await submitInspect('available_providers', {
        domain: 'finance',
      });

      const response = getResponse<{
        domain_filter: string;
        domains: Array<{ domain: string }>;
      }>(result);

      expect(response?.domain_filter).toBe('finance');
      response?.domains.forEach(d => {
        expect(d.domain).toBe('finance');
      });
    });

    it('should get bucket definition for provider', async () => {
      const result = await submitInspect('bucket_definition', {
        provider: 'http',
        flow_type: 'web3_rpc',
      });

      const response = getResponse<{
        provider: string;
        flow_type: string;
        domain: string;
        version: number;
        bucket_definitions: Array<{
          bucket_key: string;
          boundaries: number[];
          labels: string[];
          bucket_count: number;
        }>;
        freshness_half_life: number;
      }>(result);

      expect(response?.provider).toBe('http');
      expect(response?.flow_type).toBe('web3_rpc');
      expect(response?.domain).toBe('finance');

      // Verify bucket definitions
      const balanceRange = response?.bucket_definitions.find(
        b => b.bucket_key === 'balance_range'
      );
      expect(balanceRange).toBeDefined();
      expect(balanceRange?.labels).toEqual(['<1K', '1K-10K', '10K-100K', '>100K']);
      expect(balanceRange?.boundaries).toEqual([0, 1000, 10000, 100000, 1000000]);
    });

    it('should return error for non-existent schema', async () => {
      const result = await submitInspect('bucket_definition', {
        provider: 'non_existent',
        flow_type: 'unknown',
      });

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toContain('not found');
    });
  });
});
