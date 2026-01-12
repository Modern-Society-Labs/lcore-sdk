/**
 * E2E Tests: CoinGecko Price Attestation Flow
 *
 * Tests the complete attestor-to-Cartesi flow using the real CoinGecko example:
 * - Based on example/coin-gecko.json
 * - Simulates TEE attestor fetching crypto prices from CoinGecko API
 * - Privacy-preserving price discovery via buckets
 * - Access control for exact price data
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  buildCoinGeckoSchemaPayload,
  buildCoinGeckoPriceAttestation,
  buildGrantAccessPayload,
  buildAddAdminPayload,
  generateId,
  getResponse,
  assertAccepted,
  assertRejected,
} from './e2e-helpers';

describe('E2E: CoinGecko Price Attestation Flow', () => {
  const PRICE_ORACLE_OWNER = TEST_ADDRESSES.owner;
  const ADMIN = TEST_ADDRESSES.admin;
  const DEFI_DAPP = TEST_ADDRESSES.grantee;
  const TRADING_BOT = '0x' + 'b'.repeat(40);

  beforeAll(async () => {
    await waitForServer();

    // Bootstrap admin if needed
    const checkResult = await submitInspect('all_schema_admins', {});
    const checkResponse = getResponse<{ count: number }>(checkResult);

    if (checkResponse?.count === 0) {
      const adminPayload = buildAddAdminPayload(ADMIN, true, true);
      await submitAdvance(adminPayload, ADMIN);
    }

    // Register CoinGecko price schema
    const schemaPayload = buildCoinGeckoSchemaPayload();
    const schemaResult = await submitAdvance(schemaPayload, ADMIN);
    // Schema may already exist, so we don't assert here
  }, 60000);

  describe('CoinGecko Schema Registration', () => {
    it('should have CoinGecko price schema registered', async () => {
      const result = await submitInspect('provider_schema', {
        provider: 'http',
        flow_type: 'coingecko_price',
      });

      const response = getResponse<{
        schema: {
          provider: string;
          flow_type: string;
          domain: string;
          bucket_definitions: Record<string, unknown>;
          data_keys: string[];
          freshness_half_life: number;
        };
      }>(result);

      expect(response?.schema.provider).toBe('http');
      expect(response?.schema.flow_type).toBe('coingecko_price');
      expect(response?.schema.domain).toBe('crypto_prices');
      expect(response?.schema.data_keys).toContain('cardanoPrice');
      expect(response?.schema.data_keys).toContain('solanaPrice');
      expect(response?.schema.freshness_half_life).toBe(300); // 5 minutes
    });

    it('should have correct bucket definitions for price ranges', async () => {
      const result = await submitInspect('bucket_definition', {
        provider: 'http',
        flow_type: 'coingecko_price',
      });

      const response = getResponse<{
        bucket_definitions: Array<{
          bucket_key: string;
          labels: string[];
          boundaries: number[];
        }>;
      }>(result);

      const priceRange = response?.bucket_definitions.find(
        b => b.bucket_key === 'price_range_usd'
      );
      expect(priceRange?.labels).toContain('micro');
      expect(priceRange?.labels).toContain('sub-dollar');
      expect(priceRange?.labels).toContain('premium');

      const priceChange = response?.bucket_definitions.find(
        b => b.bucket_key === 'price_change_24h'
      );
      expect(priceChange?.labels).toContain('crash');
      expect(priceChange?.labels).toContain('moon');
    });
  });

  describe('Price Attestation Ingestion', () => {
    let priceAttestationId: string;

    it('should ingest Cardano price attestation (sub-dollar range)', async () => {
      const payload = buildCoinGeckoPriceAttestation(PRICE_ORACLE_OWNER, {
        cardanoPrice: 0.85,
        solanaPrice: 145.23,
      });
      priceAttestationId = payload.id;

      const result = await submitAdvance(payload, PRICE_ORACLE_OWNER);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        attestation_id: string;
        domain: string;
        provider: string;
        flow_type: string;
        buckets_count: number;
        data_keys_count: number;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.domain).toBe('crypto_prices');
      expect(response?.provider).toBe('http');
      expect(response?.flow_type).toBe('coingecko_price');
      expect(response?.buckets_count).toBe(2);
      expect(response?.data_keys_count).toBe(4);
    });

    it('should verify attestation stored with correct buckets', async () => {
      const result = await submitInspect('attestation', { id: priceAttestationId });

      const response = getResponse<{
        attestation: {
          id: string;
          domain: string;
          status: string;
        };
        buckets: Array<{ key: string; value: string }>;
      }>(result);

      expect(response?.attestation.domain).toBe('crypto_prices');
      expect(response?.attestation.status).toBe('active');

      const priceRange = response?.buckets.find(b => b.key === 'price_range_usd');
      expect(priceRange?.value).toBe('sub-dollar');

      const priceChange = response?.buckets.find(b => b.key === 'price_change_24h');
      expect(priceChange?.value).toBe('slight_up');
    });

    it('should ingest multiple price attestations with different ranges', async () => {
      // Micro price token (< $0.01)
      const microPayload = buildCoinGeckoPriceAttestation(PRICE_ORACLE_OWNER, {
        id: generateId('micro-token'),
        cardanoPrice: 0.005,
        solanaPrice: 150,
      });
      const microResult = await submitAdvance(microPayload, PRICE_ORACLE_OWNER);
      assertAccepted(microResult);

      // Premium price token (> $1000)
      const premiumPayload = buildCoinGeckoPriceAttestation(PRICE_ORACLE_OWNER, {
        id: generateId('premium-token'),
        cardanoPrice: 2500,
        solanaPrice: 150,
        priceRangeBucket: 'premium',
      });
      const premiumResult = await submitAdvance(premiumPayload, PRICE_ORACLE_OWNER);
      assertAccepted(premiumResult);
    });
  });

  describe('Privacy-Preserving Price Discovery', () => {
    it('should discover all sub-dollar token attestations', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'crypto_prices',
        bucket_key: 'price_range_usd',
        bucket_value: 'sub-dollar',
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
          provider: string;
          buckets: Array<{ key: string; value: string }>;
        }>;
      }>(result);

      expect(response?.query.domain).toBe('crypto_prices');
      expect(response?.count).toBeGreaterThan(0);

      // All returned attestations should be in sub-dollar range
      response?.attestations.forEach(att => {
        const priceRange = att.buckets.find(b => b.key === 'price_range_usd');
        expect(priceRange?.value).toBe('sub-dollar');
      });
    });

    it('should count tokens by price range (market overview)', async () => {
      const result = await submitInspect('count_by_bucket', {
        domain: 'crypto_prices',
        bucket_key: 'price_range_usd',
      });

      const response = getResponse<{
        total: number;
        distribution: Array<{
          bucket_value: string;
          label: string;
          count: number;
        }>;
      }>(result);

      expect(response?.total).toBeGreaterThan(0);

      // Log the distribution (useful for debugging)
      console.log('Price range distribution:', response?.distribution);

      // Verify we have attestations in expected ranges
      const subDollar = response?.distribution.find(d => d.bucket_value === 'sub-dollar');
      expect(subDollar?.count).toBeGreaterThan(0);
    });

    it('should filter bullish tokens (price_change_24h)', async () => {
      const result = await submitInspect('query_by_bucket', {
        domain: 'crypto_prices',
        bucket_key: 'price_change_24h',
        bucket_value: 'slight_up',
      });

      const response = getResponse<{
        count: number;
        attestations: Array<{
          id: string;
          buckets: Array<{ key: string; value: string }>;
        }>;
      }>(result);

      expect(response?.count).toBeGreaterThan(0);
    });
  });

  describe('DeFi DApp Access Flow', () => {
    let priceAttestationId: string;
    let accessGrantId: string;

    beforeAll(async () => {
      // Create a fresh attestation for access control tests
      const payload = buildCoinGeckoPriceAttestation(PRICE_ORACLE_OWNER, {
        id: generateId('access-test-price'),
        cardanoPrice: 0.92,
        solanaPrice: 155.50,
      });
      priceAttestationId = payload.id;

      const result = await submitAdvance(payload, PRICE_ORACLE_OWNER);
      assertAccepted(result);
    });

    it('should grant full access to DeFi DApp', async () => {
      accessGrantId = generateId('defi-access');

      const grantPayload = buildGrantAccessPayload(
        priceAttestationId,
        DEFI_DAPP,
        'full',
        { grant_id: accessGrantId }
      );

      const result = await submitAdvance(grantPayload, PRICE_ORACLE_OWNER);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        grant_type: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.grant_type).toBe('full');
    });

    it('should allow DeFi DApp to retrieve exact prices', async () => {
      const result = await submitInspect('attestation_data', {
        attestation_id: priceAttestationId,
        grantee: DEFI_DAPP,
        current_input: '0',
      });

      const response = getResponse<{
        attestation_id: string;
        grant_type: string;
        data: Array<{
          data_key: string;
          encrypted_value: string;
          encryption_key_id: string;
        }>;
      }>(result);

      expect(response?.grant_type).toBe('full');

      // Decode and verify prices
      const cardanoData = response?.data.find(d => d.data_key === 'cardanoPrice');
      const cardanoPrice = Buffer.from(
        cardanoData?.encrypted_value ?? '',
        'base64'
      ).toString('utf8');
      expect(cardanoPrice).toBe('0.92');

      const solanaData = response?.data.find(d => d.data_key === 'solanaPrice');
      const solanaPrice = Buffer.from(
        solanaData?.encrypted_value ?? '',
        'base64'
      ).toString('utf8');
      expect(solanaPrice).toBe('155.5');

      // Verify source URL is included
      const sourceData = response?.data.find(d => d.data_key === 'source_url');
      const sourceUrl = Buffer.from(
        sourceData?.encrypted_value ?? '',
        'base64'
      ).toString('utf8');
      expect(sourceUrl).toContain('coingecko.com');
    });

    it('should grant partial access to trading bot (only prices, no source)', async () => {
      const partialGrantId = generateId('bot-partial');

      const grantPayload = buildGrantAccessPayload(
        priceAttestationId,
        TRADING_BOT,
        'partial',
        {
          grant_id: partialGrantId,
          data_keys: ['cardanoPrice', 'solanaPrice'],
        }
      );

      const result = await submitAdvance(grantPayload, PRICE_ORACLE_OWNER);
      assertAccepted(result);

      // Trading bot can only see prices
      const dataResult = await submitInspect('attestation_data', {
        attestation_id: priceAttestationId,
        grantee: TRADING_BOT,
        current_input: '0',
      });

      const dataResponse = getResponse<{
        grant_type: string;
        data: Array<{ data_key: string }>;
      }>(dataResult);

      expect(dataResponse?.grant_type).toBe('partial');
      const dataKeys = dataResponse?.data.map(d => d.data_key) ?? [];
      expect(dataKeys).toContain('cardanoPrice');
      expect(dataKeys).toContain('solanaPrice');
      expect(dataKeys).not.toContain('source_url');
      expect(dataKeys).not.toContain('timestamp');
    });

    it('should deny access to unauthorized addresses', async () => {
      const unauthorized = '0x' + 'c'.repeat(40);

      const result = await submitInspect('attestation_data', {
        attestation_id: priceAttestationId,
        grantee: unauthorized,
        current_input: '0',
      });

      const response = getResponse<{
        error: string;
      }>(result);

      expect(response?.error).toBe('Access denied');
    });
  });

  describe('Price Update (Attestation Supersession)', () => {
    let oldPriceAttestationId: string;
    let newPriceAttestationId: string;

    beforeAll(async () => {
      // Create initial price attestation
      const oldPayload = buildCoinGeckoPriceAttestation(PRICE_ORACLE_OWNER, {
        id: generateId('old-price'),
        cardanoPrice: 0.80,
        solanaPrice: 140,
      });
      oldPriceAttestationId = oldPayload.id;
      await submitAdvance(oldPayload, PRICE_ORACLE_OWNER);
    });

    it('should create updated price attestation', async () => {
      const newPayload = buildCoinGeckoPriceAttestation(PRICE_ORACLE_OWNER, {
        id: generateId('new-price'),
        cardanoPrice: 0.95, // Price went up
        solanaPrice: 160,
      });
      newPriceAttestationId = newPayload.id;

      const result = await submitAdvance(newPayload, PRICE_ORACLE_OWNER);
      assertAccepted(result);
    });

    it('should supersede old price with new price', async () => {
      const supersedePayload = {
        action: 'supersede_attestation',
        old_attestation_id: oldPriceAttestationId,
        new_attestation_id: newPriceAttestationId,
      };

      const result = await submitAdvance(supersedePayload, PRICE_ORACLE_OWNER);
      assertAccepted(result);

      // Verify old attestation is superseded
      const oldResult = await submitInspect('attestation', { id: oldPriceAttestationId });
      const oldResponse = getResponse<{
        attestation: { status: string };
      }>(oldResult);
      expect(oldResponse?.attestation.status).toBe('superseded');

      // Verify new attestation is active
      const newResult = await submitInspect('attestation', { id: newPriceAttestationId });
      const newResponse = getResponse<{
        attestation: { status: string };
      }>(newResult);
      expect(newResponse?.attestation.status).toBe('active');
    });
  });

  describe('Crypto Prices Statistics', () => {
    it('should show freshness stats for crypto_prices domain', async () => {
      const result = await submitInspect('freshness_stats', {
        domain: 'crypto_prices',
      });

      const response = getResponse<{
        statistics: {
          total_count: number;
          avg_freshness: number;
          min_freshness: number;
          max_freshness: number;
        };
        tiers: Array<{ tier: string; count: number }>;
      }>(result);

      expect(response?.statistics.total_count).toBeGreaterThan(0);

      // New attestations should be fresh
      expect(response?.statistics.avg_freshness).toBeGreaterThan(50);

      console.log('Crypto prices freshness:', response?.statistics);
    });

    it('should count attestations by provider in crypto domain', async () => {
      const result = await submitInspect('count_by_provider', {
        domain: 'crypto_prices',
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

      expect(response?.domain).toBe('crypto_prices');
      expect(response?.total).toBeGreaterThan(0);

      const coingecko = response?.providers.find(
        p => p.flow_type === 'coingecko_price'
      );
      expect(coingecko?.count).toBeGreaterThan(0);
    });
  });
});
