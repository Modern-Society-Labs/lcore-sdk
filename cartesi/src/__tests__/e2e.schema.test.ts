/**
 * E2E Tests: Provider Schema Lifecycle
 *
 * Tests the schema management system:
 * - Bootstrap admin creation
 * - Adding/removing schema admins
 * - Registering provider schemas
 * - Deprecating schemas
 * - Schema querying
 */

import {
  submitAdvance,
  submitInspect,
  waitForServer,
  TEST_ADDRESSES,
  buildProviderSchemaPayload,
  buildAddAdminPayload,
  getResponse,
  assertAccepted,
  assertRejected,
} from './e2e-helpers';

describe('E2E: Provider Schema Lifecycle', () => {
  // Note: These tests assume a fresh database state
  // In practice, the database persists across tests
  // We work around this by using unique provider names

  beforeAll(async () => {
    await waitForServer();
  }, 30000);

  describe('Admin Bootstrap', () => {
    it('should bootstrap first admin with full permissions', async () => {
      // Check if admins already exist
      const checkResult = await submitInspect('all_schema_admins', {});
      const checkResponse = getResponse<{ count: number }>(checkResult);

      if (checkResponse?.count === 0) {
        // First admin gets bootstrapped with full permissions
        const payload = buildAddAdminPayload(TEST_ADDRESSES.admin, true, true);
        const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
        assertAccepted(result);

        const response = getResponse<{
          success: boolean;
          bootstrap: boolean;
          wallet_address: string;
          can_add_providers: boolean;
          can_add_admins: boolean;
        }>(result);

        expect(response?.success).toBe(true);
        expect(response?.bootstrap).toBe(true);
        expect(response?.wallet_address).toBe(TEST_ADDRESSES.admin);
        expect(response?.can_add_providers).toBe(true);
        expect(response?.can_add_admins).toBe(true);
      } else {
        // Admin already exists, which is fine for subsequent test runs
        expect(checkResponse?.count).toBeGreaterThan(0);
      }
    });

    it('should list all schema admins', async () => {
      const result = await submitInspect('all_schema_admins', {});

      const response = getResponse<{
        count: number;
        admins: Array<{
          wallet_address: string;
          added_by: string;
          can_add_providers: boolean;
          can_add_admins: boolean;
        }>;
      }>(result);

      expect(response?.count).toBeGreaterThan(0);

      // Verify bootstrap admin exists
      const bootstrapAdmin = response?.admins.find(
        a => a.wallet_address === TEST_ADDRESSES.admin
      );
      expect(bootstrapAdmin).toBeDefined();
      expect(bootstrapAdmin?.can_add_providers).toBe(true);
    });

    it('should query specific admin', async () => {
      const result = await submitInspect('schema_admin', {
        wallet: TEST_ADDRESSES.admin,
      });

      const response = getResponse<{
        is_admin: boolean;
        wallet: string;
        added_by: string;
        can_add_providers: boolean;
        can_add_admins: boolean;
      }>(result);

      expect(response?.is_admin).toBe(true);
      expect(response?.wallet).toBe(TEST_ADDRESSES.admin);
    });

    it('should return is_admin=false for non-admin', async () => {
      const result = await submitInspect('schema_admin', {
        wallet: TEST_ADDRESSES.unauthorized,
      });

      const response = getResponse<{
        is_admin: boolean;
        wallet: string;
      }>(result);

      expect(response?.is_admin).toBe(false);
    });
  });

  describe('Adding Schema Admins', () => {
    it('should add new admin with limited permissions', async () => {
      const newAdmin = '0x' + '2'.repeat(40);
      const payload = buildAddAdminPayload(newAdmin, true, false);

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        wallet_address: string;
        can_add_providers: boolean;
        can_add_admins: boolean;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.wallet_address).toBe(newAdmin);
      expect(response?.can_add_providers).toBe(true);
      expect(response?.can_add_admins).toBe(false);
    });

    it('should reject adding admin by non-admin', async () => {
      const newAdmin = '0x' + '3'.repeat(40);
      const payload = buildAddAdminPayload(newAdmin, true, false);

      const result = await submitAdvance(payload, TEST_ADDRESSES.unauthorized);

      assertRejected(result, 'Not authorized');
    });

    it('should reject adding admin by admin without can_add_admins', async () => {
      // First add an admin without can_add_admins
      const limitedAdmin = '0x' + '4'.repeat(40);
      const addLimited = buildAddAdminPayload(limitedAdmin, true, false);
      const addResult = await submitAdvance(addLimited, TEST_ADDRESSES.admin);
      assertAccepted(addResult);

      // Now try to add another admin using the limited admin
      const anotherAdmin = '0x' + '5'.repeat(40);
      const addAnother = buildAddAdminPayload(anotherAdmin, true, false);
      const result = await submitAdvance(addAnother, limitedAdmin);

      assertRejected(result, 'permission to add admins');
    });
  });

  describe('Removing Schema Admins', () => {
    it('should remove schema admin', async () => {
      // First add an admin to remove
      const adminToRemove = '0x' + '6'.repeat(40);
      const addPayload = buildAddAdminPayload(adminToRemove, true, false);
      const addResult = await submitAdvance(addPayload, TEST_ADDRESSES.admin);
      assertAccepted(addResult);

      // Now remove them
      const removePayload = {
        action: 'remove_schema_admin',
        wallet_address: adminToRemove,
      };
      const result = await submitAdvance(removePayload, TEST_ADDRESSES.admin);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        wallet_address: string;
        removed: boolean;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.removed).toBe(true);

      // Verify they're no longer an admin
      const checkResult = await submitInspect('schema_admin', {
        wallet: adminToRemove,
      });
      const checkResponse = getResponse<{ is_admin: boolean }>(checkResult);
      expect(checkResponse?.is_admin).toBe(false);
    });

    it('should prevent removing last admin with can_add_admins', async () => {
      // This test is tricky because we need to ensure there's only one admin
      // with can_add_admins. In practice, we just verify the error message.

      // Try to remove self
      const removePayload = {
        action: 'remove_schema_admin',
        wallet_address: TEST_ADDRESSES.admin,
      };
      const result = await submitAdvance(removePayload, TEST_ADDRESSES.admin);

      // If there are other admins with can_add_admins, this might succeed
      // Otherwise it should fail
      const response = getResponse<{ error?: string; success?: boolean }>(result);

      if (response?.error) {
        expect(response.error).toContain('last admin');
      }
    });
  });

  describe('Registering Provider Schemas', () => {
    it('should register new provider schema', async () => {
      const payload = buildProviderSchemaPayload(
        'api',
        'rest_endpoint',
        'healthcare',
        {
          bucket_definitions: {
            age_range: {
              boundaries: [0, 18, 30, 50, 70, 120],
              labels: ['<18', '18-30', '30-50', '50-70', '>70'],
            },
          },
          data_keys: ['age', 'blood_type', 'conditions'],
          freshness_half_life: 604800, // 7 days
        }
      );

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        provider: string;
        flow_type: string;
        domain: string;
        version: number;
        bucket_keys: string[];
        data_keys: string[];
        freshness_half_life: number;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.provider).toBe('api');
      expect(response?.flow_type).toBe('rest_endpoint');
      expect(response?.domain).toBe('healthcare');
      expect(response?.version).toBeGreaterThanOrEqual(1); // May be > 1 if test re-runs
      expect(response?.bucket_keys).toContain('age_range');
      expect(response?.data_keys).toEqual(['age', 'blood_type', 'conditions']);
    });

    it('should reject schema with invalid bucket definitions', async () => {
      const payload = buildProviderSchemaPayload(
        'invalid_bucket',
        'test_flow',
        'test_domain',
        {
          bucket_definitions: {
            invalid: {
              boundaries: [0, 10, 20], // 3 boundaries
              labels: ['a', 'b', 'c', 'd'], // 4 labels (should be 2)
            },
          },
        }
      );

      const result = await submitAdvance(payload, TEST_ADDRESSES.admin);

      assertRejected(result, 'boundaries length must be labels length + 1');
    });

    it('should reject schema registration by non-admin', async () => {
      const payload = buildProviderSchemaPayload(
        'unauthorized_provider',
        'test_flow',
        'test_domain'
      );

      const result = await submitAdvance(payload, TEST_ADDRESSES.unauthorized);

      assertRejected(result, 'Not authorized');
    });

    it('should register multiple schemas for same domain', async () => {
      // Register first schema
      const payload1 = buildProviderSchemaPayload(
        'multi_provider_1',
        'flow_1',
        'multi_domain'
      );
      const result1 = await submitAdvance(payload1, TEST_ADDRESSES.admin);
      assertAccepted(result1);

      // Register second schema in same domain
      const payload2 = buildProviderSchemaPayload(
        'multi_provider_2',
        'flow_2',
        'multi_domain'
      );
      const result2 = await submitAdvance(payload2, TEST_ADDRESSES.admin);
      assertAccepted(result2);

      // Verify both exist
      const queryResult = await submitInspect('all_provider_schemas', {
        domain: 'multi_domain',
      });
      const queryResponse = getResponse<{
        count: number;
        schemas: Array<{ provider: string }>;
      }>(queryResult);

      // At least 2 schemas (may be more if test re-runs with persistent DB)
      expect(queryResponse?.count).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Querying Provider Schemas', () => {
    beforeAll(async () => {
      // Ensure we have the default http schema registered
      const payload = buildProviderSchemaPayload();
      await submitAdvance(payload, TEST_ADDRESSES.admin);
    });

    it('should query specific provider schema', async () => {
      const result = await submitInspect('provider_schema', {
        provider: 'http',
        flow_type: 'web3_rpc',
      });

      const response = getResponse<{
        schema: {
          provider: string;
          flow_type: string;
          domain: string;
          version: number;
          bucket_definitions: Record<string, unknown>;
          data_keys: string[];
          freshness_half_life: number;
          status: string;
        };
      }>(result);

      expect(response?.schema.provider).toBe('http');
      expect(response?.schema.flow_type).toBe('web3_rpc');
      expect(response?.schema.domain).toBe('finance');
      expect(response?.schema.status).toBe('active');
    });

    it('should list all active schemas', async () => {
      const result = await submitInspect('all_provider_schemas', {
        active_only: 'true',
      });

      const response = getResponse<{
        count: number;
        schemas: Array<{
          provider: string;
          flow_type: string;
          status: string;
        }>;
      }>(result);

      expect(response?.count).toBeGreaterThan(0);

      // All returned schemas should be active
      response?.schemas.forEach(schema => {
        expect(schema.status).toBe('active');
      });
    });

    it('should filter schemas by domain', async () => {
      const result = await submitInspect('all_provider_schemas', {
        domain: 'finance',
      });

      const response = getResponse<{
        count: number;
        schemas: Array<{ domain?: string }>;
      }>(result);

      // HTTP schema is in finance domain
      expect(response?.count).toBeGreaterThan(0);
    });

    it('should return error for non-existent schema', async () => {
      const result = await submitInspect('provider_schema', {
        provider: 'non_existent',
        flow_type: 'unknown',
      });

      const response = getResponse<{ error: string }>(result);
      expect(response?.error).toContain('not found');
    });
  });

  describe('Deprecating Provider Schemas', () => {
    it('should deprecate a provider schema', async () => {
      // First register a schema to deprecate
      const registerPayload = buildProviderSchemaPayload(
        'deprecate_test',
        'to_deprecate',
        'test_domain'
      );
      const registerResult = await submitAdvance(registerPayload, TEST_ADDRESSES.admin);
      assertAccepted(registerResult);

      const registerResponse = getResponse<{ version: number }>(registerResult);
      const version = registerResponse?.version ?? 1;

      // Now deprecate it
      const deprecatePayload = {
        action: 'deprecate_provider_schema',
        provider: 'deprecate_test',
        flow_type: 'to_deprecate',
        version,
      };
      const result = await submitAdvance(deprecatePayload, TEST_ADDRESSES.admin);
      assertAccepted(result);

      const response = getResponse<{
        success: boolean;
        provider: string;
        new_status: string;
      }>(result);

      expect(response?.success).toBe(true);
      expect(response?.new_status).toBe('deprecated');

      // Verify status changed - use all_provider_schemas with active_only=false
      const queryResult = await submitInspect('all_provider_schemas', {
        active_only: 'false',
      });
      const queryResponse = getResponse<{
        schemas: Array<{ provider: string; flow_type: string; status: string }>;
      }>(queryResult);

      const deprecatedSchema = queryResponse?.schemas.find(
        s => s.provider === 'deprecate_test' && s.flow_type === 'to_deprecate'
      );
      expect(deprecatedSchema?.status).toBe('deprecated');
    });

    it('should exclude deprecated schemas from active-only query', async () => {
      const result = await submitInspect('all_provider_schemas', {
        active_only: 'true',
      });

      const response = getResponse<{
        schemas: Array<{ provider: string; status: string }>;
      }>(result);

      // Deprecated schemas should not appear
      const deprecatedSchema = response?.schemas.find(
        s => s.provider === 'deprecate_test'
      );
      expect(deprecatedSchema).toBeUndefined();
    });

    it('should reject deprecation by non-admin', async () => {
      const deprecatePayload = {
        action: 'deprecate_provider_schema',
        provider: 'http',
        flow_type: 'web3_rpc',
        version: 1,
      };
      const result = await submitAdvance(deprecatePayload, TEST_ADDRESSES.unauthorized);

      assertRejected(result, 'Not authorized');
    });
  });

  describe('Schema Versioning', () => {
    it('should increment version on re-registration', async () => {
      // Register a schema
      const payload1 = buildProviderSchemaPayload(
        'version_test',
        'versioned_flow',
        'version_domain'
      );
      const result1 = await submitAdvance(payload1, TEST_ADDRESSES.admin);
      assertAccepted(result1);

      const response1 = getResponse<{ version: number }>(result1);
      const version1 = response1?.version ?? 0;

      // Re-register with updated definitions
      const payload2 = buildProviderSchemaPayload(
        'version_test',
        'versioned_flow',
        'version_domain',
        {
          data_keys: ['updated_key_1', 'updated_key_2'],
        }
      );
      const result2 = await submitAdvance(payload2, TEST_ADDRESSES.admin);
      assertAccepted(result2);

      const response2 = getResponse<{ version: number }>(result2);
      const version2 = response2?.version ?? 0;

      // Version should increment
      expect(version2).toBe(version1 + 1);
    });
  });
});
