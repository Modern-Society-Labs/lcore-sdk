/**
 * L{CORE} SDK - Handler Index
 *
 * Central export for all L{CORE} SDK handlers.
 * Import from this file to get all handlers configured for the router.
 */

// ============= Attestation Handlers =============
export {
  handleIngestAttestation,
  handleRevokeAttestation,
  handleSupersedeAttestation,
  handleInspectAttestation,
  handleInspectAttestationsByOwner,
} from './lcore-attestation';

// ============= Access Control Handlers =============
export {
  handleGrantAccess,
  handleRevokeAccess,
  handleInspectCheckAccess,
  handleInspectGrant,
  handleInspectGrantsByAttestation,
  handleInspectGrantsByGrantee,
  handleInspectAttestationData,
} from './lcore-access';

// ============= Provider Schema Handlers =============
export {
  handleRegisterProviderSchema,
  handleDeprecateProviderSchema,
  handleAddSchemaAdmin,
  handleRemoveSchemaAdmin,
  handleInspectProviderSchema,
  handleInspectAllProviderSchemas,
  handleInspectSchemaAdmin,
  handleInspectAllSchemaAdmins,
} from './lcore-schema';

// ============= Discovery & Aggregate Handlers =============
export {
  handleInspectQueryByBucket,
  handleInspectQueryByDomain,
  handleInspectCountByBucket,
  handleInspectCountByDomain,
  handleInspectCountByProvider,
  handleInspectFreshnessStats,
  handleInspectAvailableProviders,
  handleInspectBucketDefinition,
} from './lcore-discovery';

// ============= Encryption Handlers =============
export {
  handleSetEncryptionKey,
  handleInspectEncryptionConfig,
  handleInspectEncryptionStatus,
} from './lcore-encryption';

// ============= Route Configuration =============

import { RouteConfig } from '../router';

// Import all handlers
import {
  handleIngestAttestation,
  handleRevokeAttestation,
  handleSupersedeAttestation,
  handleInspectAttestation,
  handleInspectAttestationsByOwner,
} from './lcore-attestation';

import {
  handleGrantAccess,
  handleRevokeAccess,
  handleInspectCheckAccess,
  handleInspectGrant,
  handleInspectGrantsByAttestation,
  handleInspectGrantsByGrantee,
  handleInspectAttestationData,
} from './lcore-access';

import {
  handleRegisterProviderSchema,
  handleDeprecateProviderSchema,
  handleAddSchemaAdmin,
  handleRemoveSchemaAdmin,
  handleInspectProviderSchema,
  handleInspectAllProviderSchemas,
  handleInspectSchemaAdmin,
  handleInspectAllSchemaAdmins,
} from './lcore-schema';

import {
  handleInspectQueryByBucket,
  handleInspectQueryByDomain,
  handleInspectCountByBucket,
  handleInspectCountByDomain,
  handleInspectCountByProvider,
  handleInspectFreshnessStats,
  handleInspectAvailableProviders,
  handleInspectBucketDefinition,
} from './lcore-discovery';

import {
  handleSetEncryptionKey,
  handleInspectEncryptionConfig,
  handleInspectEncryptionStatus,
} from './lcore-encryption';

/**
 * L{CORE} SDK Route Configuration
 *
 * Ready-to-use configuration for all L{CORE} SDK handlers.
 * Import this and pass to createRouter() or merge with your own routes.
 */
export const lcoreRouteConfig: RouteConfig = {
  advance: {
    // Attestation management (from TEE/Attestor)
    ingest_attestation: handleIngestAttestation,
    revoke_attestation: handleRevokeAttestation,
    supersede_attestation: handleSupersedeAttestation,

    // Access control (for dApps)
    grant_access: handleGrantAccess,
    revoke_access: handleRevokeAccess,

    // Schema management (for admins)
    register_provider_schema: handleRegisterProviderSchema,
    deprecate_provider_schema: handleDeprecateProviderSchema,
    add_schema_admin: handleAddSchemaAdmin,
    remove_schema_admin: handleRemoveSchemaAdmin,

    // Encryption management (for admins)
    set_encryption_key: handleSetEncryptionKey,
  },
  inspect: {
    // Attestation queries
    attestation: handleInspectAttestation,
    attestations_by_owner: handleInspectAttestationsByOwner,

    // Access control queries
    check_access: handleInspectCheckAccess,
    grant: handleInspectGrant,
    grants_by_attestation: handleInspectGrantsByAttestation,
    grants_by_grantee: handleInspectGrantsByGrantee,
    attestation_data: handleInspectAttestationData,

    // Schema queries
    provider_schema: handleInspectProviderSchema,
    all_provider_schemas: handleInspectAllProviderSchemas,
    schema_admin: handleInspectSchemaAdmin,
    all_schema_admins: handleInspectAllSchemaAdmins,

    // Discovery queries (bucket-based)
    query_by_bucket: handleInspectQueryByBucket,
    query_by_domain: handleInspectQueryByDomain,

    // Aggregate queries (privacy-preserving)
    count_by_bucket: handleInspectCountByBucket,
    count_by_domain: handleInspectCountByDomain,
    count_by_provider: handleInspectCountByProvider,
    freshness_stats: handleInspectFreshnessStats,

    // Schema discovery
    available_providers: handleInspectAvailableProviders,
    bucket_definition: handleInspectBucketDefinition,

    // Encryption queries
    encryption_config: handleInspectEncryptionConfig,
    encryption_status: handleInspectEncryptionStatus,
  },
};

/**
 * Merge L{CORE} routes with custom routes.
 * L{CORE} routes take precedence for duplicate keys.
 */
export function mergeLCoreRoutes(customConfig: Partial<RouteConfig>): RouteConfig {
  return {
    advance: {
      ...(customConfig.advance || {}),
      ...lcoreRouteConfig.advance,
    },
    inspect: {
      ...(customConfig.inspect || {}),
      ...lcoreRouteConfig.inspect,
    },
  };
}
