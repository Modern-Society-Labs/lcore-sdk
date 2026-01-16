/**
 * L{CORE} SDK
 *
 * Privacy-preserving attestation layer for off-chain data.
 *
 * @packageDocumentation
 */

// Main client
export { LCore, createLCoreFromEnv } from './client.js'

// Sub-clients
export { AttestorClient } from './attestor.js'
export { CartesiClient } from './cartesi.js'

// Types
export type {
  LCoreConfig,
  AttestRequest,
  AttestResult,
  QueryRequest,
  QueryResult,
  QueryParams,
  HttpProviderParams,
  SecretParams,
  AttestContext,
  ResponseMatch,
  ResponseRedaction,
  ProviderSchema,
  BucketDefinition,
  AccessGrant,
  AccessPermission,
  HealthStatus,
  LCoreErrorCode,
} from './types.js'

export { LCoreError } from './types.js'

// Utilities
export {
  hexEncode,
  hexDecode,
  encodeInspectQuery,
  buildInspectUrl,
  validateConfig,
} from './utils.js'
