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
export { IdentityClient } from './identity.js'

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
  KYCProviderInfo,
  StartVerificationParams,
  StartVerificationResult,
  KYCSessionStatus,
  IdentityAttestation,
  IdentityStats,
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

// IoT Provider Helpers
export {
  awsIotShadow,
  azureIotTwin,
  gcpIotDevice,
  thingsBoard,
  homeAssistant,
  genericApi,
  createIoTRequest,
} from './iot.js'

export type {
  AwsIotShadowConfig,
  AzureIotTwinConfig,
  GcpIotDeviceConfig,
  ThingsBoardConfig,
  HomeAssistantConfig,
  GenericApiConfig,
  IoTProviderConfig,
} from './iot.js'

// Device Identity (did:key support)
export { DeviceIdentity, publicKeyToDIDKey, createJWS } from './device.js'
