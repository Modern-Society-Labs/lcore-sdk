/**
 * L{CORE} SDK Type Definitions
 */

// ============= Configuration =============

export interface LCoreConfig {
  /** URL of the L{CORE} attestor (e.g., http://localhost:8001) */
  attestorUrl: string
  /** URL of the Cartesi node (e.g., http://localhost:10000) */
  cartesiUrl: string
  /** Cartesi DApp address on Arbitrum */
  dappAddress: string
  /** Optional: RPC URL for blockchain interactions */
  rpcUrl?: string
  /** Optional: Request timeout in milliseconds (default: 30000) */
  timeout?: number
}

// ============= Attestation =============

export interface AttestRequest {
  /** Provider name (e.g., 'http') */
  provider: string
  /** Provider-specific parameters */
  params: HttpProviderParams | Record<string, unknown>
  /** Optional: Secret parameters (headers, cookies) - not included in proof */
  secretParams?: SecretParams
  /** Optional: Context for the attestation */
  context?: AttestContext
}

export interface HttpProviderParams {
  /** URL to fetch data from (supports {{paramValues}} placeholders) */
  url: string
  /** HTTP method (default: GET) */
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  /** Request body for POST/PUT */
  body?: string
  /** URL parameter values to substitute */
  paramValues?: Record<string, string>
  /** Response validation rules */
  responseMatches?: ResponseMatch[]
  /** Fields to extract and redact from response */
  responseRedactions?: ResponseRedaction[]
}

export interface SecretParams {
  /** Headers to include but not expose in proof */
  headers?: Record<string, string>
  /** Cookies to include but not expose in proof */
  cookies?: Record<string, string>
}

export interface AttestContext {
  /** Address that will receive the attestation */
  receiver?: string
  /** Timestamp for the attestation */
  timestamp?: number
  /** Additional metadata */
  metadata?: Record<string, unknown>
}

export interface ResponseMatch {
  /** Match type */
  type: 'contains' | 'regex' | 'exact'
  /** Value to match */
  value: string
}

export interface ResponseRedaction {
  /** JSON path to extract (e.g., 'data.temperature') */
  jsonPath?: string
  /** Regex pattern to extract */
  regex?: string
  /** Start index for substring extraction */
  startIndex?: number
  /** End index for substring extraction */
  endIndex?: number
}

export interface AttestResult {
  /** Whether attestation succeeded */
  success: boolean
  /** Claim ID if successful */
  claimId?: string
  /** Extracted data from the attestation */
  extractedData?: Record<string, unknown>
  /** Transaction hash if submitted on-chain */
  txHash?: string
  /** Error message if failed */
  error?: string
}

// ============= Query =============

export interface QueryRequest {
  /** Query type */
  type: 'attestation' | 'provider_schemas' | 'bucket' | 'access_grants'
  /** Query parameters */
  params?: QueryParams
}

export interface QueryParams {
  /** Claim ID for attestation queries */
  claimId?: string
  /** Provider name for schema queries */
  provider?: string
  /** Bucket ID for bucket queries */
  bucketId?: string
  /** Address for access grant queries */
  address?: string
  /** Pagination limit */
  limit?: number
  /** Pagination offset */
  offset?: number
}

export interface QueryResult<T = unknown> {
  /** Whether query succeeded */
  success: boolean
  /** Query result data */
  data?: T
  /** Error message if failed */
  error?: string
}

// ============= Provider Schemas =============

export interface ProviderSchema {
  /** Provider identifier */
  provider: string
  /** Flow type (e.g., 'http') */
  flowType: string
  /** Domain being attested */
  domain: string
  /** Bucket definitions for privacy */
  bucketDefinitions: Record<string, BucketDefinition>
  /** Data keys to extract */
  dataKeys: string[]
  /** Freshness half-life in seconds */
  freshnessHalfLife: number
  /** Minimum freshness score (0-1) */
  minFreshness?: number
}

export interface BucketDefinition {
  /** Bucket boundaries */
  boundaries: number[]
  /** Labels for each bucket */
  labels: string[]
}

// ============= Access Control =============

export interface AccessGrant {
  /** Grantee address */
  grantee: string
  /** Bucket ID being accessed */
  bucketId: string
  /** Expiration timestamp */
  expiresAt: number
  /** Grant permissions */
  permissions: AccessPermission[]
}

export type AccessPermission = 'read' | 'aggregate' | 'export'

// ============= Health & Status =============

export interface HealthStatus {
  /** Overall health status */
  status: 'ok' | 'degraded' | 'down'
  /** Attestor version */
  version?: string
  /** Whether L{CORE} features are enabled */
  lcoreEnabled?: boolean
  /** Cartesi node connection status */
  cartesiConnected?: boolean
  /** Last block processed */
  lastBlock?: number
}

// ============= Identity / KYC (zkIdentity) =============

export interface KYCProviderInfo {
  /** Provider identifier (e.g., 'smile_id') */
  name: string
  /** Human-readable display name */
  displayName: string
  /** ISO 3166-1 alpha-2 country codes supported */
  supportedCountries: string[]
  /** Whether running in stub/test mode */
  stubMode: boolean
}

export interface StartVerificationParams {
  /** User's did:key identifier */
  userDid: string
  /** KYC provider to use (e.g., 'smile_id') */
  provider: string
  /** Wallet signature authorizing verification */
  walletSignature: string
  /** Timestamp from signature message */
  timestamp: number
  /** Optional: country hint */
  country?: string
  /** Optional: verification level */
  jobType?: 'basic' | 'document' | 'biometric'
}

export interface StartVerificationResult {
  /** KYC session identifier */
  sessionId: string
  /** Provider name */
  provider: string
  /** URL for user to complete verification */
  verificationUrl: string
  /** Session expiry (unix timestamp) */
  expiresAt: number
}

export interface KYCSessionStatus {
  /** Session identifier */
  sessionId: string
  /** Provider name */
  provider: string
  /** Current status */
  status: 'pending' | 'completed' | 'failed' | 'expired'
  /** User's did:key */
  user_did: string
}

export interface IdentityAttestation {
  /** Record ID */
  id: number
  /** User's did:key identifier */
  user_did: string
  /** KYC provider (e.g., 'smile_id') */
  provider: string
  /** ISO 3166-1 alpha-2 country code */
  country_code: string
  /** Verification level achieved */
  verification_level: 'basic' | 'document' | 'biometric'
  /** Whether user is verified */
  verified: boolean
  /** When attestation was issued (unix timestamp) */
  issued_at: number
  /** When attestation expires (unix timestamp) */
  expires_at: number
  /** JWS from attestor */
  attestor_signature: string
  /** Session ID for idempotency */
  session_id: string
  /** Whether attestation was revoked */
  revoked: boolean
  /** Cartesi input index */
  input_index: number
  /** Creation timestamp */
  created_at: string
}

export interface IdentityStats {
  /** Total attestations (including expired/revoked) */
  total: number
  /** Active (valid, not expired, not revoked) */
  active: number
  /** Unique user DIDs */
  unique_users: number
  /** Counts by provider */
  by_provider: Record<string, number>
  /** Counts by country */
  by_country: Record<string, number>
}

// ============= Errors =============

export class LCoreError extends Error {
  constructor(
    message: string,
    public code: LCoreErrorCode,
    public details?: unknown
  ) {
    super(message)
    this.name = 'LCoreError'
  }
}

export type LCoreErrorCode =
  | 'ATTESTOR_UNREACHABLE'
  | 'CARTESI_UNREACHABLE'
  | 'INVALID_CONFIG'
  | 'ATTESTATION_FAILED'
  | 'QUERY_FAILED'
  | 'SIGNATURE_INVALID'
  | 'TIMEOUT'
  | 'UNKNOWN'
