/**
 * E2E Test Helpers for L{CORE} SDK
 *
 * Provides utilities for interacting with the test-rollup-server
 * and generating test data for attestation flows.
 */

import http from 'http';

// ============= Configuration =============

export const TEST_ROLLUP_URL = process.env.TEST_ROLLUP_URL || 'http://127.0.0.1:5004';

// Default test addresses (Foundry anvil defaults)
export const TEST_ADDRESSES = {
  owner: '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266',
  admin: '0x70997970c51812dc3a010c7d01b50e0d17dc79c8',
  grantee: '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc',
  unauthorized: '0x90f79bf6eb2c4f870365e785982e1f101e93b906',
};

// ============= HTTP Client =============

interface AdvanceResult {
  status: 'accept' | 'reject';
  notices: Array<{ payload: string; payloadJson: unknown }>;
  reports: Array<{ payload: string; payloadJson: unknown }>;
  vouchers: Array<{ destination: string; payload: string }>;
}

interface InspectResult {
  reports: Array<{ payload: string; payloadJson: unknown }>;
}

interface ServerStatus {
  status: string;
  inputIndex: number;
  queueLength: number;
  processingRequest: boolean;
}

/**
 * Make an HTTP request to the test rollup server
 */
async function makeRequest<T>(
  path: string,
  method: 'GET' | 'POST',
  body?: unknown
): Promise<T> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, TEST_ROLLUP_URL);

    const options: http.RequestOptions = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(options, res => {
      let data = '';
      res.on('data', chunk => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          resolve(JSON.parse(data) as T);
        } catch {
          reject(new Error(`Failed to parse response: ${data}`));
        }
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

// ============= Test API Functions =============

/**
 * Submit an advance request to the test rollup server
 */
export async function submitAdvance(
  payload: unknown,
  sender: string = TEST_ADDRESSES.owner
): Promise<AdvanceResult> {
  return makeRequest<AdvanceResult>('/test/advance', 'POST', {
    sender,
    payload,
  });
}

/**
 * Submit an inspect query to the test rollup server
 */
export async function submitInspect(
  type: string,
  params: Record<string, string | number | boolean> = {}
): Promise<InspectResult> {
  return makeRequest<InspectResult>('/test/inspect', 'POST', {
    type,
    params,
  });
}

/**
 * Get the server status
 */
export async function getServerStatus(): Promise<ServerStatus> {
  return makeRequest<ServerStatus>('/test/status', 'GET');
}

/**
 * Check if the test rollup server is healthy
 */
export async function isServerHealthy(): Promise<boolean> {
  try {
    const result = await makeRequest<{ status: string }>('/health', 'GET');
    return result.status === 'healthy';
  } catch {
    return false;
  }
}

/**
 * Wait for the server to be healthy
 */
export async function waitForServer(
  maxAttempts: number = 30,
  intervalMs: number = 1000
): Promise<void> {
  for (let i = 0; i < maxAttempts; i++) {
    if (await isServerHealthy()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Test rollup server not healthy after ${maxAttempts} attempts`);
}

// ============= Test Data Generators =============

let idCounter = 0;

/**
 * Generate a unique ID for test data
 */
export function generateId(prefix: string = 'test'): string {
  return `${prefix}-${Date.now()}-${++idCounter}`;
}

/**
 * Generate a mock attestation hash
 */
export function generateHash(): string {
  const bytes = new Array(32).fill(0).map(() => Math.floor(Math.random() * 256));
  return '0x' + bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a mock TEE signature
 */
export function generateSignature(): string {
  const bytes = new Array(65).fill(0).map(() => Math.floor(Math.random() * 256));
  return '0x' + bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============= Payload Builders =============

/**
 * Build a provider schema registration payload
 */
export interface ProviderSchemaPayload {
  action: 'register_provider_schema';
  provider: string;
  flow_type: string;
  domain: string;
  bucket_definitions: Record<string, { boundaries: number[]; labels: string[] }>;
  data_keys: string[];
  freshness_half_life: number;
  min_freshness?: number;
}

export function buildProviderSchemaPayload(
  provider: string = 'http',
  flowType: string = 'web3_rpc',
  domain: string = 'finance',
  options: Partial<Omit<ProviderSchemaPayload, 'action' | 'provider' | 'flow_type' | 'domain'>> = {}
): ProviderSchemaPayload {
  return {
    action: 'register_provider_schema',
    provider,
    flow_type: flowType,
    domain,
    bucket_definitions: options.bucket_definitions ?? {
      balance_range: {
        boundaries: [0, 1000, 10000, 100000, 1000000],
        labels: ['<1K', '1K-10K', '10K-100K', '>100K'],
      },
    },
    data_keys: options.data_keys ?? ['balance', 'address', 'timestamp'],
    freshness_half_life: options.freshness_half_life ?? 86400, // 24 hours
    min_freshness: options.min_freshness,
  };
}

/**
 * Build a CoinGecko price attestation schema (based on example/coin-gecko.json)
 * This represents real-world crypto price attestations
 */
export function buildCoinGeckoSchemaPayload(): ProviderSchemaPayload {
  return {
    action: 'register_provider_schema',
    provider: 'http',
    flow_type: 'coingecko_price',
    domain: 'crypto_prices',
    bucket_definitions: {
      price_range_usd: {
        boundaries: [0, 0.01, 0.1, 1, 10, 100, 1000, 10000],
        labels: ['micro', 'penny', 'sub-dollar', 'low', 'mid', 'high', 'premium'],
      },
      price_change_24h: {
        boundaries: [-100, -10, -5, 0, 5, 10, 100],
        labels: ['crash', 'bearish', 'slight_down', 'slight_up', 'bullish', 'moon'],
      },
    },
    data_keys: ['cardanoPrice', 'solanaPrice', 'timestamp', 'source_url'],
    freshness_half_life: 300, // 5 minutes - crypto prices change fast
    min_freshness: 70,
  };
}

/**
 * Build a CoinGecko price attestation payload
 * Simulates what the attestor would produce from the coin-gecko.json example
 */
export function buildCoinGeckoPriceAttestation(
  owner: string = TEST_ADDRESSES.owner,
  options: {
    id?: string;
    cardanoPrice?: number;
    solanaPrice?: number;
    priceRangeBucket?: string;
  } = {}
): IngestAttestationPayload {
  const cardanoPrice = options.cardanoPrice ?? 0.85;
  const solanaPrice = options.solanaPrice ?? 145.23;

  // Determine price bucket based on cardano price
  let priceRangeBucket = options.priceRangeBucket ?? 'sub-dollar';
  if (cardanoPrice < 0.01) priceRangeBucket = 'micro';
  else if (cardanoPrice < 0.1) priceRangeBucket = 'penny';
  else if (cardanoPrice < 1) priceRangeBucket = 'sub-dollar';
  else if (cardanoPrice < 10) priceRangeBucket = 'low';
  else if (cardanoPrice < 100) priceRangeBucket = 'mid';

  return {
    action: 'ingest_attestation',
    id: options.id ?? generateId('coingecko'),
    attestation_hash: generateHash(),
    owner_address: owner,
    provider: 'http',
    flow_type: 'coingecko_price',
    valid_from: Math.floor(Date.now() / 1000),
    valid_until: Math.floor(Date.now() / 1000) + 600, // 10 min validity for price data
    tee_signature: generateSignature(),
    buckets: [
      { key: 'price_range_usd', value: priceRangeBucket },
      { key: 'price_change_24h', value: 'slight_up' },
    ],
    data: [
      {
        key: 'cardanoPrice',
        value: Buffer.from(cardanoPrice.toString()).toString('base64'),
        encryption_key_id: 'tee-key-1',
      },
      {
        key: 'solanaPrice',
        value: Buffer.from(solanaPrice.toString()).toString('base64'),
        encryption_key_id: 'tee-key-1',
      },
      {
        key: 'timestamp',
        value: Buffer.from(Date.now().toString()).toString('base64'),
        encryption_key_id: 'tee-key-1',
      },
      {
        key: 'source_url',
        value: Buffer.from('https://api.coingecko.com/api/v3/simple/price?ids=cardano,solana&vs_currencies=usd').toString('base64'),
        encryption_key_id: 'tee-key-1',
      },
    ],
  };
}

/**
 * Build an add schema admin payload
 */
export interface AddSchemaAdminPayload {
  action: 'add_schema_admin';
  wallet_address: string;
  can_add_providers?: boolean;
  can_add_admins?: boolean;
}

export function buildAddAdminPayload(
  walletAddress: string,
  canAddProviders: boolean = true,
  canAddAdmins: boolean = false
): AddSchemaAdminPayload {
  return {
    action: 'add_schema_admin',
    wallet_address: walletAddress,
    can_add_providers: canAddProviders,
    can_add_admins: canAddAdmins,
  };
}

/**
 * Build an attestation ingestion payload
 */
export interface IngestAttestationPayload {
  action: 'ingest_attestation';
  id: string;
  attestation_hash: string;
  owner_address: string;
  provider: string;
  flow_type: string;
  valid_from: number;
  valid_until?: number;
  tee_signature: string;
  buckets: Array<{ key: string; value: string }>;
  data: Array<{ key: string; value: string; encryption_key_id: string }>;
}

export function buildAttestationPayload(
  owner: string = TEST_ADDRESSES.owner,
  options: Partial<Omit<IngestAttestationPayload, 'action'>> = {}
): IngestAttestationPayload {
  return {
    action: 'ingest_attestation',
    id: options.id ?? generateId('att'),
    attestation_hash: options.attestation_hash ?? generateHash(),
    owner_address: owner,
    provider: options.provider ?? 'http',
    flow_type: options.flow_type ?? 'web3_rpc',
    valid_from: options.valid_from ?? Math.floor(Date.now() / 1000),
    valid_until: options.valid_until,
    tee_signature: options.tee_signature ?? generateSignature(),
    buckets: options.buckets ?? [
      { key: 'balance_range', value: '1K-10K' },
    ],
    data: options.data ?? [
      { key: 'balance', value: Buffer.from('5000').toString('base64'), encryption_key_id: 'key-1' },
      { key: 'address', value: Buffer.from(owner).toString('base64'), encryption_key_id: 'key-1' },
    ],
  };
}

/**
 * Build a grant access payload
 */
export interface GrantAccessPayload {
  action: 'grant_access';
  grant_id: string;
  attestation_id: string;
  grantee_address: string;
  data_keys?: string[];
  grant_type: 'full' | 'partial' | 'aggregate';
  expires_at_input?: number;
}

export function buildGrantAccessPayload(
  attestationId: string,
  grantee: string = TEST_ADDRESSES.grantee,
  grantType: 'full' | 'partial' | 'aggregate' = 'full',
  options: Partial<Omit<GrantAccessPayload, 'action' | 'attestation_id' | 'grantee_address' | 'grant_type'>> = {}
): GrantAccessPayload {
  return {
    action: 'grant_access',
    grant_id: options.grant_id ?? generateId('grant'),
    attestation_id: attestationId,
    grantee_address: grantee,
    grant_type: grantType,
    data_keys: options.data_keys,
    expires_at_input: options.expires_at_input,
  };
}

/**
 * Build a revoke attestation payload
 */
export interface RevokeAttestationPayload {
  action: 'revoke_attestation';
  attestation_id: string;
}

export function buildRevokeAttestationPayload(attestationId: string): RevokeAttestationPayload {
  return {
    action: 'revoke_attestation',
    attestation_id: attestationId,
  };
}

/**
 * Build a revoke access payload
 */
export interface RevokeAccessPayload {
  action: 'revoke_access';
  grant_id: string;
}

export function buildRevokeAccessPayload(grantId: string): RevokeAccessPayload {
  return {
    action: 'revoke_access',
    grant_id: grantId,
  };
}

// ============= Assertion Helpers =============

/**
 * Extract the response from a notice or report
 */
export function getResponse<T = unknown>(result: AdvanceResult | InspectResult): T | null {
  if ('notices' in result && result.notices.length > 0) {
    return result.notices[0]!.payloadJson as T;
  }
  if ('reports' in result && result.reports.length > 0) {
    return result.reports[0]!.payloadJson as T;
  }
  return null;
}

/**
 * Assert that an advance request was accepted
 */
export function assertAccepted(result: AdvanceResult): void {
  if (result.status !== 'accept') {
    const response = getResponse(result);
    throw new Error(
      `Expected status 'accept', got '${result.status}': ${JSON.stringify(response)}`
    );
  }
}

/**
 * Assert that an advance request was rejected
 */
export function assertRejected(result: AdvanceResult, expectedError?: string): void {
  if (result.status !== 'reject') {
    throw new Error(`Expected status 'reject', got '${result.status}'`);
  }
  if (expectedError) {
    const response = getResponse<{ error?: string }>(result);
    if (!response?.error?.includes(expectedError)) {
      throw new Error(
        `Expected error containing '${expectedError}', got: ${JSON.stringify(response)}`
      );
    }
  }
}

// ============= Setup Helpers =============

/**
 * Bootstrap the schema admin (first admin gets full permissions)
 */
export async function bootstrapAdmin(
  adminAddress: string = TEST_ADDRESSES.admin
): Promise<AdvanceResult> {
  return submitAdvance(buildAddAdminPayload(adminAddress, true, true), adminAddress);
}

/**
 * Register a default provider schema for testing
 */
export async function registerDefaultSchema(
  adminAddress: string = TEST_ADDRESSES.admin
): Promise<AdvanceResult> {
  return submitAdvance(buildProviderSchemaPayload(), adminAddress);
}

/**
 * Create a test attestation (requires schema to be registered first)
 */
export async function createTestAttestation(
  owner: string = TEST_ADDRESSES.owner,
  options: Partial<Omit<IngestAttestationPayload, 'action'>> = {}
): Promise<{ result: AdvanceResult; payload: IngestAttestationPayload }> {
  const payload = buildAttestationPayload(owner, options);
  const result = await submitAdvance(payload, owner);
  return { result, payload };
}

/**
 * Full setup: bootstrap admin, register schema, create attestation
 */
export async function fullSetup(): Promise<{
  adminResult: AdvanceResult;
  schemaResult: AdvanceResult;
  attestationResult: AdvanceResult;
  attestationId: string;
}> {
  const adminResult = await bootstrapAdmin();
  const schemaResult = await registerDefaultSchema();

  const { result: attestationResult, payload } = await createTestAttestation();

  return {
    adminResult,
    schemaResult,
    attestationResult,
    attestationId: payload.id,
  };
}
