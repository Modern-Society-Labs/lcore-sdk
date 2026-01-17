/**
 * L{CORE} SDK Client
 *
 * Main entry point for interacting with L{CORE} infrastructure.
 */

import type {
  LCoreConfig,
  AttestRequest,
  AttestResult,
  QueryRequest,
  QueryResult,
  HealthStatus,
  ProviderSchema,
} from './types.js'
import { LCoreError } from './types.js'
import { AttestorClient } from './attestor.js'
import { CartesiClient } from './cartesi.js'
import { validateConfig } from './utils.js'

/**
 * L{CORE} SDK Client
 *
 * @example
 * ```typescript
 * import { LCore } from '@localecore/lcore-sdk'
 *
 * const lcore = new LCore({
 *   attestorUrl: 'http://localhost:8001',
 *   cartesiUrl: 'http://localhost:10000',
 *   dappAddress: '0x...',
 * })
 *
 * // Create attestation
 * const result = await lcore.attest({
 *   provider: 'http',
 *   params: {
 *     url: 'https://api.example.com/data',
 *     responseRedactions: [{ jsonPath: 'temperature' }]
 *   }
 * })
 *
 * // Query data
 * const data = await lcore.query({ type: 'attestation', params: { claimId: '...' } })
 * ```
 */
export class LCore {
  private attestor: AttestorClient
  private cartesi: CartesiClient
  private config: LCoreConfig

  constructor(config: LCoreConfig) {
    // Validate configuration
    const errors = validateConfig(config)
    if (errors.length > 0) {
      throw new LCoreError(
        `Invalid configuration: ${errors.join(', ')}`,
        'INVALID_CONFIG',
        errors
      )
    }

    this.config = config
    this.attestor = new AttestorClient({
      baseUrl: config.attestorUrl,
      timeout: config.timeout,
    })
    this.cartesi = new CartesiClient({
      baseUrl: config.cartesiUrl,
      dappAddress: config.dappAddress,
      timeout: config.timeout,
    })
  }

  /**
   * Create an attestation for off-chain data
   *
   * @param request - Attestation request configuration
   * @returns Attestation result with claim ID if successful
   */
  async attest(request: AttestRequest): Promise<AttestResult> {
    return this.attestor.attest(request)
  }

  /**
   * Query attested data from Cartesi
   *
   * @param request - Query request
   * @returns Query result with data if successful
   */
  async query<T = unknown>(request: QueryRequest): Promise<QueryResult<T>> {
    return this.cartesi.query<T>(request)
  }

  /**
   * Get a specific attestation by claim ID
   *
   * @param claimId - The claim ID to retrieve
   */
  async getAttestation(claimId: string) {
    return this.cartesi.getAttestation(claimId)
  }

  /**
   * List all registered provider schemas
   */
  async getProviderSchemas(): Promise<ProviderSchema[]> {
    return this.attestor.getProviderSchemas()
  }

  /**
   * Check health of both attestor and Cartesi node
   */
  async health(): Promise<HealthStatus> {
    const [attestorHealth, cartesiHealth] = await Promise.all([
      this.attestor.health().catch(e => ({ status: 'down' as const, error: e.message })),
      this.cartesi.health(),
    ])

    const attestorOk = attestorHealth.status === 'ok'
    const cartesiOk = cartesiHealth.status === 'ok'

    return {
      status: attestorOk && cartesiOk ? 'ok' : attestorOk || cartesiOk ? 'degraded' : 'down',
      version: (attestorHealth as HealthStatus).version,
      lcoreEnabled: (attestorHealth as HealthStatus).lcoreEnabled,
      cartesiConnected: cartesiOk,
    }
  }

  /**
   * Get the attestor client for advanced operations
   */
  get attestorClient(): AttestorClient {
    return this.attestor
  }

  /**
   * Get the Cartesi client for advanced operations
   */
  get cartesiClient(): CartesiClient {
    return this.cartesi
  }

  /**
   * Get current configuration
   */
  getConfig(): Readonly<LCoreConfig> {
    return { ...this.config }
  }
}

/**
 * Create an L{CORE} client from environment variables
 *
 * Expects:
 * - LCORE_ATTESTOR_URL
 * - LCORE_CARTESI_URL
 * - LCORE_DAPP_ADDRESS
 */
export function createLCoreFromEnv(): LCore {
  const config: LCoreConfig = {
    attestorUrl: process.env.LCORE_ATTESTOR_URL ?? '',
    cartesiUrl: process.env.LCORE_CARTESI_URL ?? '',
    dappAddress: process.env.LCORE_DAPP_ADDRESS ?? '',
    rpcUrl: process.env.LCORE_RPC_URL,
    timeout: process.env.LCORE_TIMEOUT ? parseInt(process.env.LCORE_TIMEOUT, 10) : undefined,
  }

  return new LCore(config)
}
