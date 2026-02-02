/**
 * L{CORE} Identity Client (zkIdentity)
 *
 * Privacy-preserving KYC verification.
 * Communicates with the attestor for KYC flow and Cartesi for identity queries.
 */

import type {
  KYCProviderInfo,
  StartVerificationParams,
  StartVerificationResult,
  KYCSessionStatus,
  IdentityAttestation,
  IdentityStats,
  LCoreErrorCode,
} from './types.js'
import { LCoreError } from './types.js'
import { buildInspectUrl, hexDecode } from './utils.js'

export interface IdentityClientConfig {
  /** Attestor base URL for KYC endpoints */
  attestorBaseUrl: string
  /** Cartesi node base URL for inspect queries */
  cartesiBaseUrl: string
  /** Request timeout in milliseconds */
  timeout?: number
}

export class IdentityClient {
  private attestorBaseUrl: string
  private cartesiBaseUrl: string
  private timeout: number

  constructor(config: IdentityClientConfig) {
    this.attestorBaseUrl = config.attestorBaseUrl.replace(/\/$/, '')
    this.cartesiBaseUrl = config.cartesiBaseUrl.replace(/\/$/, '')
    this.timeout = config.timeout ?? 30000
  }

  // ============= KYC Flow (via Attestor) =============

  /**
   * List available KYC providers with country coverage
   */
  async getProviders(): Promise<KYCProviderInfo[]> {
    const response = await this.fetchAttestor('/api/kyc/providers')
    return (response as { providers: KYCProviderInfo[] }).providers ?? []
  }

  /**
   * Start a KYC verification session
   *
   * @param params - Verification parameters including user DID, provider, and wallet signature
   * @returns Session ID and verification URL for the user to complete KYC
   */
  async startVerification(params: StartVerificationParams): Promise<StartVerificationResult> {
    const response = await this.fetchAttestor('/api/kyc/start', {
      method: 'POST',
      body: JSON.stringify({
        user_did: params.userDid,
        provider: params.provider,
        wallet_signature: params.walletSignature,
        timestamp: params.timestamp,
        country: params.country,
        job_type: params.jobType,
      }),
    })

    const data = response as {
      sessionId: string
      provider: string
      verificationUrl: string
      expiresAt: number
    }

    return {
      sessionId: data.sessionId,
      provider: data.provider,
      verificationUrl: data.verificationUrl,
      expiresAt: data.expiresAt,
    }
  }

  /**
   * Check the status of a KYC session
   *
   * @param sessionId - Session ID returned from startVerification
   */
  async checkStatus(sessionId: string): Promise<KYCSessionStatus> {
    const response = await this.fetchAttestor(`/api/kyc/status/${encodeURIComponent(sessionId)}`)
    return response as KYCSessionStatus
  }

  /**
   * Simulate a webhook callback for testing (stub mode only)
   *
   * @param sessionId - Session ID to simulate completion for
   */
  async simulateWebhook(sessionId: string): Promise<void> {
    await this.fetchAttestor(`/api/kyc/simulate-webhook/${encodeURIComponent(sessionId)}`, {
      method: 'POST',
    })
  }

  // ============= Identity Queries (via Cartesi Inspect) =============

  /**
   * Get the latest valid identity attestation for a user
   *
   * @param userDid - User's did:key identifier
   * @returns Latest valid attestation or null if none found
   */
  async getIdentity(userDid: string): Promise<IdentityAttestation | null> {
    const result = await this.inspectQuery<IdentityAttestation | { error: string }>('identity', {
      user_did: userDid,
    })

    if (!result || 'error' in result) {
      return null
    }

    return result
  }

  /**
   * Get all identity attestations for a user (with pagination)
   *
   * @param userDid - User's did:key identifier
   * @param options - Pagination options
   */
  async getIdentityHistory(
    userDid: string,
    options?: { limit?: number; offset?: number }
  ): Promise<IdentityAttestation[]> {
    const result = await this.inspectQuery<IdentityAttestation[]>('identity_history', {
      user_did: userDid,
      limit: options?.limit,
      offset: options?.offset,
    })

    return result ?? []
  }

  /**
   * Get identity attestation counts by country
   */
  async getIdentityByCountry(): Promise<Record<string, number>> {
    const result = await this.inspectQuery<Array<{ country_code: string; count: number }>>(
      'identity_by_country',
      {}
    )

    if (!result) {
      return {}
    }

    const map: Record<string, number> = {}
    for (const entry of result) {
      map[entry.country_code] = entry.count
    }
    return map
  }

  /**
   * Get identity attestation statistics
   */
  async getIdentityStats(): Promise<IdentityStats> {
    const result = await this.inspectQuery<IdentityStats>('identity_stats', {})

    return result ?? {
      total: 0,
      active: 0,
      unique_users: 0,
      by_provider: {},
      by_country: {},
    }
  }

  // ============= Internal: Attestor HTTP =============

  private async fetchAttestor(
    path: string,
    options: {
      method?: string
      body?: string
      headers?: Record<string, string>
    } = {}
  ): Promise<unknown> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.timeout)

    try {
      const response = await fetch(`${this.attestorBaseUrl}${path}`, {
        method: options.method ?? 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        body: options.body,
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '')
        throw new LCoreError(
          `Identity request failed: ${response.status} ${response.statusText}`,
          this.mapStatusToErrorCode(response.status),
          { status: response.status, body: errorBody }
        )
      }

      return await response.json()
    } catch (error) {
      clearTimeout(timeoutId)

      if (error instanceof LCoreError) {
        throw error
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new LCoreError('Request timed out', 'TIMEOUT')
      }

      throw new LCoreError(
        `Failed to connect to attestor: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'ATTESTOR_UNREACHABLE',
        error
      )
    }
  }

  // ============= Internal: Cartesi Inspect =============

  private async inspectQuery<T>(type: string, params: Record<string, unknown>): Promise<T | null> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.timeout)

    try {
      const url = buildInspectUrl(this.cartesiBaseUrl, { type, params })
      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        throw new LCoreError(
          `Identity query failed: ${response.status} ${response.statusText}`,
          'QUERY_FAILED'
        )
      }

      const data = await response.json()
      const reports = (data as { reports?: Array<{ payload: string }> }).reports ?? []

      if (reports.length === 0) {
        return null
      }

      return hexDecode<T>(reports[0].payload)
    } catch (error) {
      clearTimeout(timeoutId)

      if (error instanceof LCoreError) {
        throw error
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new LCoreError('Request timed out', 'TIMEOUT')
      }

      throw new LCoreError(
        `Failed to query identity data: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CARTESI_UNREACHABLE',
        error
      )
    }
  }

  private mapStatusToErrorCode(status: number): LCoreErrorCode {
    if (status === 401 || status === 403) return 'SIGNATURE_INVALID'
    if (status === 400) return 'INVALID_CONFIG'
    if (status >= 500) return 'ATTESTOR_UNREACHABLE'
    return 'ATTESTATION_FAILED'
  }
}
