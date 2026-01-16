/**
 * L{CORE} Cartesi Client
 *
 * Handles queries to the Cartesi node for attestation data.
 */

import type {
  QueryRequest,
  QueryResult,
  QueryParams,
  LCoreErrorCode,
} from './types.js'
import { LCoreError } from './types.js'
import { hexDecode, buildInspectUrl } from './utils.js'

export interface CartesiClientConfig {
  baseUrl: string
  dappAddress: string
  timeout?: number
}

export class CartesiClient {
  private baseUrl: string
  private dappAddress: string
  private timeout: number

  constructor(config: CartesiClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '')
    this.dappAddress = config.dappAddress
    this.timeout = config.timeout ?? 30000
  }

  /**
   * Query the Cartesi node via inspect endpoint
   */
  async query<T = unknown>(request: QueryRequest): Promise<QueryResult<T>> {
    try {
      const queryPayload = {
        type: request.type,
        params: request.params ?? {},
      }

      const url = buildInspectUrl(this.baseUrl, queryPayload)
      const response = await this.fetchInspect(url)

      // Parse Cartesi inspect response
      const reports = (response as { reports?: Array<{ payload: string }> }).reports ?? []

      if (reports.length === 0) {
        return {
          success: true,
          data: undefined,
        }
      }

      // Decode the first report payload
      const payload = reports[0].payload
      const decoded = hexDecode<T>(payload)

      return {
        success: true,
        data: decoded,
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  }

  /**
   * Query a specific attestation by claim ID
   */
  async getAttestation(claimId: string): Promise<QueryResult<{
    claimId: string
    provider: string
    data: Record<string, unknown>
    timestamp: number
    signature: string
  }>> {
    return this.query({
      type: 'attestation',
      params: { claimId },
    })
  }

  /**
   * Query all provider schemas
   */
  async getProviderSchemas(): Promise<QueryResult<Array<{
    provider: string
    flowType: string
    domain: string
    dataKeys: string[]
  }>>> {
    return this.query({
      type: 'provider_schemas',
    })
  }

  /**
   * Query bucket data
   */
  async getBucket(bucketId: string): Promise<QueryResult<{
    bucketId: string
    label: string
    count: number
  }>> {
    return this.query({
      type: 'bucket',
      params: { bucketId },
    })
  }

  /**
   * Query access grants for an address
   */
  async getAccessGrants(address: string): Promise<QueryResult<Array<{
    grantee: string
    bucketId: string
    expiresAt: number
    permissions: string[]
  }>>> {
    return this.query({
      type: 'access_grants',
      params: { address },
    })
  }

  /**
   * Check Cartesi node health
   */
  async health(): Promise<{ status: 'ok' | 'error'; error?: string }> {
    try {
      // Simple inspect query to check if node is responding
      const url = buildInspectUrl(this.baseUrl, { type: 'health' })
      await this.fetchInspect(url)
      return { status: 'ok' }
    } catch (error) {
      return {
        status: 'error',
        error: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  }

  /**
   * Internal fetch for inspect endpoint
   */
  private async fetchInspect(url: string): Promise<unknown> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this.timeout)

    try {
      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        throw new LCoreError(
          `Cartesi query failed: ${response.status} ${response.statusText}`,
          this.mapStatusToErrorCode(response.status)
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
        `Failed to connect to Cartesi node: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'CARTESI_UNREACHABLE',
        error
      )
    }
  }

  private mapStatusToErrorCode(status: number): LCoreErrorCode {
    if (status >= 500) return 'CARTESI_UNREACHABLE'
    return 'QUERY_FAILED'
  }
}
