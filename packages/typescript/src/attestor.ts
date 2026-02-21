/**
 * L{CORE} Attestor Client
 *
 * Handles communication with the L{CORE} attestor service.
 */

import type {
  AttestRequest,
  AttestResult,
  HealthStatus,
  ProviderSchema,
  LCoreErrorCode,
} from './types.js'
import { LCoreError } from './types.js'

export interface AttestorClientConfig {
  baseUrl: string
  timeout?: number
}

export class AttestorClient {
  private baseUrl: string
  private timeout: number

  constructor(config: AttestorClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '')
    this.timeout = config.timeout ?? 30000
  }

  /**
   * Check attestor health status
   */
  async health(): Promise<HealthStatus> {
    const response = await this.fetch('/api/health')
    return response as HealthStatus
  }

  /**
   * Get L{CORE} status
   */
  async status(): Promise<{ enabled: boolean; nodeUrl: string }> {
    const response = await this.fetch('/api/lcore/status')
    return response as { enabled: boolean; nodeUrl: string }
  }

  /**
   * Create an attestation claim
   */
  async attest(request: AttestRequest): Promise<AttestResult> {
    try {
      const response = await this.fetch('/api/lcore/attest', {
        method: 'POST',
        body: JSON.stringify(request),
      })

      return {
        success: true,
        claimId: (response as { claimId: string }).claimId,
        extractedData: (response as { data: Record<string, unknown> }).data,
        txHash: (response as { txHash?: string }).txHash,
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  }

  /**
   * List all provider schemas
   */
  async getProviderSchemas(): Promise<ProviderSchema[]> {
    const response = await this.fetch('/api/lcore/provider-schemas')
    return (response as { schemas: ProviderSchema[] }).schemas ?? []
  }

  /**
   * Register a new provider schema (admin only)
   */
  async registerProviderSchema(
    schema: ProviderSchema,
    adminKey?: string
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const headers: Record<string, string> = {}
      if (adminKey) {
        headers['Authorization'] = `Bearer ${adminKey}`
      }

      await this.fetch('/api/lcore/provider-schema', {
        method: 'POST',
        body: JSON.stringify(schema),
        headers,
      })

      return { success: true }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  }

  /**
   * Internal fetch wrapper with error handling
   */
  private async fetch(
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
      const response = await fetch(`${this.baseUrl}${path}`, {
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
          `Attestor request failed: ${response.status} ${response.statusText}`,
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

  private mapStatusToErrorCode(status: number): LCoreErrorCode {
    if (status === 401 || status === 403) return 'SIGNATURE_INVALID'
    if (status === 400) return 'INVALID_CONFIG'
    if (status >= 500) return 'ATTESTOR_UNREACHABLE'
    return 'ATTESTATION_FAILED'
  }
}
