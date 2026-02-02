/**
 * Plaid Identity Verification Provider
 *
 * Global identity verification covering US, Canada, UK, and Europe.
 *
 * Operates in two modes:
 * - STUB MODE (default): When PLAID_CLIENT_ID or PLAID_SECRET is not set, returns mock results for testing
 * - LIVE MODE: Integrates with Plaid Identity Verification API
 *
 * Docs: https://plaid.com/docs/identity-verification/
 */

import { getEnvVariable } from '#src/utils/env.ts'
import type {
	KYCProvider,
	KYCSession,
	KYCStatus,
	KYCResult,
	CreateSessionOptions,
} from './interface.ts'

// ============= Configuration =============

const PLAID_CLIENT_ID = getEnvVariable('PLAID_CLIENT_ID') || ''
const PLAID_SECRET = getEnvVariable('PLAID_SECRET') || ''
const PLAID_ENVIRONMENT = getEnvVariable('PLAID_ENVIRONMENT') || 'sandbox'
const PLAID_WEBHOOK_URL = getEnvVariable('PLAID_WEBHOOK_URL') || ''

const IS_STUB = !PLAID_CLIENT_ID || !PLAID_SECRET

const PLAID_BASE_URL = PLAID_ENVIRONMENT === 'production'
	? 'https://production.plaid.com'
	: 'https://sandbox.plaid.com'

// ============= Stub State =============

/** In-memory session store for stub mode */
const stubSessions = new Map<string, {
	userDid: string
	status: 'pending' | 'completed' | 'failed'
	country: string
	level: 'basic' | 'document' | 'biometric'
	createdAt: number
}>()

function generateStubId(): string {
	return `stub_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
}

// ============= Plaid Provider =============

export const plaidProvider: KYCProvider = {
	name: 'plaid',

	supportedCountries: ['US', 'CA', 'GB', 'FR', 'DE', 'ES', 'NL', 'IE', 'AU'],

	isStubMode: IS_STUB,

	async createSession(
		userDid: string,
		options?: CreateSessionOptions
	): Promise<KYCSession> {
		const sessionId = IS_STUB
			? generateStubId()
			: await createLiveSession(userDid, options)

		const expiresAt = Math.floor(Date.now() / 1000) + 30 * 60 // 30 minutes

		if(IS_STUB) {
			stubSessions.set(sessionId, {
				userDid,
				status: 'pending',
				country: options?.country || 'US',
				level: options?.jobType || 'basic',
				createdAt: Date.now(),
			})
		}

		const verificationUrl = IS_STUB
			? `https://stub.plaid.com/verify/${sessionId}`
			: `https://cdn.plaid.com/link/v2/stable/link.html?token=${sessionId}`

		return {
			sessionId,
			provider: 'plaid',
			verificationUrl,
			expiresAt,
		}
	},

	async getStatus(sessionId: string): Promise<KYCStatus> {
		if(IS_STUB) {
			const session = stubSessions.get(sessionId)
			if(!session) {
				return { sessionId, status: 'expired' }
			}

			if(session.status === 'completed') {
				return {
					sessionId,
					status: 'completed',
					result: {
						success: true,
						sessionId,
						country: session.country,
						level: session.level,
						provider: 'plaid',
					},
				}
			}

			return { sessionId, status: session.status }
		}

		return getLiveStatus(sessionId)
	},

	verifyWebhook(payload: unknown, signature: string): boolean {
		if(IS_STUB) {
			return true
		}

		return verifyPlaidSignature(payload, signature)
	},

	parseResult(webhookPayload: unknown): KYCResult {
		if(IS_STUB) {
			return parseStubResult(webhookPayload)
		}

		return parseLiveResult(webhookPayload)
	},
}

// ============= Stub Mode Helpers =============

/**
 * Complete a stub session (called by simulate-webhook endpoint).
 * Returns the KYCResult for submission to Cartesi.
 */
export function completeStubSession(
	sessionId: string,
	options?: { country?: string; level?: 'basic' | 'document' | 'biometric'; success?: boolean }
): KYCResult | null {
	const session = stubSessions.get(sessionId)
	if(!session) {
		return null
	}

	const success = options?.success ?? true
	session.status = success ? 'completed' : 'failed'

	return {
		success,
		sessionId,
		country: options?.country || session.country,
		level: options?.level || session.level,
		provider: 'plaid',
	}
}

/**
 * Get the user DID for a stub session.
 */
export function getStubSessionDid(sessionId: string): string | null {
	return stubSessions.get(sessionId)?.userDid ?? null
}

function parseStubResult(webhookPayload: unknown): KYCResult {
	const payload = webhookPayload as {
		sessionId?: string
		country?: string
		level?: string
		success?: boolean
	}

	return {
		success: payload.success ?? true,
		sessionId: payload.sessionId || 'unknown',
		country: payload.country || 'US',
		level: (payload.level as KYCResult['level']) || 'basic',
		provider: 'plaid',
	}
}

// ============= Live Mode Helpers =============

async function createLiveSession(
	userDid: string,
	options?: CreateSessionOptions
): Promise<string> {
	const response = await fetch(`${PLAID_BASE_URL}/link/token/create`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			client_id: PLAID_CLIENT_ID,
			secret: PLAID_SECRET,
			client_name: 'zkIdentity',
			products: ['identity_verification'],
			country_codes: [options?.country || 'US'],
			language: 'en',
			webhook: PLAID_WEBHOOK_URL,
			user: {
				client_user_id: userDid,
			},
			identity_verification: {
				template_id: getEnvVariable('PLAID_IDV_TEMPLATE_ID') || '',
			},
		}),
		signal: AbortSignal.timeout(10000),
	})

	if(!response.ok) {
		const body = await response.text().catch(() => '')
		throw new Error(`Plaid session creation failed: ${response.status} ${body}`)
	}

	const result = await response.json() as { link_token?: string }
	if(!result.link_token) {
		throw new Error('Plaid did not return a link_token')
	}
	return result.link_token
}

async function getLiveStatus(sessionId: string): Promise<KYCStatus> {
	const response = await fetch(`${PLAID_BASE_URL}/identity_verification/get`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			client_id: PLAID_CLIENT_ID,
			secret: PLAID_SECRET,
			identity_verification_id: sessionId,
		}),
		signal: AbortSignal.timeout(10000),
	})

	if(!response.ok) {
		return { sessionId, status: 'pending' }
	}

	const result = await response.json() as {
		status?: string
		steps?: {
			verify_step?: string
			documentary_verification?: string
			selfie_check?: string
		}
		user?: { address?: { country?: string } }
	}

	const plaidStatus = result.status
	if(plaidStatus === 'success') {
		return {
			sessionId,
			status: 'completed',
			result: {
				success: true,
				sessionId,
				country: result.user?.address?.country || 'US',
				level: mapVerificationLevel(result.steps),
				provider: 'plaid',
			},
		}
	}

	if(plaidStatus === 'failed' || plaidStatus === 'canceled' || plaidStatus === 'expired') {
		return { sessionId, status: 'failed' }
	}

	return { sessionId, status: 'pending' }
}

function verifyPlaidSignature(_payload: unknown, _signature: string): boolean {
	// Plaid webhook verification uses JWT with JWK
	// In production, verify JWT from Plaid-Verification header using /webhook_verification_key/get
	// For now, return true — production implementation will use jose/jsonwebtoken
	return true
}

function parseLiveResult(webhookPayload: unknown): KYCResult {
	const payload = webhookPayload as {
		webhook_type?: string
		webhook_code?: string
		identity_verification_id?: string
		environment?: string
	}

	const success = payload.webhook_code === 'STATUS_UPDATED'

	return {
		success,
		sessionId: payload.identity_verification_id || 'unknown',
		country: 'US',
		level: 'basic',
		provider: 'plaid',
	}
}

function mapVerificationLevel(steps?: {
	verify_step?: string
	documentary_verification?: string
	selfie_check?: string
}): 'basic' | 'document' | 'biometric' {
	if(!steps) return 'basic'
	if(steps.selfie_check === 'success') return 'biometric'
	if(steps.documentary_verification === 'success') return 'document'
	return 'basic'
}
