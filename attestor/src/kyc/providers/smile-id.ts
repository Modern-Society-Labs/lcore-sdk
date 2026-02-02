/**
 * Smile ID KYC Provider
 *
 * Africa-focused identity verification covering Ethiopia, Nigeria, Kenya, and 10+ countries.
 *
 * Operates in two modes:
 * - STUB MODE (default): When SMILE_ID_API_KEY is not set, returns mock results for testing
 * - LIVE MODE: Integrates with Smile ID REST API for real verification
 *
 * Docs: https://docs.usesmileid.com
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

const SMILE_ID_PARTNER_ID = getEnvVariable('SMILE_ID_PARTNER_ID') || ''
const SMILE_ID_API_KEY = getEnvVariable('SMILE_ID_API_KEY') || ''
const SMILE_ID_CALLBACK_URL = getEnvVariable('SMILE_ID_CALLBACK_URL') || ''
const SMILE_ID_ENVIRONMENT = getEnvVariable('SMILE_ID_ENVIRONMENT') || 'sandbox'

const IS_STUB = !SMILE_ID_API_KEY

const SMILE_ID_BASE_URL = SMILE_ID_ENVIRONMENT === 'production'
	? 'https://api.smileidentity.com'
	: 'https://testapi.smileidentity.com'

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

// ============= Smile ID Provider =============

export const smileIdProvider: KYCProvider = {
	name: 'smile_id',

	supportedCountries: ['ET', 'NG', 'KE', 'GH', 'ZA', 'UG', 'TZ', 'RW', 'BJ', 'BF', 'CM', 'CI'],

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
				country: options?.country || 'ET',
				level: options?.jobType || 'basic',
				createdAt: Date.now(),
			})
		}

		const verificationUrl = IS_STUB
			? `https://stub.smileidentity.com/verify/${sessionId}`
			: `https://links.usesmileid.com/${sessionId}`

		return {
			sessionId,
			provider: 'smile_id',
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
						provider: 'smile_id',
					},
				}
			}

			return { sessionId, status: session.status }
		}

		return getLiveStatus(sessionId)
	},

	verifyWebhook(payload: unknown, signature: string): boolean {
		if(IS_STUB) {
			// In stub mode, accept all webhooks
			return true
		}

		return verifySmileIdSignature(payload, signature)
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
		provider: 'smile_id',
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
		country: payload.country || 'ET',
		level: (payload.level as KYCResult['level']) || 'basic',
		provider: 'smile_id',
	}
}

// ============= Live Mode Helpers =============

async function createLiveSession(
	userDid: string,
	options?: CreateSessionOptions
): Promise<string> {
	const jobType = mapJobType(options?.jobType || 'basic')
	const jobId = `kyc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`

	const response = await fetch(`${SMILE_ID_BASE_URL}/v1/auth_smile`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			partner_id: SMILE_ID_PARTNER_ID,
			api_key: SMILE_ID_API_KEY,
			user_id: userDid,
			job_id: jobId,
			product: jobType,
			callback_url: SMILE_ID_CALLBACK_URL,
		}),
		signal: AbortSignal.timeout(10000),
	})

	if(!response.ok) {
		const body = await response.text().catch(() => '')
		throw new Error(`Smile ID session creation failed: ${response.status} ${body}`)
	}

	const result = await response.json() as { token?: string; job_id?: string }
	return result.job_id || jobId
}

async function getLiveStatus(sessionId: string): Promise<KYCStatus> {
	const response = await fetch(`${SMILE_ID_BASE_URL}/v1/job_status`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({
			partner_id: SMILE_ID_PARTNER_ID,
			api_key: SMILE_ID_API_KEY,
			job_id: sessionId,
		}),
		signal: AbortSignal.timeout(10000),
	})

	if(!response.ok) {
		return { sessionId, status: 'pending' }
	}

	const result = await response.json() as {
		job_complete?: boolean
		result?: { ResultCode?: string; Country?: string }
	}

	if(!result.job_complete) {
		return { sessionId, status: 'pending' }
	}

	const success = result.result?.ResultCode === '0000'

	return {
		sessionId,
		status: success ? 'completed' : 'failed',
		result: success ? {
			success: true,
			sessionId,
			country: result.result?.Country || 'unknown',
			level: 'basic',
			provider: 'smile_id',
		} : undefined,
	}
}

function verifySmileIdSignature(_payload: unknown, _signature: string): boolean {
	// Smile ID webhook verification uses the partner's API key
	// In production, verify HMAC signature against SMILE_ID_API_KEY
	// For now, return true — production implementation will use smile-identity-core
	return true
}

function parseLiveResult(webhookPayload: unknown): KYCResult {
	const payload = webhookPayload as {
		ResultCode?: string
		PartnerParams?: {
			job_id?: string
			job_type?: number
		}
		Country?: string
	}

	const success = payload.ResultCode === '0000'

	return {
		success,
		sessionId: payload.PartnerParams?.job_id || 'unknown',
		country: payload.Country || 'unknown',
		level: mapJobTypeReverse(payload.PartnerParams?.job_type),
		provider: 'smile_id',
		rawData: success ? undefined : { resultCode: payload.ResultCode },
	}
}

function mapJobType(level: string): string {
	switch(level) {
	case 'biometric': return 'biometric_kyc'
	case 'document': return 'enhanced_kyc'
	default: return 'basic_kyc'
	}
}

function mapJobTypeReverse(jobType?: number): 'basic' | 'document' | 'biometric' {
	switch(jobType) {
	case 4: return 'biometric'
	case 6: return 'document'
	default: return 'basic'
	}
}
