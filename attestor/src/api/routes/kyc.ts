/**
 * KYC (zkIdentity) API Routes
 *
 * Privacy-preserving identity verification endpoints.
 *
 * GET    /api/kyc/providers              - List available KYC providers
 * POST   /api/kyc/start                  - Start a KYC verification session
 * GET    /api/kyc/status/:sessionId      - Check session status
 * POST   /api/kyc/webhook/:provider      - Provider webhook callback
 * POST   /api/kyc/simulate-webhook/:id   - Simulate webhook (stub mode only)
 *
 * PRIVACY MODEL:
 * - Raw KYC data (name, DOB, ID images) is NEVER stored or forwarded
 * - Only boolean flags (verified, country_code, level) are submitted to Cartesi
 * - The attestor signs the attestation but does NOT store PII
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { ethers, Wallet } from 'ethers'
import { parseJsonBody, sendError, sendJson } from '#src/api/utils/http.ts'
import { isValidDIDKeyFormat, createJWS } from '#src/api/services/did.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { getAvailableProviders, getProvider, hasProvider } from '#src/kyc/providers/index.ts'
import { completeStubSession as completeSmileIdStub } from '#src/kyc/providers/smile-id.ts'
import { completeStubSession as completePlaidStub } from '#src/kyc/providers/plaid.ts'
import {
	createSession,
	getSession,
	updateSessionStatus,
} from '#src/kyc/sessions.ts'

// ============= L{CORE} Configuration =============

const LCORE_RPC_URL = getEnvVariable('LCORE_RPC_URL') || ''
const LCORE_DAPP_ADDRESS = getEnvVariable('LCORE_DAPP_ADDRESS') || ''
const LCORE_INPUTBOX_ADDRESS = getEnvVariable('LCORE_INPUTBOX_ADDRESS') || '0x59b22D57D4f067708AB0c00552767405926dc768'
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'

const INPUT_BOX_ABI = [
	'function addInput(address _dapp, bytes calldata _input) external returns (bytes32)'
]

let _wallet: Wallet | null = null
let _provider: ethers.providers.JsonRpcProvider | null = null

function getRpcProvider(): ethers.providers.JsonRpcProvider {
	if(!_provider) {
		if(!LCORE_RPC_URL) {
			throw new Error('LCORE_RPC_URL is required')
		}
		_provider = new ethers.providers.JsonRpcProvider(LCORE_RPC_URL)
	}
	return _provider
}

function getWallet(): Wallet {
	if(!_wallet) {
		const mnemonic = getEnvVariable('MNEMONIC')
		if(!mnemonic) {
			throw new Error('MNEMONIC is required for signing transactions')
		}
		_wallet = Wallet.fromMnemonic(mnemonic).connect(getRpcProvider())
	}
	return _wallet
}

function hexEncode(data: unknown): string {
	const jsonStr = JSON.stringify(data)
	return '0x' + Buffer.from(jsonStr, 'utf-8').toString('hex')
}

// Get attestor private key for signing attestations
function getAttestorPrivateKey(): Uint8Array {
	const mnemonic = getEnvVariable('MNEMONIC')
	if(!mnemonic) {
		throw new Error('MNEMONIC is required for attestor signing')
	}
	const wallet = Wallet.fromMnemonic(mnemonic)
	// Convert hex private key to Uint8Array (strip 0x prefix)
	const hexKey = wallet.privateKey.slice(2)
	return Uint8Array.from(Buffer.from(hexKey, 'hex'))
}

// ============= Route Handler =============

export async function handleKycRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// GET /api/kyc/providers
	if(path === '/api/kyc/providers' && method === 'GET') {
		await handleListProviders(req, res)
		return true
	}

	// POST /api/kyc/start
	if(path === '/api/kyc/start' && method === 'POST') {
		await handleStartVerification(req, res)
		return true
	}

	// GET /api/kyc/status/:sessionId
	if(path.startsWith('/api/kyc/status/') && method === 'GET') {
		const sessionId = path.slice('/api/kyc/status/'.length)
		await handleCheckStatus(req, res, sessionId)
		return true
	}

	// POST /api/kyc/webhook/:provider
	if(path.startsWith('/api/kyc/webhook/') && method === 'POST') {
		const provider = path.slice('/api/kyc/webhook/'.length)
		await handleWebhook(req, res, provider)
		return true
	}

	// POST /api/kyc/simulate-webhook/:sessionId
	if(path.startsWith('/api/kyc/simulate-webhook/') && method === 'POST') {
		const sessionId = path.slice('/api/kyc/simulate-webhook/'.length)
		await handleSimulateWebhook(req, res, sessionId)
		return true
	}

	return false
}

// ============= Endpoint Handlers =============

/**
 * GET /api/kyc/providers
 * List available KYC providers with country coverage
 */
async function handleListProviders(
	_req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	sendJson(res, {
		providers: getAvailableProviders(),
	})
}

/**
 * POST /api/kyc/start
 * Start a KYC verification session
 */
async function handleStartVerification(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const body = await parseJsonBody<{
		user_did: string
		provider: string
		wallet_signature: string
		timestamp: number
		country?: string
		job_type?: 'basic' | 'document' | 'biometric'
	}>(req)

	if(!body) {
		return sendError(res, 400, 'Invalid request body')
	}

	// Validate required fields
	if(!body.user_did) {
		return sendError(res, 400, 'user_did is required')
	}
	if(!body.provider) {
		return sendError(res, 400, 'provider is required')
	}
	if(!body.wallet_signature) {
		return sendError(res, 400, 'wallet_signature is required')
	}
	if(!body.timestamp || typeof body.timestamp !== 'number') {
		return sendError(res, 400, 'timestamp is required and must be a number')
	}

	// Validate DID format
	if(!isValidDIDKeyFormat(body.user_did)) {
		return sendError(res, 400, 'Invalid user_did format. Expected did:key:z...')
	}

	// Validate provider exists
	if(!hasProvider(body.provider)) {
		return sendError(res, 400, `Unknown provider: ${body.provider}`)
	}

	try {
		const provider = getProvider(body.provider)

		// Create session with provider
		const kycSession = await provider.createSession(body.user_did, {
			jobType: body.job_type,
			country: body.country,
		})

		// Track session locally
		createSession({
			sessionId: kycSession.sessionId,
			provider: body.provider,
			userDid: body.user_did,
			walletSignature: body.wallet_signature,
			signatureTimestamp: body.timestamp,
		})

		sendJson(res, {
			sessionId: kycSession.sessionId,
			provider: kycSession.provider,
			verificationUrl: kycSession.verificationUrl,
			expiresAt: kycSession.expiresAt,
		}, 201)
	} catch(error) {
		sendError(res, 500, error instanceof Error ? error.message : 'Failed to create session')
	}
}

/**
 * GET /api/kyc/status/:sessionId
 * Check the status of a KYC session
 */
async function handleCheckStatus(
	_req: IncomingMessage,
	res: ServerResponse,
	sessionId: string
): Promise<void> {
	if(!sessionId) {
		return sendError(res, 400, 'sessionId is required')
	}

	const session = getSession(sessionId)
	if(!session) {
		return sendError(res, 404, 'Session not found or expired')
	}

	try {
		const provider = getProvider(session.provider)
		const status = await provider.getStatus(sessionId)

		sendJson(res, {
			sessionId: session.sessionId,
			provider: session.provider,
			status: status.status,
			user_did: session.userDid,
		})
	} catch(error) {
		sendError(res, 500, error instanceof Error ? error.message : 'Failed to check status')
	}
}

/**
 * POST /api/kyc/webhook/:provider
 * Handle provider webhook callback
 */
async function handleWebhook(
	req: IncomingMessage,
	res: ServerResponse,
	providerName: string
): Promise<void> {
	if(!hasProvider(providerName)) {
		return sendError(res, 404, `Unknown provider: ${providerName}`)
	}

	const body = await parseJsonBody<unknown>(req)
	if(!body) {
		return sendError(res, 400, 'Invalid request body')
	}

	const provider = getProvider(providerName)

	// Verify webhook signature
	const signature = (req.headers['x-signature'] || req.headers['x-smile-signature'] || '') as string
	if(!provider.verifyWebhook(body, signature)) {
		return sendError(res, 401, 'Invalid webhook signature')
	}

	// Parse result
	const result = provider.parseResult(body)

	if(!result.success) {
		// Update session status to failed
		updateSessionStatus(result.sessionId, 'failed')
		return sendJson(res, { received: true, success: false })
	}

	// Look up session to get user DID
	const session = getSession(result.sessionId)
	if(!session) {
		return sendError(res, 404, 'Session not found or expired')
	}

	// Update session
	updateSessionStatus(result.sessionId, 'completed')

	// Submit identity attestation to Cartesi (NO PII)
	const submitResult = await submitIdentityAttestation(
		session.userDid,
		result,
		session.sessionId
	)

	if(!submitResult.success) {
		return sendError(res, 500, submitResult.error || 'Failed to submit attestation')
	}

	sendJson(res, {
		received: true,
		success: true,
		txHash: submitResult.data?.txHash,
	})
}

/**
 * POST /api/kyc/simulate-webhook/:sessionId
 * Simulate a successful webhook for stub mode testing
 */
async function handleSimulateWebhook(
	req: IncomingMessage,
	res: ServerResponse,
	sessionId: string
): Promise<void> {
	// Look up session
	const session = getSession(sessionId)
	if(!session) {
		return sendError(res, 404, 'Session not found or expired')
	}

	const provider = getProvider(session.provider)
	if(!provider.isStubMode) {
		return sendError(res, 400, 'simulate-webhook is only available in stub mode')
	}

	// Parse optional body for custom result
	const body = await parseJsonBody<{
		country?: string
		level?: 'basic' | 'document' | 'biometric'
		success?: boolean
	}>(req)

	// Route to the correct provider's stub completion
	const stubCompleters: Record<string, typeof completeSmileIdStub> = {
		smile_id: completeSmileIdStub,
		plaid: completePlaidStub,
	}
	const completer = stubCompleters[session.provider]
	if(!completer) {
		return sendError(res, 400, `Stub mode not implemented for provider: ${session.provider}`)
	}

	const result = completer(sessionId, {
		country: body?.country,
		level: body?.level,
		success: body?.success,
	})

	if(!result) {
		return sendError(res, 404, 'Stub session not found')
	}

	// Update our session tracking
	updateSessionStatus(sessionId, result.success ? 'completed' : 'failed')

	if(!result.success) {
		return sendJson(res, { success: false, status: 'failed' })
	}

	// Submit identity attestation to Cartesi
	const submitResult = await submitIdentityAttestation(
		session.userDid,
		result,
		sessionId
	)

	if(!submitResult.success) {
		return sendError(res, 500, submitResult.error || 'Failed to submit attestation')
	}

	sendJson(res, {
		success: true,
		status: 'completed',
		txHash: submitResult.data?.txHash,
	})
}

// ============= Cartesi Submission =============

/**
 * Submit an identity attestation to the Cartesi rollup.
 * Contains ONLY non-PII metadata — no personal data.
 */
async function submitIdentityAttestation(
	userDid: string,
	result: { provider: string; country: string; level: string },
	sessionId: string
): Promise<{ success: boolean; data?: { txHash: string; blockNumber: number }; error?: string }> {
	if(!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	if(!LCORE_DAPP_ADDRESS) {
		return { success: false, error: 'LCORE_DAPP_ADDRESS is required' }
	}

	try {
		const now = Math.floor(Date.now() / 1000)
		const oneYear = 365 * 24 * 60 * 60

		// Build the attestation claim (no PII)
		const claim = {
			user_did: userDid,
			provider: result.provider,
			country_code: result.country,
			verification_level: result.level,
			verified: true,
			issued_at: now,
			expires_at: now + oneYear,
		}

		// Sign the claim with attestor key
		const attestorKey = getAttestorPrivateKey()
		const attestorSignature = createJWS(claim, attestorKey)

		const payload = {
			action: 'identity_attestation',
			...claim,
			attestor_signature: attestorSignature,
			session_id: sessionId,
		}

		const wallet = getWallet()
		const inputBox = new ethers.Contract(LCORE_INPUTBOX_ADDRESS, INPUT_BOX_ABI, wallet)
		const inputData = hexEncode(payload)

		const tx = await inputBox.addInput(LCORE_DAPP_ADDRESS, inputData)
		const receipt = await tx.wait()

		if(!receipt) {
			return { success: false, error: 'Transaction failed - no receipt' }
		}

		return {
			success: true,
			data: { txHash: tx.hash, blockNumber: receipt.blockNumber },
		}
	} catch(error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : String(error),
		}
	}
}
