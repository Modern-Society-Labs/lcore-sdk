/**
 * L{CORE} Inspect Proxy — Decrypted Read Gateway
 *
 * Proxies Cartesi inspect queries, decrypts V1 packed blobs with
 * LCORE_PRIVATE_KEY, and re-encrypts for the requester's NaCl public key.
 *
 * This completes the V1 data flow: devices submit encrypted data to Cartesi,
 * and authorized requesters read decrypted data through this proxy.
 *
 * POST  /api/inspect/device-attestations  - Query device attestations by DID
 * POST  /api/inspect/device-latest        - Latest attestation for a device
 * POST  /api/inspect/attestation-data     - Gated attestation data (access grant required)
 * GET   /api/inspect/public-key           - Get admin public key for re-encryption
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { parseJsonBody, sendError, sendJson } from '#src/api/utils/http.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import {
	isDecryptionConfigured,
	getAdminPublicKey,
	processLCoreResponse,
	reEncryptForRequester,
	validateNaClPublicKey,
} from '#src/lcore/encryption.ts'

// ============= Config =============

const LCORE_NODE_URL = getEnvVariable('LCORE_NODE_URL') || 'http://127.0.0.1:10000'
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'

// Revocation confirmation depth — how many inputs must pass after
// a revocation before we stop serving that grant's data.
const REVOCATION_CONFIRM_DEPTH = parseInt(
	getEnvVariable('LCORE_REVOCATION_CONFIRM_DEPTH') || '1',
	10
)

// ============= Helpers =============

function hexEncode(data: unknown): string {
	const jsonStr = JSON.stringify(data)
	return '0x' + Buffer.from(jsonStr, 'utf-8').toString('hex')
}

function hexDecode(hex: string): unknown {
	const str = Buffer.from(hex.slice(2), 'hex').toString('utf-8')
	return JSON.parse(str)
}

/**
 * Query the Cartesi inspect endpoint and process the response.
 */
async function queryCartesiInspect<T = unknown>(
	type: string,
	params: Record<string, string>
): Promise<{ success: true; data: T; wasEncrypted: boolean } | { success: false; error: string }> {
	const query = { type, params }
	const encodedPayload = encodeURIComponent(JSON.stringify(query))

	const response = await fetch(`${LCORE_NODE_URL}/inspect/${encodedPayload}`, {
		method: 'GET',
		signal: AbortSignal.timeout(10000),
	})

	if (!response.ok) {
		return { success: false, error: `Cartesi node returned HTTP ${response.status}` }
	}

	const result = await response.json() as {
		reports?: Array<{ payload: string }>
	}

	if (!result.reports || result.reports.length === 0) {
		return { success: false, error: 'No reports returned from Cartesi node' }
	}

	const rawResponse = hexDecode(result.reports[0].payload)

	// Process (decrypt outer envelope if encrypted)
	const processed = await processLCoreResponse<T>(rawResponse)
	if ('error' in processed) {
		return { success: false, error: processed.error }
	}

	return {
		success: true,
		data: processed.data,
		wasEncrypted: processed.wasEncrypted,
	}
}

// ============= Types =============

interface DeviceAttestationRecord {
	id: number
	device_did: string
	data_hash: string
	encrypted_data: string
	jws: string
	encryption_key_id: string
	timestamp: number
	source: string | null
	input_index: number
	created_at: string
}

interface DeviceAttestationsResponse {
	device_did: string
	count: number
	attestations: DeviceAttestationRecord[]
}

interface AttestationDataResponse {
	attestation_id: string
	grantee: string
	grant_id: string
	grant_type: string
	data_count: number
	data: Array<{
		data_key: string
		encrypted_value: string
		encryption_key_id: string
	}>
}

// ============= Route Handler =============

/**
 * Route handler for /api/inspect/*
 */
export async function handleInspectProxyRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// GET /api/inspect/public-key
	if (path === '/api/inspect/public-key' && method === 'GET') {
		await handlePublicKey(req, res)
		return true
	}

	// All other endpoints are POST
	if (method !== 'POST') {
		return false
	}

	// POST /api/inspect/device-attestations
	if (path === '/api/inspect/device-attestations') {
		await handleDeviceAttestations(req, res)
		return true
	}

	// POST /api/inspect/device-latest
	if (path === '/api/inspect/device-latest') {
		await handleDeviceLatest(req, res)
		return true
	}

	// POST /api/inspect/attestation-data
	if (path === '/api/inspect/attestation-data') {
		await handleAttestationData(req, res)
		return true
	}

	return false
}

// ============= Endpoint Handlers =============

/**
 * GET /api/inspect/public-key
 *
 * Returns the admin NaCl public key so clients know what key
 * to use when requesting re-encrypted data.
 */
async function handlePublicKey(
	_req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const publicKey = getAdminPublicKey()
	if (!publicKey) {
		return sendError(res, 503, 'Decryption not configured')
	}

	sendJson(res, {
		public_key: publicKey,
		algorithm: 'nacl-box',
		key_type: 'x25519',
	})
}

/**
 * POST /api/inspect/device-attestations
 *
 * Query device attestations by DID. If requester_public_key is provided,
 * re-encrypts the encrypted_data blobs for the requester.
 *
 * Body:
 * {
 *   device_did: string,
 *   requester_public_key?: string,  // base64 NaCl public key
 *   limit?: number,
 *   offset?: number,
 * }
 */
async function handleDeviceAttestations(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if (!preflight(res)) return

	const body = await parseJsonBody<{
		device_did: string
		requester_public_key?: string
		limit?: number
		offset?: number
	}>(req)

	if (!body?.device_did) {
		return sendError(res, 400, 'device_did is required')
	}

	if (body.requester_public_key && !validateNaClPublicKey(body.requester_public_key)) {
		return sendError(res, 400, 'Invalid requester_public_key — expected base64-encoded 32-byte NaCl public key')
	}

	const result = await queryCartesiInspect<DeviceAttestationsResponse>(
		'device_attestations',
		{
			device_did: body.device_did,
			limit: String(body.limit ?? 50),
			offset: String(body.offset ?? 0),
		}
	)

	if (!result.success) {
		return sendError(res, 502, result.error)
	}

	// If no requester key, return raw (encrypted blobs stay encrypted)
	if (!body.requester_public_key) {
		return sendJson(res, result.data)
	}

	// Re-encrypt each attestation's encrypted_data for the requester
	const reEncrypted = reEncryptAttestations(
		result.data.attestations,
		body.requester_public_key
	)

	sendJson(res, {
		device_did: result.data.device_did,
		count: result.data.count,
		attestations: reEncrypted,
	})
}

/**
 * POST /api/inspect/device-latest
 *
 * Query latest attestation for a device. If requester_public_key is
 * provided, re-encrypts the encrypted_data for the requester.
 *
 * Body:
 * {
 *   device_did: string,
 *   requester_public_key?: string,
 * }
 */
async function handleDeviceLatest(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if (!preflight(res)) return

	const body = await parseJsonBody<{
		device_did: string
		requester_public_key?: string
	}>(req)

	if (!body?.device_did) {
		return sendError(res, 400, 'device_did is required')
	}

	if (body.requester_public_key && !validateNaClPublicKey(body.requester_public_key)) {
		return sendError(res, 400, 'Invalid requester_public_key — expected base64-encoded 32-byte NaCl public key')
	}

	const result = await queryCartesiInspect<DeviceAttestationRecord & { error?: string }>(
		'device_latest',
		{ device_did: body.device_did }
	)

	if (!result.success) {
		return sendError(res, 502, result.error)
	}

	// Forward Cartesi-level errors (e.g. "No attestations found")
	if (result.data.error) {
		return sendError(res, 404, result.data.error)
	}

	if (!body.requester_public_key) {
		return sendJson(res, result.data)
	}

	// Re-encrypt for requester (pass encryption_key_id + device_did for V2 dispatch)
	const reEncResult = reEncryptForRequester(
		result.data.encrypted_data,
		body.requester_public_key,
		result.data.encryption_key_id,
		result.data.device_did
	)

	if (!reEncResult.success) {
		return sendError(res, 500, `Re-encryption failed: ${reEncResult.error}`)
	}

	sendJson(res, {
		...result.data,
		encrypted_data: reEncResult.encrypted_data,
		re_encrypted_for: 'requester',
	})
}

/**
 * POST /api/inspect/attestation-data
 *
 * Gated read of attestation data — Cartesi checks the access grant,
 * then this proxy re-encrypts the returned data entries for the requester.
 *
 * Body:
 * {
 *   attestation_id: string,
 *   grantee: string,
 *   requester_public_key?: string,
 *   current_input?: number,
 *   data_key?: string,
 * }
 */
async function handleAttestationData(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if (!preflight(res)) return

	const body = await parseJsonBody<{
		attestation_id: string
		grantee: string
		requester_public_key?: string
		current_input?: number
		data_key?: string
	}>(req)

	if (!body?.attestation_id || !body?.grantee) {
		return sendError(res, 400, 'attestation_id and grantee are required')
	}

	if (body.requester_public_key && !validateNaClPublicKey(body.requester_public_key)) {
		return sendError(res, 400, 'Invalid requester_public_key — expected base64-encoded 32-byte NaCl public key')
	}

	const params: Record<string, string> = {
		attestation_id: body.attestation_id,
		grantee: body.grantee,
	}

	if (body.current_input !== undefined) {
		params.current_input = String(body.current_input)
	}

	if (body.data_key) {
		params.data_key = body.data_key
	}

	const result = await queryCartesiInspect<AttestationDataResponse & { error?: string }>(
		'attestation_data',
		params
	)

	if (!result.success) {
		return sendError(res, 502, result.error)
	}

	// Forward access-denied or not-found errors from Cartesi
	if (result.data.error) {
		return sendError(res, 403, result.data.error)
	}

	if (!body.requester_public_key) {
		return sendJson(res, result.data)
	}

	// Re-encrypt each data entry for the requester
	const reEncryptedData = result.data.data.map(entry => {
		const reEnc = reEncryptForRequester(
			entry.encrypted_value,
			body.requester_public_key!
		)

		if (!reEnc.success) {
			return {
				...entry,
				re_encryption_error: reEnc.error,
			}
		}

		return {
			data_key: entry.data_key,
			encrypted_value: reEnc.encrypted_data,
			encryption_key_id: 'requester_key',
			re_encrypted_for: 'requester',
		}
	})

	sendJson(res, {
		attestation_id: result.data.attestation_id,
		grantee: result.data.grantee,
		grant_id: result.data.grant_id,
		grant_type: result.data.grant_type,
		data_count: result.data.data_count,
		data: reEncryptedData,
	})
}

// ============= Internal Helpers =============

/**
 * Pre-flight check: L{CORE} enabled and decryption configured.
 */
function preflight(res: ServerResponse): boolean {
	if (!LCORE_ENABLED) {
		sendError(res, 503, 'L{CORE} is not enabled')
		return false
	}

	if (!isDecryptionConfigured()) {
		sendError(res, 503, 'Decryption not configured — LCORE_PRIVATE_KEY not set')
		return false
	}

	return true
}

/**
 * Re-encrypt encrypted_data blobs in a list of attestation records.
 */
function reEncryptAttestations(
	attestations: DeviceAttestationRecord[],
	requesterPublicKey: string
): Array<DeviceAttestationRecord & { re_encrypted_for?: string; re_encryption_error?: string }> {
	return attestations.map(att => {
		const reEnc = reEncryptForRequester(
			att.encrypted_data,
			requesterPublicKey,
			att.encryption_key_id,
			att.device_did
		)

		if (!reEnc.success) {
			return {
				...att,
				re_encryption_error: reEnc.error,
			}
		}

		return {
			...att,
			encrypted_data: reEnc.encrypted_data,
			re_encrypted_for: 'requester',
		}
	})
}
