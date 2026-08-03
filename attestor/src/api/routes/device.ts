/**
 * Device Direct Submission API routes
 *
 * Endpoint for IoT devices to submit signed sensor data directly.
 * Devices use did:key for identity and JWS for signature verification.
 *
 * SECURITY MODEL:
 * - Device signs a deterministic hash: sha256(canonical_json(payload) + did + timestamp)
 * - Attestor recomputes hash and verifies device JWS (fail-fast pre-check)
 * - Cartesi independently re-verifies the JWS over hash (fraud-provable)
 * - Inputs are encrypted before hitting the InputBox (privacy)
 * - Anyone can re-run Cartesi and verify every signature was valid
 *
 * BATCHING:
 * - Submissions are buffered and flushed as batch_device_attestation
 * - Mitigates metadata activity pattern leaks (timing, cadence)
 * - Configurable via LCORE_BATCH_FLUSH_INTERVAL and LCORE_BATCH_MAX_SIZE
 * - Set LCORE_BATCH_ENABLED=0 to disable batching (direct submission)
 *
 * POST /api/device/submit - Submit signed device data
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { parseJsonBody, sendError, sendJson } from '#src/api/utils/http.ts'
import { isValidDIDKeyFormat, parseDIDKey, verifyJWSOverHash } from '#src/api/services/did.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { ethers, Wallet } from 'ethers'
import { encryptDataForSubmission, encryptDataForSubmissionV2, computeDataHash, isInputEncryptionConfigured, isV2Configured } from '#src/lcore/encryption.ts'
import { SubmissionBatcher, type BatchableSubmission, type BatchFlushResult } from '#src/submission-batcher.ts'

// Reuse L{CORE} configuration
const LCORE_RPC_URL = getEnvVariable('LCORE_RPC_URL') || ''
const LCORE_DAPP_ADDRESS = getEnvVariable('LCORE_DAPP_ADDRESS') || ''
const LCORE_INPUTBOX_ADDRESS = getEnvVariable('LCORE_INPUTBOX_ADDRESS') || '0x59b22D57D4f067708AB0c00552767405926dc768'
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'
const BATCH_ENABLED = getEnvVariable('LCORE_BATCH_ENABLED') !== '0'

// Replay protection: reject re-submission of an identical signed data_hash
// within the freshness window. data_hash = sha256(payload + did + timestamp),
// so an intercepted submission is byte-identical on replay. In-memory and
// per-process — adequate for a single attestor; back with a shared store
// (as auth nonces already are) for multi-node deployments.
const REPLAY_TTL_MS = 10 * 60 * 1000 // covers the ±5min timestamp window
const MAX_REPLAY_ENTRIES = 100_000
const seenDataHashes = new Map<string, number>() // data_hash -> expiry (epoch ms)

function isReplayedDataHash(dataHash: string): boolean {
	const now = Date.now()
	// Bounded lazy purge of expired entries when the cache hits its cap
	if (seenDataHashes.size >= MAX_REPLAY_ENTRIES) {
		for (const [h, exp] of seenDataHashes) {
			if (exp <= now) seenDataHashes.delete(h)
		}
	}
	const existing = seenDataHashes.get(dataHash)
	if (existing !== undefined && existing > now) {
		return true
	}
	seenDataHashes.set(dataHash, now + REPLAY_TTL_MS)
	return false
}

// InputBox ABI (minimal)
const INPUT_BOX_ABI = [
	'function addInput(address _dapp, bytes calldata _input) external returns (bytes32)'
]

// Wallet for signing transactions (shared with lcore.ts)
let _wallet: Wallet | null = null
let _provider: ethers.providers.JsonRpcProvider | null = null

function getProvider(): ethers.providers.JsonRpcProvider {
	if (!_provider) {
		if (!LCORE_RPC_URL) {
			throw new Error('LCORE_RPC_URL is required for production mode')
		}
		_provider = new ethers.providers.JsonRpcProvider(LCORE_RPC_URL)
	}
	return _provider
}

function getWallet(): Wallet {
	if (!_wallet) {
		const mnemonic = getEnvVariable('MNEMONIC')
		if (!mnemonic) {
			throw new Error('MNEMONIC is required for signing transactions')
		}
		_wallet = Wallet.fromMnemonic(mnemonic).connect(getProvider())
	}
	return _wallet
}

function hexEncode(data: unknown): string {
	const jsonStr = JSON.stringify(data)
	return '0x' + Buffer.from(jsonStr, 'utf-8').toString('hex')
}

interface DeviceSubmission {
	did: string
	payload: Record<string, unknown>
	signature: string
	timestamp: number
}

// ============= Batch Flush Function =============

/**
 * Flush a batch of submissions to the InputBox as a single transaction.
 */
async function flushBatch(submissions: BatchableSubmission[]): Promise<BatchFlushResult> {
	try {
		const wallet = getWallet()
		const inputBox = new ethers.Contract(LCORE_INPUTBOX_ADDRESS, INPUT_BOX_ABI, wallet)

		const batchPayload = {
			action: 'batch_device_attestation',
			submissions,
		}

		const inputData = hexEncode(batchPayload)
		const tx = await inputBox.addInput(LCORE_DAPP_ADDRESS, inputData)
		const receipt = await tx.wait()

		if (!receipt) {
			return { success: false, count: submissions.length, error: 'Transaction failed - no receipt' }
		}

		return {
			success: true,
			count: submissions.length,
			txHash: tx.hash,
			blockNumber: receipt.blockNumber,
		}
	} catch (error) {
		return {
			success: false,
			count: submissions.length,
			error: error instanceof Error ? error.message : String(error),
		}
	}
}

// Singleton batcher instance
let _batcher: SubmissionBatcher | null = null

function getBatcher(): SubmissionBatcher {
	if (!_batcher) {
		_batcher = new SubmissionBatcher(flushBatch)
		_batcher.start()
	}
	return _batcher
}

/**
 * Stop the batcher and flush remaining items. Call on shutdown.
 */
export async function stopBatcher(): Promise<BatchFlushResult | null> {
	if (_batcher) {
		const result = await _batcher.stop()
		_batcher = null
		return result
	}
	return null
}

// ============= Submission Logic =============

/**
 * Build a submission from device data.
 * Uses V2 per-device ECDH when configured, falls back to V1.
 */
function buildSubmission(
	deviceDid: string,
	data: Record<string, unknown>,
	signature: string,
	timestamp: number
): BatchableSubmission {
	const encrypted = isV2Configured()
		? encryptDataForSubmissionV2(data, deviceDid, timestamp)
		: encryptDataForSubmission(data, deviceDid, timestamp)

	return {
		action: 'device_attestation',
		data_hash: encrypted.data_hash,
		jws: signature,
		encrypted_data: encrypted.encrypted_data,
		device_did: deviceDid,
		timestamp,
		encryption_key_id: encrypted.encryption_key_id,
		source: 'relay',
	}
}

/**
 * Submit device attestation directly to InputBox (non-batched).
 */
async function submitDeviceAttestationDirect(
	deviceDid: string,
	data: Record<string, unknown>,
	signature: string,
	timestamp: number
): Promise<{ success: boolean; data?: unknown; error?: string }> {
	if (!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	if (!LCORE_DAPP_ADDRESS) {
		return { success: false, error: 'LCORE_DAPP_ADDRESS is required' }
	}

	if (!isInputEncryptionConfigured()) {
		return {
			success: false,
			error: 'Input encryption not configured - LCORE_PUBLIC_KEY required'
		}
	}

	try {
		const wallet = getWallet()
		const inputBox = new ethers.Contract(LCORE_INPUTBOX_ADDRESS, INPUT_BOX_ABI, wallet)

		const payload = buildSubmission(deviceDid, data, signature, timestamp)
		const inputData = hexEncode(payload)

		const tx = await inputBox.addInput(LCORE_DAPP_ADDRESS, inputData)
		const receipt = await tx.wait()

		if (!receipt) {
			return { success: false, error: 'Transaction failed - no receipt' }
		}

		return {
			success: true,
			data: { txHash: tx.hash, blockNumber: receipt.blockNumber }
		}
	} catch (error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : String(error)
		}
	}
}

/**
 * Submit device attestation via the batcher (batched mode).
 * Returns immediately with a buffered receipt.
 */
async function submitDeviceAttestationBatched(
	deviceDid: string,
	data: Record<string, unknown>,
	signature: string,
	timestamp: number
): Promise<{ success: boolean; data?: unknown; error?: string }> {
	if (!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	if (!LCORE_DAPP_ADDRESS) {
		return { success: false, error: 'LCORE_DAPP_ADDRESS is required' }
	}

	if (!isInputEncryptionConfigured()) {
		return {
			success: false,
			error: 'Input encryption not configured - LCORE_PUBLIC_KEY required'
		}
	}

	const submission = buildSubmission(deviceDid, data, signature, timestamp)
	const batcher = getBatcher()
	const flushResult = await batcher.add(submission)

	// If max-size triggered an immediate flush, report it
	if (flushResult && !flushResult.success) {
		return { success: false, error: flushResult.error }
	}

	return {
		success: true,
		data: {
			batched: true,
			buffer_size: batcher.size,
			data_hash: submission.data_hash,
			...(flushResult ? { txHash: flushResult.txHash, blockNumber: flushResult.blockNumber } : {}),
		}
	}
}

// ============= HTTP Handlers =============

/**
 * POST /api/device/submit
 * Submit signed device sensor data
 *
 * The device signs a deterministic hash of its payload:
 *   data_hash = sha256(canonical_json(payload) + device_did + timestamp)
 *
 * The attestor:
 * 1. Recomputes the same data_hash from the payload
 * 2. Verifies the device's JWS over that hash (fail-fast pre-check)
 * 3. Encrypts the payload and submits to Cartesi
 * 4. Cartesi independently re-verifies the JWS (fraud-provable)
 */
async function handleDeviceSubmit(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const body = await parseJsonBody<DeviceSubmission>(req)

	if (!body) {
		return sendError(res, 400, 'Invalid request body')
	}

	// Validate required fields
	if (!body.did) {
		return sendError(res, 400, 'did is required')
	}

	if (!body.payload || typeof body.payload !== 'object' || Array.isArray(body.payload)) {
		return sendError(res, 400, 'payload is required and must be an object')
	}

	if (!body.signature) {
		return sendError(res, 400, 'signature is required')
	}

	if (!body.timestamp || typeof body.timestamp !== 'number') {
		return sendError(res, 400, 'timestamp is required and must be a number')
	}

	// Validate timestamp is recent (within 5 minutes)
	const now = Math.floor(Date.now() / 1000)
	const maxAge = 5 * 60 // 5 minutes
	if (Math.abs(now - body.timestamp) > maxAge) {
		return sendError(res, 400, 'timestamp is too old or in the future')
	}

	// Validate DID format
	if (!isValidDIDKeyFormat(body.did)) {
		return sendError(res, 400, 'Invalid did:key format. Expected did:key:z... with secp256k1 key')
	}

	// Recompute the deterministic data_hash from the payload
	// The device computed the same hash and signed it
	const dataHash = computeDataHash(body.payload, body.did, body.timestamp)

	// Verify the device's JWS over the data_hash (fail-fast pre-check)
	// Cartesi will independently re-verify this (fraud-provable)
	const pubKey = parseDIDKey(body.did)
	if (!pubKey) {
		return sendError(res, 400, 'Could not parse public key from did:key')
	}

	const jwsValid = verifyJWSOverHash(body.signature, dataHash, pubKey)
	if (!jwsValid) {
		return sendError(res, 401, 'Invalid device signature — JWS verification over data_hash failed')
	}

	// Replay protection: reject an identical signed submission seen within the
	// freshness window (checked only after the signature is verified, so an
	// attacker cannot poison the cache with unsigned hashes).
	if (isReplayedDataHash(dataHash)) {
		return sendError(res, 409, 'Duplicate submission — this signed data_hash was already accepted')
	}

	// Submit via batcher or directly based on configuration
	const submitFn = BATCH_ENABLED
		? submitDeviceAttestationBatched
		: submitDeviceAttestationDirect

	const result = await submitFn(
		body.did,
		body.payload,
		body.signature,
		body.timestamp
	)

	if (!result.success) {
		return sendError(res, 500, result.error || 'Failed to submit device attestation')
	}

	sendJson(res, {
		success: true,
		data: result.data
	}, 201)
}

/**
 * Route handler for /api/device/*
 */
export async function handleDeviceRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// POST /api/device/submit
	if (path === '/api/device/submit' && method === 'POST') {
		await handleDeviceSubmit(req, res)
		return true
	}

	return false
}
