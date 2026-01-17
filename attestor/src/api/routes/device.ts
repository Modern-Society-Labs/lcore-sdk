/**
 * Device Direct Submission API routes
 *
 * Endpoint for IoT devices to submit signed sensor data directly.
 * Devices use did:key for identity and JWS for signature verification.
 *
 * POST /api/device/submit - Submit signed device data
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { parseJsonBody, sendError, sendJson } from '#src/api/utils/http.ts'
import { parseDIDKey, verifyJWS } from '#src/api/services/did.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { ethers, Wallet } from 'ethers'

// Reuse L{CORE} configuration
const LCORE_RPC_URL = getEnvVariable('LCORE_RPC_URL') || ''
const LCORE_DAPP_ADDRESS = getEnvVariable('LCORE_DAPP_ADDRESS') || ''
const LCORE_INPUTBOX_ADDRESS = getEnvVariable('LCORE_INPUTBOX_ADDRESS') || '0x59b22D57D4f067708AB0c00552767405926dc768'
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'

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

/**
 * Submit device attestation to L{CORE} Cartesi rollup
 */
async function submitDeviceAttestation(
	deviceDid: string,
	data: Record<string, unknown>,
	timestamp: number
): Promise<{ success: boolean; data?: unknown; error?: string }> {
	if (!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	if (!LCORE_DAPP_ADDRESS) {
		return { success: false, error: 'LCORE_DAPP_ADDRESS is required' }
	}

	try {
		const wallet = getWallet()
		const inputBox = new ethers.Contract(LCORE_INPUTBOX_ADDRESS, INPUT_BOX_ABI, wallet)

		const inputData = hexEncode({
			action: 'device_attestation',
			device_did: deviceDid,
			data,
			timestamp,
			source: 'direct'
		})

		// Submit to InputBox contract
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
 * POST /api/device/submit
 * Submit signed device sensor data
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

	// Parse did:key to extract public key
	const publicKey = parseDIDKey(body.did)
	if (!publicKey) {
		return sendError(res, 400, 'Invalid did:key format. Expected did:key:z... with secp256k1 key')
	}

	// Verify JWS signature
	const isValid = verifyJWS(body.signature, body.payload, publicKey)
	if (!isValid) {
		return sendError(res, 401, 'Invalid signature')
	}

	// Submit to Cartesi
	const result = await submitDeviceAttestation(
		body.did,
		body.payload,
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
