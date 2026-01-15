/**
 * L{CORE} SDK Client
 *
 * Client for submitting attestations to the L{CORE} Cartesi rollup layer.
 * Supports production mode (on-chain InputBox + node inspect API).
 *
 * PRIVACY NOTE: Responses from L{CORE} may be encrypted. This client
 * automatically decrypts responses using the admin private key stored in TEE.
 */

import { ethers, Wallet } from 'ethers'
import { type DecryptionProof, processLCoreResponse } from 'src/lcore/encryption.ts'

import { getEnvVariable } from '#src/utils/env.ts'

// Production Cartesi node configuration
const LCORE_NODE_URL = getEnvVariable('LCORE_NODE_URL') || 'http://127.0.0.1:10000'
const LCORE_RPC_URL = getEnvVariable('LCORE_RPC_URL') || ''
const LCORE_DAPP_ADDRESS = getEnvVariable('LCORE_DAPP_ADDRESS') || ''
const LCORE_INPUTBOX_ADDRESS = getEnvVariable('LCORE_INPUTBOX_ADDRESS') || '0x59b22D57D4f067708AB0c00552767405926dc768'

// InputBox ABI (minimal)
const INPUT_BOX_ABI = [
	'function addInput(address _dapp, bytes calldata _input) external returns (bytes32)'
]

// Wallet for signing transactions (from MNEMONIC env var injected by EigenCloud)
let _wallet: Wallet | null = null
let _provider: ethers.providers.JsonRpcProvider | null = null

function getProvider(): ethers.providers.JsonRpcProvider {
	if(!_provider) {
		if(!LCORE_RPC_URL) {
			throw new Error('LCORE_RPC_URL is required for production mode')
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

		_wallet = Wallet.fromMnemonic(mnemonic).connect(getProvider())
	}

	return _wallet
}

/**
 * Hex encode data for Cartesi input
 */
function hexEncode(data: unknown): string {
	const jsonStr = JSON.stringify(data)
	return '0x' + Buffer.from(jsonStr, 'utf-8').toString('hex')
}

/**
 * Hex decode Cartesi output
 */
function hexDecode(hex: string): unknown {
	const str = Buffer.from(hex.slice(2), 'hex').toString('utf-8')
	return JSON.parse(str)
}

interface IngestAttestationInput {
	id: string
	attestationHash: string
	ownerAddress: string
	provider: string
	flowType: string
	validFrom: number
	validUntil?: number
	teeSignature: string
	buckets: Array<{ key: string, value: string }>
	data: Array<{ key: string, value: string, encryptionKeyId: string }>
}

interface AttestationResult {
	success: boolean
	attestationId?: string
	attestationHash?: string
	domain?: string
	provider?: string
	flowType?: string
	error?: string
	details?: string
}

/**
 * Submit an attestation to the L{CORE} Cartesi rollup layer.
 *
 * This is called after the attestor creates and signs a claim,
 * forwarding it to the Cartesi layer for deterministic storage
 * and privacy-preserving queries.
 *
 * Uses the InputBox contract to submit on-chain transactions.
 */
export async function submitAttestationToLCore(
	input: IngestAttestationInput,
	_senderAddress: string
): Promise<AttestationResult> {
	const payload = {
		action: 'ingest_attestation',
		id: input.id,
		attestation_hash: input.attestationHash,
		owner_address: input.ownerAddress,
		provider: input.provider,
		flow_type: input.flowType,
		valid_from: input.validFrom,
		valid_until: input.validUntil,
		tee_signature: input.teeSignature,
		buckets: input.buckets,
		data: input.data.map(d => ({
			key: d.key,
			value: d.value, // Already base64 encoded
			encryption_key_id: d.encryptionKeyId,
		})),
	}

	try {
		if(!LCORE_DAPP_ADDRESS) {
			throw new Error('LCORE_DAPP_ADDRESS is required')
		}

		const wallet = getWallet()
		const inputBox = new ethers.Contract(LCORE_INPUTBOX_ADDRESS, INPUT_BOX_ABI, wallet)
		const inputData = hexEncode(payload)

		// Submit to InputBox contract
		const tx = await inputBox.addInput(LCORE_DAPP_ADDRESS, inputData)
		const receipt = await tx.wait()

		if(!receipt) {
			return {
				success: false,
				error: 'Transaction failed - no receipt',
			}
		}

		// Transaction submitted successfully
		// Note: We return success immediately after on-chain confirmation
		// The Cartesi node will process the input asynchronously
		return {
			success: true,
			attestationId: input.id,
			attestationHash: input.attestationHash,
			provider: input.provider,
			flowType: input.flowType,
		}
	} catch(error) {
		return {
			success: false,
			error: 'Failed to submit to L{CORE} InputBox',
			details: error instanceof Error ? error.message : String(error),
		}
	}
}

/**
 * Query result from L{CORE} with optional decryption proof.
 */
export interface LCoreQueryResult<T = unknown> {
	data: T
	/** Whether the response was encrypted (and decrypted by TEE) */
	wasEncrypted: boolean
	/** Decryption proof - only present if data was encrypted */
	proof?: DecryptionProof
}

/**
 * Query error result.
 */
export interface LCoreQueryError {
	error: string
	details?: string
}

/**
 * Query attestation from L{CORE} by ID or hash.
 *
 * PRIVACY: Response may be encrypted. This function automatically
 * decrypts if encryption is configured and includes a TEE-signed
 * proof of correct decryption.
 */
export async function queryAttestationFromLCore<T = unknown>(
	params: { id?: string, hash?: string }
): Promise<LCoreQueryResult<T> | LCoreQueryError> {
	try {
		// Build inspect query
		const query = { type: 'attestation', params }
		const hexPayload = hexEncode(query).slice(2) // Remove 0x prefix for URL

		const response = await fetch(`${LCORE_NODE_URL}/inspect/${hexPayload}`, {
			method: 'GET',
		})

		if(!response.ok) {
			return { error: `HTTP ${response.status}: ${response.statusText}` }
		}

		const result = await response.json() as { reports?: Array<{ payload: string }> }

		if(!result.reports || result.reports.length === 0) {
			return { error: 'No reports returned' }
		}

		// Decode hex payload from Cartesi node
		const rawResponse = hexDecode(result.reports[0].payload)

		// Process response (decrypt if encrypted, generate proof)
		const processed = await processLCoreResponse<T>(rawResponse)
		if('error' in processed) {
			return { error: processed.error }
		}

		return {
			data: processed.data,
			wasEncrypted: processed.wasEncrypted,
			proof: processed.proof,
		}
	} catch(error) {
		return {
			error: 'Failed to query L{CORE}',
			details: error instanceof Error ? error.message : String(error),
		}
	}
}

/**
 * Check if L{CORE} Cartesi node is healthy.
 */
export async function checkLCoreHealth(): Promise<boolean> {
	try {
		// Check if node responds to GraphQL
		const response = await fetch(`${LCORE_NODE_URL}/graphql`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ query: '{ inputs { totalCount } }' }),
			signal: AbortSignal.timeout(5000),
		})
		return response.ok
	} catch{
		return false
	}
}

/**
 * Get L{CORE} server status.
 */
export async function getLCoreStatus(): Promise<unknown> {
	try {
		const response = await fetch(`${LCORE_NODE_URL}/graphql`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				query: `{
					inputs { totalCount }
				}`
			}),
		})

		if(!response.ok) {
			return { status: 'error', error: `HTTP ${response.status}` }
		}

		const data = await response.json()
		return {
			status: 'running',
			nodeUrl: LCORE_NODE_URL,
			dappAddress: LCORE_DAPP_ADDRESS,
			...data,
		}
	} catch(error) {
		return {
			status: 'unavailable',
			error: error instanceof Error ? error.message : String(error),
		}
	}
}
