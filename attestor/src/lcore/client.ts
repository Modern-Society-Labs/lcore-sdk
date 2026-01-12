/**
 * L{CORE} SDK Client
 *
 * Client for submitting attestations to the L{CORE} Cartesi rollup layer.
 * This runs embedded in the attestor container and communicates with
 * the local test-rollup-server and lcore-main processes.
 *
 * PRIVACY NOTE: Responses from L{CORE} may be encrypted. This client
 * automatically decrypts responses using the admin private key stored in TEE.
 */

import { getEnvVariable } from '#src/utils/env.ts'
import { processLCoreResponse, type DecryptionProof } from './encryption.ts'

// Default to local embedded rollup server
const LCORE_ROLLUP_URL = getEnvVariable('LCORE_ROLLUP_URL') || 'http://127.0.0.1:5004'

interface IngestAttestationInput {
	id: string
	attestationHash: string
	ownerAddress: string
	provider: string
	flowType: string
	validFrom: number
	validUntil?: number
	teeSignature: string
	buckets: Array<{ key: string; value: string }>
	data: Array<{ key: string; value: string; encryptionKeyId: string }>
}

interface LCoreResponse {
	status: 'accept' | 'reject'
	notices: Array<{ payload: string; payloadJson: unknown }>
	reports: Array<{ payload: string; payloadJson: unknown }>
	vouchers: Array<{ destination: string; payload: string }>
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
 */
export async function submitAttestationToLCore(
	input: IngestAttestationInput,
	senderAddress: string
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
		const response = await fetch(`${LCORE_ROLLUP_URL}/input/advance`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				sender: senderAddress,
				payload,
			}),
		})

		if (!response.ok) {
			return {
				success: false,
				error: `HTTP ${response.status}: ${response.statusText}`,
			}
		}

		const result = await response.json() as LCoreResponse

		if (result.status === 'reject') {
			// Check reports for error details
			const errorReport = result.reports.find(r =>
				r.payloadJson && typeof r.payloadJson === 'object' && 'error' in (r.payloadJson as object)
			)
			const errorPayload = errorReport?.payloadJson as { error?: string; details?: string } | undefined

			return {
				success: false,
				error: errorPayload?.error || 'Request rejected',
				details: errorPayload?.details,
			}
		}

		// Extract result from notice
		const notice = result.notices[0]?.payloadJson as AttestationResult | undefined

		return {
			success: notice?.success ?? true,
			attestationId: notice?.attestationId,
			attestationHash: notice?.attestationHash,
			domain: notice?.domain,
			provider: notice?.provider,
			flowType: notice?.flowType,
		}
	} catch (error) {
		return {
			success: false,
			error: 'Failed to connect to L{CORE} rollup',
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
	params: { id?: string; hash?: string }
): Promise<LCoreQueryResult<T> | LCoreQueryError> {
	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/input/inspect`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				type: 'attestation',
				params,
			}),
		})

		if (!response.ok) {
			return { error: `HTTP ${response.status}: ${response.statusText}` }
		}

		const result = await response.json() as { reports: Array<{ payloadJson: unknown }> }
		const rawResponse = result.reports[0]?.payloadJson

		// Process response (decrypt if encrypted, generate proof)
		const processed = await processLCoreResponse<T>(rawResponse)
		if ('error' in processed) {
			return { error: processed.error }
		}

		return {
			data: processed.data,
			wasEncrypted: processed.wasEncrypted,
			proof: processed.proof,
		}
	} catch (error) {
		return {
			error: 'Failed to query L{CORE}',
			details: error instanceof Error ? error.message : String(error),
		}
	}
}

/**
 * Check if L{CORE} rollup server is healthy.
 */
export async function checkLCoreHealth(): Promise<boolean> {
	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/health`, {
			method: 'GET',
			signal: AbortSignal.timeout(5000),
		})
		return response.ok
	} catch {
		return false
	}
}

/**
 * Get L{CORE} server status.
 */
export async function getLCoreStatus(): Promise<unknown> {
	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/status`, {
			method: 'GET',
		})
		return response.json()
	} catch (error) {
		return {
			status: 'unavailable',
			error: error instanceof Error ? error.message : String(error),
		}
	}
}
