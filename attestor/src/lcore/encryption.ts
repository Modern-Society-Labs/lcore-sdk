/**
 * L{CORE} Decryption Module
 *
 * Provides decryption utilities for the Attestor to decrypt responses from Cartesi.
 *
 * ARCHITECTURE:
 * - Admin private key is stored in the TEE environment (never exposed)
 * - Cartesi outputs are encrypted with the admin public key
 * - Only this module (running in TEE) can decrypt
 * - Decryption responses include a TEE signature proving correct decryption
 *
 * See docs/LCORE-ARCHITECTURE.md for full privacy model documentation.
 */

import { utils } from 'ethers'
import nacl from 'tweetnacl'

import { getAttestorAddress, signAsAttestor } from '#src/server/utils/generics.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { SelectedServiceSignatureType } from '#src/utils/signatures/index.ts'

// ============= Types =============

export interface EncryptedOutput {
	version: 1
	algorithm: 'nacl-box'
	nonce: string // Base64-encoded 24-byte nonce
	ciphertext: string // Base64-encoded encrypted data
	publicKey: string // Base64-encoded ephemeral public key
}

/**
 * Decryption proof - TEE signature proving correct decryption.
 *
 * This allows dApps to verify that:
 * 1. The data was decrypted by a trusted TEE
 * 2. The ciphertext hash matches what was received from L{CORE}
 * 3. The plaintext hash matches the returned data
 *
 * Verification: Recover signer from signature, compare to known TEE address.
 */
export interface DecryptionProof {
	/** SHA256 hash of the encrypted payload (hex) */
	ciphertextHash: string
	/** SHA256 hash of the decrypted plaintext JSON (hex) */
	plaintextHash: string
	/** Unix timestamp when decryption occurred */
	timestamp: number
	/** TEE/Attestor wallet address that performed decryption */
	teeAddress: string
	/** ECDSA signature over keccak256(ciphertextHash, plaintextHash, timestamp) */
	signature: string
}

export interface DecryptionResult<T = unknown> {
	success: true
	data: T
}

export interface DecryptionError {
	success: false
	error: string
}

/**
 * Response from L{CORE} with optional decryption proof.
 */
export interface LCoreResponseWithProof<T = unknown> {
	data: T
	wasEncrypted: boolean
	/** Decryption proof (only present if data was encrypted) */
	proof?: DecryptionProof
}

// ============= Key Management =============

let adminPrivateKey: Uint8Array | null = null

/**
 * Initialize the decryption module with the admin private key.
 * This should be called once at startup.
 *
 * @throws Error if LCORE_ADMIN_PRIVATE_KEY is not set
 */
export function initDecryption(): void {
	const privateKeyBase64 = getEnvVariable('LCORE_ADMIN_PRIVATE_KEY')

	if(!privateKeyBase64) {
		console.warn('[LCORE] LCORE_ADMIN_PRIVATE_KEY not set - decryption disabled')
		return
	}

	try {
		adminPrivateKey = base64ToUint8Array(privateKeyBase64)

		if(adminPrivateKey.length !== 32) {
			throw new Error(`Invalid private key length: expected 32 bytes, got ${adminPrivateKey.length}`)
		}

		console.log('[LCORE] Decryption initialized')
	} catch(e) {
		console.error('[LCORE] Failed to initialize decryption:', e)
		adminPrivateKey = null
	}
}

/**
 * Check if decryption is configured and ready.
 */
export function isDecryptionConfigured(): boolean {
	return adminPrivateKey !== null
}

/**
 * Get the admin public key (derived from private key).
 * Useful for verification or registration.
 */
export function getAdminPublicKey(): string | null {
	if(!adminPrivateKey) {
		return null
	}

	const keypair = nacl.box.keyPair.fromSecretKey(adminPrivateKey)
	return uint8ArrayToBase64(keypair.publicKey)
}

// ============= Decryption Functions =============

/**
 * Decrypt an encrypted output from Cartesi.
 *
 * @param encrypted - The encrypted output object
 * @returns Decrypted data or error
 */
export function decryptOutput<T = unknown>(
	encrypted: EncryptedOutput
): DecryptionResult<T> | DecryptionError {
	if(!adminPrivateKey) {
		return {
			success: false,
			error: 'Decryption not configured - LCORE_ADMIN_PRIVATE_KEY not set',
		}
	}

	// Validate version
	if(encrypted.version !== 1) {
		return {
			success: false,
			error: `Unsupported encryption version: ${encrypted.version}`,
		}
	}

	// Validate algorithm
	if(encrypted.algorithm !== 'nacl-box') {
		return {
			success: false,
			error: `Unsupported algorithm: ${encrypted.algorithm}`,
		}
	}

	try {
		// Decode components
		const nonce = base64ToUint8Array(encrypted.nonce)
		const ciphertext = base64ToUint8Array(encrypted.ciphertext)
		const ephemeralPublicKey = base64ToUint8Array(encrypted.publicKey)

		// Validate lengths
		if(nonce.length !== nacl.box.nonceLength) {
			return {
				success: false,
				error: `Invalid nonce length: expected ${nacl.box.nonceLength}, got ${nonce.length}`,
			}
		}

		if(ephemeralPublicKey.length !== nacl.box.publicKeyLength) {
			return {
				success: false,
				error: `Invalid public key length: expected ${nacl.box.publicKeyLength}, got ${ephemeralPublicKey.length}`,
			}
		}

		// Decrypt
		const decrypted = nacl.box.open(
			ciphertext,
			nonce,
			ephemeralPublicKey,
			adminPrivateKey
		)

		if(!decrypted) {
			return {
				success: false,
				error: 'Decryption failed - invalid ciphertext or key mismatch',
			}
		}

		// Parse JSON
		const plaintext = new TextDecoder().decode(decrypted)
		const data = JSON.parse(plaintext) as T

		return {
			success: true,
			data,
		}
	} catch(e) {
		return {
			success: false,
			error: e instanceof Error ? e.message : String(e),
		}
	}
}

// ============= Decryption Proof Functions =============

/**
 * Create a decryption proof for a decrypted response.
 *
 * This signs a proof that the TEE correctly decrypted the ciphertext
 * into the given plaintext, allowing dApps to verify the operation.
 *
 * @param encryptedPayload - The original encrypted payload from L{CORE}
 * @param plaintextJson - The decrypted plaintext as JSON string
 * @returns DecryptionProof signed by TEE
 */
async function createDecryptionProof(
	encryptedPayload: EncryptedOutput,
	plaintextJson: string
): Promise<DecryptionProof> {
	// Hash the encrypted payload (canonical JSON)
	const ciphertextJson = JSON.stringify(encryptedPayload)
	const ciphertextHash = utils.sha256(Buffer.from(ciphertextJson))

	// Hash the plaintext
	const plaintextHash = utils.sha256(Buffer.from(plaintextJson))

	// Current timestamp
	const timestamp = Math.floor(Date.now() / 1000)

	// Get TEE address
	const teeAddress = getAttestorAddress(SelectedServiceSignatureType)

	// Create message to sign: keccak256(ciphertextHash, plaintextHash, timestamp)
	const messageHash = utils.keccak256(
		utils.solidityPack(
			['bytes32', 'bytes32', 'uint256'],
			[ciphertextHash, plaintextHash, timestamp]
		)
	)

	// Sign with TEE private key
	const signatureBytes = await signAsAttestor(
		utils.arrayify(messageHash),
		SelectedServiceSignatureType
	)
	const signature = utils.hexlify(signatureBytes)

	return {
		ciphertextHash,
		plaintextHash,
		timestamp,
		teeAddress,
		signature,
	}
}

/**
 * Verify a decryption proof.
 *
 * This allows dApps to verify that a decryption was performed by a trusted TEE.
 *
 * @param proof - The decryption proof to verify
 * @param expectedTeeAddress - Optional: Expected TEE address (if known)
 * @returns true if proof is valid
 */
export function verifyDecryptionProof(
	proof: DecryptionProof,
	expectedTeeAddress?: string
): boolean {
	try {
		// Recreate the message hash
		const messageHash = utils.keccak256(
			utils.solidityPack(
				['bytes32', 'bytes32', 'uint256'],
				[proof.ciphertextHash, proof.plaintextHash, proof.timestamp]
			)
		)

		// Recover signer from signature
		const recoveredAddress = utils.verifyMessage(
			utils.arrayify(messageHash),
			proof.signature
		)

		// Check if recovered address matches the claimed TEE address
		if(recoveredAddress.toLowerCase() !== proof.teeAddress.toLowerCase()) {
			return false
		}

		// If expected address provided, verify it matches
		if(expectedTeeAddress && expectedTeeAddress.toLowerCase() !== proof.teeAddress.toLowerCase()) {
			return false
		}

		return true
	} catch{
		return false
	}
}

/**
 * Check if a response is encrypted and decrypt if necessary.
 *
 * This handles both encrypted and plaintext responses gracefully.
 * When data is encrypted, includes a TEE-signed proof of correct decryption.
 *
 * @param response - Response from Cartesi (may or may not be encrypted)
 * @returns The decrypted or original data with optional proof
 */
export async function processLCoreResponse<T = unknown>(
	response: unknown
): Promise<LCoreResponseWithProof<T> | { error: string }> {
	// Check if this is an encrypted response
	if(isEncryptedOutput(response)) {
		const encryptedPayload = response.payload

		// Decrypt
		const result = decryptOutput<T>(encryptedPayload)

		if(!result.success) {
			return { error: result.error }
		}

		// Create proof of decryption
		const plaintextJson = JSON.stringify(result.data)
		const proof = await createDecryptionProof(encryptedPayload, plaintextJson)

		return {
			data: result.data,
			wasEncrypted: true,
			proof,
		}
	}

	// Check if it's a plaintext wrapper
	if(
		typeof response === 'object' &&
		response !== null &&
		'encrypted' in response &&
		(response as { encrypted: boolean }).encrypted === false &&
		'data' in response
	) {
		return {
			data: (response as { data: T }).data,
			wasEncrypted: false,
		}
	}

	// Assume plaintext response
	return {
		data: response as T,
		wasEncrypted: false,
	}
}

/**
 * Synchronous version of processLCoreResponse without proof generation.
 *
 * Use this when you don't need the decryption proof (internal use).
 */
export function processLCoreResponseSync<T = unknown>(
	response: unknown
): { data: T, wasEncrypted: boolean } | { error: string } {
	// Check if this is an encrypted response
	if(isEncryptedOutput(response)) {
		const result = decryptOutput<T>(response.payload)

		if(!result.success) {
			return { error: result.error }
		}

		return {
			data: result.data,
			wasEncrypted: true,
		}
	}

	// Check if it's a plaintext wrapper
	if(
		typeof response === 'object' &&
		response !== null &&
		'encrypted' in response &&
		(response as { encrypted: boolean }).encrypted === false &&
		'data' in response
	) {
		return {
			data: (response as { data: T }).data,
			wasEncrypted: false,
		}
	}

	// Assume plaintext response
	return {
		data: response as T,
		wasEncrypted: false,
	}
}

// ============= Type Guards =============

/**
 * Check if a response is an encrypted output envelope.
 */
export function isEncryptedOutput(
	response: unknown
): response is { encrypted: true, payload: EncryptedOutput } {
	if(typeof response !== 'object' || response === null) {
		return false
	}

	const obj = response as Record<string, unknown>

	if(obj.encrypted !== true) {
		return false
	}

	if(!obj.payload || typeof obj.payload !== 'object') {
		return false
	}

	const payload = obj.payload as Record<string, unknown>

	return (
		payload.version === 1 &&
		payload.algorithm === 'nacl-box' &&
		typeof payload.nonce === 'string' &&
		typeof payload.ciphertext === 'string' &&
		typeof payload.publicKey === 'string'
	)
}

// ============= Input Encryption (for device attestation privacy) =============

/**
 * INPUT ENCRYPTION MODULE
 *
 * This module handles encryption of device attestation data BEFORE it is
 * submitted to the InputBox. This ensures device data remains private
 * on-chain (only ciphertext visible on the blockchain).
 *
 * Flow:
 * Device → Attestor (encrypts here with INPUT public key) → InputBox (ciphertext) → Cartesi (decrypts)
 *
 * The input keypair is SEPARATE from the output keypair:
 * - Output keypair: Cartesi encrypts → Attestor decrypts (existing, above)
 * - Input keypair: Attestor encrypts (this) → Cartesi decrypts
 */

let inputPublicKey: Uint8Array | null = null

/**
 * Initialize input encryption with the public key.
 * Call this at startup - reads from LCORE_INPUT_PUBLIC_KEY environment variable.
 */
export function initInputEncryption(): void {
	const publicKeyBase64 = getEnvVariable('LCORE_INPUT_PUBLIC_KEY')

	if(!publicKeyBase64) {
		console.warn('[LCORE] LCORE_INPUT_PUBLIC_KEY not set - input encryption disabled')
		return
	}

	try {
		inputPublicKey = base64ToUint8Array(publicKeyBase64)

		if(inputPublicKey.length !== 32) {
			throw new Error(`Invalid public key length: expected 32 bytes, got ${inputPublicKey.length}`)
		}

		console.log('[LCORE] Input encryption initialized')
	} catch(e) {
		console.error('[LCORE] Failed to initialize input encryption:', e)
		inputPublicKey = null
	}
}

/**
 * Check if input encryption is configured and ready.
 */
export function isInputEncryptionConfigured(): boolean {
	return inputPublicKey !== null
}

/**
 * Encrypt data for submission to InputBox.
 *
 * This encrypts device attestation payloads before they are submitted
 * to the Cartesi InputBox, ensuring the data is not visible on-chain.
 *
 * Uses NaCl box with an ephemeral keypair for forward secrecy.
 *
 * @param data - Data to encrypt (will be JSON.stringified)
 * @returns EncryptedOutput object ready for submission
 * @throws Error if input encryption is not configured
 */
export function encryptInput(data: unknown): EncryptedOutput {
	if(!inputPublicKey) {
		throw new Error('Input encryption not configured - LCORE_INPUT_PUBLIC_KEY not set')
	}

	// Convert data to string
	const plaintext = typeof data === 'string' ? data : JSON.stringify(data)
	const plaintextBytes = new TextEncoder().encode(plaintext)

	// Generate ephemeral keypair for this message (forward secrecy)
	const ephemeral = nacl.box.keyPair()

	// Generate random nonce
	const nonce = nacl.randomBytes(nacl.box.nonceLength)

	// Encrypt using NaCl box
	const ciphertext = nacl.box(
		plaintextBytes,
		nonce,
		inputPublicKey,
		ephemeral.secretKey
	)

	return {
		version: 1,
		algorithm: 'nacl-box',
		nonce: uint8ArrayToBase64(nonce),
		ciphertext: uint8ArrayToBase64(ciphertext),
		publicKey: uint8ArrayToBase64(ephemeral.publicKey),
	}
}

/**
 * Wrap encrypted input in the standard envelope format.
 *
 * @param data - Data to encrypt
 * @returns Object with encrypted flag and payload
 */
export function encryptInputEnvelope(data: unknown): { encrypted: true; payload: EncryptedOutput } {
	return {
		encrypted: true,
		payload: encryptInput(data),
	}
}

// ============= Helper Functions =============

/**
 * Convert a Base64 string to Uint8Array.
 */
function base64ToUint8Array(base64: string): Uint8Array {
	return new Uint8Array(Buffer.from(base64, 'base64'))
}

/**
 * Convert a Uint8Array to Base64 string.
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64')
}
