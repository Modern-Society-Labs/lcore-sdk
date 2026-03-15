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

import canonicalize from 'canonicalize'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { utils } from 'ethers'
import nacl from 'tweetnacl'

import { getAttestorAddress, signAsAttestor } from '#src/server/utils/generics.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { SelectedServiceSignatureType } from '#src/utils/signatures/index.ts'

// ============= Types =============

export type CipherAlgorithm = 'nacl-box' | 'xchacha20-poly1305'

export interface EncryptedOutput {
	version: 1
	algorithm: CipherAlgorithm
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
 * Initialize the decryption module with the private key.
 * V1: reads LCORE_PRIVATE_KEY (falls back to LCORE_ADMIN_PRIVATE_KEY for migration).
 * This should be called once at startup.
 */
export function initDecryption(): void {
	const privateKeyBase64 = getEnvVariable('LCORE_PRIVATE_KEY') || getEnvVariable('LCORE_ADMIN_PRIVATE_KEY')

	if(!privateKeyBase64) {
		console.warn('[LCORE] LCORE_PRIVATE_KEY not set - decryption disabled')
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
	if(encrypted.algorithm !== 'nacl-box' && encrypted.algorithm !== 'xchacha20-poly1305') {
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

		// Validate lengths (both algorithms use 24-byte nonce and 32-byte keys)
		if(nonce.length !== 24) {
			return {
				success: false,
				error: `Invalid nonce length: expected 24, got ${nonce.length}`,
			}
		}

		if(ephemeralPublicKey.length !== 32) {
			return {
				success: false,
				error: `Invalid public key length: expected 32, got ${ephemeralPublicKey.length}`,
			}
		}

		let decrypted: Uint8Array | null

		if(encrypted.algorithm === 'xchacha20-poly1305') {
			// X25519 ECDH shared secret + XChaCha20-Poly1305 AEAD
			const sharedSecret = nacl.scalarMult(adminPrivateKey, ephemeralPublicKey)
			decrypted = xchacha20poly1305(sharedSecret, nonce).decrypt(ciphertext)
		} else {
			// Legacy NaCl box (X25519-XSalsa20-Poly1305)
			decrypted = nacl.box.open(
				ciphertext,
				nonce,
				ephemeralPublicKey,
				adminPrivateKey
			)
		}

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
	// Hash the encrypted payload (RFC 8785 canonical JSON)
	const ciphertextJson = (canonicalize as unknown as (v: unknown) => string)(encryptedPayload)
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
 * V1: reads LCORE_PUBLIC_KEY (falls back to LCORE_INPUT_PUBLIC_KEY for migration).
 */
export function initInputEncryption(): void {
	const publicKeyBase64 = getEnvVariable('LCORE_PUBLIC_KEY') || getEnvVariable('LCORE_INPUT_PUBLIC_KEY')

	if(!publicKeyBase64) {
		console.warn('[LCORE] LCORE_PUBLIC_KEY not set - input encryption disabled')
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
 * Uses X25519 ECDH + XChaCha20-Poly1305 AEAD with an ephemeral keypair
 * for forward secrecy.
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

	// Generate random 24-byte nonce (safe with random nonces for XChaCha20)
	const nonce = nacl.randomBytes(24)

	// X25519 ECDH shared secret
	const sharedSecret = nacl.scalarMult(ephemeral.secretKey, inputPublicKey)

	// Encrypt using XChaCha20-Poly1305 AEAD
	const ciphertext = xchacha20poly1305(sharedSecret, nonce).encrypt(plaintextBytes)

	return {
		version: 1,
		algorithm: 'xchacha20-poly1305',
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

// ============= V1 Data Encryption =============

/**
 * Compute a salted hash of data for V1 submissions.
 *
 * hash = sha256(canonical_json(data) + salt)
 *
 * The salt is included inside the encrypted blob so only the TEE can
 * recover it — prevents brute-forcing bounded data values.
 *
 * @param data - The data to hash
 * @param salt - 16-byte random salt
 * @returns hex-encoded SHA-256 hash (64 chars)
 */
export function computeDataHash(data: unknown, salt: Uint8Array): string {
	const canonical = typeof data === 'string' ? data : (canonicalize as unknown as (v: unknown) => string)(data)
	const combined = canonical + uint8ArrayToBase64(salt)
	const hash = utils.sha256(Buffer.from(combined))
	// Remove 0x prefix from ethers sha256
	return hash.startsWith('0x') ? hash.slice(2) : hash
}

/**
 * Encrypt data for V1 submission format.
 *
 * Generates a random salt, computes the salted hash, encrypts
 * the data + salt together, and returns all components needed
 * for a V1 submission.
 *
 * @param data - The plaintext data to encrypt
 * @returns V1 encryption result with hash, encrypted blob, and metadata
 */
export function encryptDataForSubmission(data: unknown): {
	data_hash: string
	encrypted_data: string
	encryption_key_id: string
} {
	if(!inputPublicKey) {
		throw new Error('Input encryption not configured - LCORE_PUBLIC_KEY not set')
	}

	// Generate 16-byte random salt
	const salt = nacl.randomBytes(16)

	// Compute salted hash
	const dataHash = computeDataHash(data, salt)

	// Encrypt data + salt together
	const plaintext = JSON.stringify({ data, salt: uint8ArrayToBase64(salt) })
	const plaintextBytes = new TextEncoder().encode(plaintext)

	// X25519 ECDH + XChaCha20-Poly1305 with ephemeral keypair
	const ephemeral = nacl.box.keyPair()
	const nonce = nacl.randomBytes(24)

	const sharedSecret = nacl.scalarMult(ephemeral.secretKey, inputPublicKey)
	const ciphertext = xchacha20poly1305(sharedSecret, nonce).encrypt(plaintextBytes)

	// Pack as a single base64 blob: nonce (24) + ephemeralPubKey (32) + ciphertext+tag
	const blob = new Uint8Array(nonce.length + ephemeral.publicKey.length + ciphertext.length)
	blob.set(nonce, 0)
	blob.set(ephemeral.publicKey, nonce.length)
	blob.set(ciphertext, nonce.length + ephemeral.publicKey.length)

	return {
		data_hash: dataHash,
		encrypted_data: uint8ArrayToBase64(blob),
		encryption_key_id: 'lcore_key_v1',
	}
}

/**
 * Decrypt a V1 packed blob (from encryptDataForSubmission).
 *
 * The blob format is: nonce (24 bytes) + ephemeralPubKey (32 bytes) + ciphertext
 * packed as a single base64 string.
 *
 * @param encryptedBlob - Base64-encoded packed blob
 * @returns Decrypted data and salt, or error
 */
export function decryptDataSubmission<T = unknown>(
	encryptedBlob: string
): DecryptionResult<{ data: T; salt: string }> | DecryptionError {
	if(!adminPrivateKey) {
		return {
			success: false,
			error: 'Decryption not configured - LCORE_PRIVATE_KEY not set',
		}
	}

	try {
		const blob = base64ToUint8Array(encryptedBlob)

		// Unpack: nonce (24) + ephemeralPubKey (32) + ciphertext (rest)
		const nonceLen = nacl.box.nonceLength // 24
		const pubKeyLen = nacl.box.publicKeyLength // 32
		const minLen = nonceLen + pubKeyLen + 1 // at least 1 byte ciphertext

		if(blob.length < minLen) {
			return {
				success: false,
				error: `Invalid blob length: expected at least ${minLen} bytes, got ${blob.length}`,
			}
		}

		const nonce = blob.slice(0, nonceLen)
		const ephemeralPublicKey = blob.slice(nonceLen, nonceLen + pubKeyLen)
		const ciphertext = blob.slice(nonceLen + pubKeyLen)

		// Try XChaCha20-Poly1305 first (current cipher), fall back to NaCl box (legacy)
		let decrypted: Uint8Array | null = null

		try {
			const sharedSecret = nacl.scalarMult(adminPrivateKey, ephemeralPublicKey)
			decrypted = xchacha20poly1305(sharedSecret, nonce).decrypt(ciphertext)
		} catch {
			// XChaCha20 failed, try legacy NaCl box
			decrypted = nacl.box.open(
				ciphertext,
				nonce,
				ephemeralPublicKey,
				adminPrivateKey
			)
		}

		if(!decrypted) {
			return {
				success: false,
				error: 'Decryption failed - invalid ciphertext or key mismatch',
			}
		}

		// Parse JSON — expects { data, salt }
		const plaintext = new TextDecoder().decode(decrypted)
		const parsed = JSON.parse(plaintext) as { data: T; salt: string }

		return {
			success: true,
			data: parsed,
		}
	} catch(e) {
		return {
			success: false,
			error: e instanceof Error ? e.message : String(e),
		}
	}
}

// ============= Re-encryption for Inspect Proxy =============

/**
 * Validate a base64-encoded NaCl public key (32 bytes).
 *
 * @param publicKeyBase64 - Base64-encoded public key to validate
 * @returns true if valid 32-byte NaCl public key
 */
export function validateNaClPublicKey(publicKeyBase64: string): boolean {
	try {
		const bytes = base64ToUint8Array(publicKeyBase64)
		return bytes.length === nacl.box.publicKeyLength
	} catch {
		return false
	}
}

/**
 * Re-encrypt data for a specific requester's public key.
 *
 * Used by the inspect proxy: decrypts V1 packed blobs with the admin
 * private key, then re-encrypts the plaintext for the requester using
 * NaCl box with an ephemeral keypair.
 *
 * @param encryptedBlob - Base64-encoded V1 packed blob
 * @param requesterPublicKeyBase64 - Requester's NaCl public key (base64)
 * @returns Re-encrypted packed blob (base64) or error
 */
export function reEncryptForRequester(
	encryptedBlob: string,
	requesterPublicKeyBase64: string
): { success: true; encrypted_data: string } | DecryptionError {
	// Decrypt with admin key
	const decrypted = decryptDataSubmission(encryptedBlob)
	if (!decrypted.success) {
		return decrypted
	}

	// Re-encrypt for requester using XChaCha20-Poly1305
	try {
		const requesterPubKey = base64ToUint8Array(requesterPublicKeyBase64)
		if (requesterPubKey.length !== 32) {
			return { success: false, error: 'Invalid requester public key length' }
		}

		const plaintext = JSON.stringify(decrypted.data)
		const plaintextBytes = new TextEncoder().encode(plaintext)

		const ephemeral = nacl.box.keyPair()
		const nonce = nacl.randomBytes(24)

		const sharedSecret = nacl.scalarMult(ephemeral.secretKey, requesterPubKey)
		const ciphertext = xchacha20poly1305(sharedSecret, nonce).encrypt(plaintextBytes)

		// Pack as blob: nonce (24) + ephemeralPubKey (32) + ciphertext+tag
		const blob = new Uint8Array(nonce.length + ephemeral.publicKey.length + ciphertext.length)
		blob.set(nonce, 0)
		blob.set(ephemeral.publicKey, nonce.length)
		blob.set(ciphertext, nonce.length + ephemeral.publicKey.length)

		return {
			success: true,
			encrypted_data: uint8ArrayToBase64(blob),
		}
	} catch (e) {
		return {
			success: false,
			error: e instanceof Error ? e.message : String(e),
		}
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
export function uint8ArrayToBase64(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString('base64')
}

/**
 * Convert a Base64 string to Uint8Array (exported for inspect proxy).
 */
export { base64ToUint8Array as decodeBase64 }
