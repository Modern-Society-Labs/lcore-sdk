/**
 * DID Key utilities for device identity verification
 *
 * Supports did:key method with secp256k1 keys for IoT device attestation.
 * Devices sign their sensor data with a private key, and this service
 * verifies the JWS signature using the public key derived from the did:key.
 */

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { base58btc } from 'multiformats/bases/base58'

/**
 * Parse a did:key identifier and extract the raw public key bytes
 *
 * did:key format: did:key:z<multibase-encoded-multicodec-pubkey>
 * For secp256k1: multicodec prefix is 0xe7 0x01
 *
 * @param did - The did:key identifier (e.g., "did:key:zQ3sh...")
 * @returns The raw public key bytes, or null if invalid
 */
export function parseDIDKey(did: string): Uint8Array | null {
	if (!did.startsWith('did:key:z')) {
		return null
	}

	try {
		const multibaseKey = did.replace('did:key:', '')
		const decoded = base58btc.decode(multibaseKey)

		// Check for secp256k1-pub multicodec prefix (0xe7 0x01)
		if (decoded.length < 35 || decoded[0] !== 0xe7 || decoded[1] !== 0x01) {
			return null
		}

		// Return the public key bytes (skip 2-byte multicodec prefix)
		return decoded.slice(2)
	} catch {
		return null
	}
}

/**
 * Generate a did:key from a secp256k1 public key
 *
 * @param publicKey - The raw secp256k1 public key bytes (33 bytes compressed)
 * @returns The did:key identifier
 */
export function publicKeyToDIDKey(publicKey: Uint8Array): string {
	// Prepend secp256k1-pub multicodec prefix
	const prefixed = new Uint8Array(2 + publicKey.length)
	prefixed[0] = 0xe7
	prefixed[1] = 0x01
	prefixed.set(publicKey, 2)

	// Encode with base58btc (multibase 'z' prefix)
	return `did:key:${base58btc.encode(prefixed)}`
}

/**
 * Verify a JWS (JSON Web Signature) compact serialization
 *
 * JWS format: <header>.<payload>.<signature>
 * The signature is over the message: <header>.<payload>
 *
 * @param jws - The JWS compact serialization
 * @param payload - The expected payload object (must match what was signed)
 * @param pubkey - The secp256k1 public key to verify against
 * @returns True if signature is valid
 */
export function verifyJWS(
	jws: string,
	payload: Record<string, unknown>,
	pubkey: Uint8Array
): boolean {
	try {
		const parts = jws.split('.')
		if (parts.length !== 3) {
			return false
		}

		const [headerB64, payloadB64, sigB64] = parts

		// Reconstruct the signing input
		// For device submissions, we verify the payload matches
		const expectedPayloadB64 = base64urlEncode(JSON.stringify(payload))
		if (payloadB64 !== expectedPayloadB64) {
			return false
		}

		const message = `${headerB64}.${payloadB64}`
		const signature = base64urlDecode(sigB64)

		// Hash the message and verify signature
		const msgHash = sha256(new TextEncoder().encode(message))

		return secp256k1.verify(signature, msgHash, pubkey)
	} catch {
		return false
	}
}

/**
 * Create a JWS signature over a payload
 *
 * @param payload - The payload to sign
 * @param privateKey - The secp256k1 private key (32 bytes)
 * @returns The JWS compact serialization
 */
export function createJWS(
	payload: Record<string, unknown>,
	privateKey: Uint8Array
): string {
	const header = { alg: 'ES256K', typ: 'JWT' }
	const headerB64 = base64urlEncode(JSON.stringify(header))
	const payloadB64 = base64urlEncode(JSON.stringify(payload))

	const message = `${headerB64}.${payloadB64}`
	const msgHash = sha256(new TextEncoder().encode(message))

	const signature = secp256k1.sign(msgHash, privateKey)
	const sigBytes = signature.toCompactRawBytes()
	const sigB64 = base64urlEncodeBytes(sigBytes)

	return `${headerB64}.${payloadB64}.${sigB64}`
}

// Base64url encoding/decoding utilities

function base64urlDecode(str: string): Uint8Array {
	// Convert base64url to base64
	const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
	// Add padding if needed
	const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
	const binary = atob(padded)
	return Uint8Array.from(binary, c => c.charCodeAt(0))
}

function base64urlEncode(str: string): string {
	const bytes = new TextEncoder().encode(str)
	const binary = String.fromCharCode(...bytes)
	return btoa(binary)
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '')
}

function base64urlEncodeBytes(bytes: Uint8Array): string {
	const binary = String.fromCharCode(...bytes)
	return btoa(binary)
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=/g, '')
}
