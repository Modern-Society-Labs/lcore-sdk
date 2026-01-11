/**
 * Wallet-based authentication for admin users
 *
 * Uses EIP-191 message signing to verify wallet ownership.
 * Similar pattern to existing auth in src/utils/auth.ts but adapted for admin sessions.
 */

import { utils } from 'ethers'
import { randomBytes } from 'crypto'

/** Nonce validity in milliseconds (5 minutes) */
const NONCE_VALIDITY_MS = 5 * 60 * 1000

/** In-memory nonce store (should be Redis in production for multi-node) */
const nonceStore = new Map<string, { nonce: string; expiresAt: number }>()

/**
 * Message template for wallet signature
 * Following EIP-4361 (Sign-In with Ethereum) simplified format
 */
function createSignMessage(params: {
	domain: string
	address: string
	nonce: string
	issuedAt: string
	expiresAt: string
}): string {
	return `Locale L{CORE} Admin Authentication

Domain: ${params.domain}
Address: ${params.address}
Nonce: ${params.nonce}
Issued At: ${params.issuedAt}
Expires At: ${params.expiresAt}

Sign this message to authenticate as an admin.
This signature will not trigger any blockchain transaction.`
}

/**
 * Generate a nonce for wallet authentication
 */
export function generateNonce(walletAddress: string): {
	nonce: string
	expiresAt: Date
} {
	const address = walletAddress.toLowerCase()
	const nonce = randomBytes(32).toString('hex')
	const expiresAt = Date.now() + NONCE_VALIDITY_MS

	// Store nonce (overwrite any existing for this address)
	nonceStore.set(address, { nonce, expiresAt })

	// Clean up expired nonces periodically
	cleanupExpiredNonces()

	return { nonce, expiresAt: new Date(expiresAt) }
}

/**
 * Verify a wallet signature and consume the nonce
 */
export async function verifyWalletSignature(params: {
	walletAddress: string
	signature: string
	domain: string
}): Promise<{ success: boolean; error?: string }> {
	const address = params.walletAddress.toLowerCase()

	// Get stored nonce
	const stored = nonceStore.get(address)
	if(!stored) {
		return { success: false, error: 'No authentication request found. Please request a new nonce.' }
	}

	// Check expiration
	if(Date.now() > stored.expiresAt) {
		nonceStore.delete(address)
		return { success: false, error: 'Authentication request expired. Please request a new nonce.' }
	}

	// Reconstruct the message that was signed
	const issuedAt = new Date(stored.expiresAt - NONCE_VALIDITY_MS).toISOString()
	const expiresAt = new Date(stored.expiresAt).toISOString()

	const message = createSignMessage({
		domain: params.domain,
		address: params.walletAddress,
		nonce: stored.nonce,
		issuedAt,
		expiresAt,
	})

	try {
		// Recover the signer address from the signature
		const recoveredAddress = utils.verifyMessage(message, params.signature)

		// Compare addresses (case-insensitive)
		if(recoveredAddress.toLowerCase() !== address) {
			return { success: false, error: 'Signature verification failed. Address mismatch.' }
		}

		// Consume the nonce (one-time use)
		nonceStore.delete(address)

		return { success: true }
	} catch(err) {
		return { success: false, error: 'Invalid signature format.' }
	}
}

/**
 * Get the message to be signed by the wallet
 */
export function getSignMessage(params: {
	walletAddress: string
	domain: string
}): { message: string; expiresAt: Date } | null {
	const address = params.walletAddress.toLowerCase()
	const stored = nonceStore.get(address)

	if(!stored || Date.now() > stored.expiresAt) {
		return null
	}

	const issuedAt = new Date(stored.expiresAt - NONCE_VALIDITY_MS).toISOString()
	const expiresAt = new Date(stored.expiresAt).toISOString()

	const message = createSignMessage({
		domain: params.domain,
		address: params.walletAddress,
		nonce: stored.nonce,
		issuedAt,
		expiresAt,
	})

	return { message, expiresAt: new Date(stored.expiresAt) }
}

/**
 * Clean up expired nonces
 */
function cleanupExpiredNonces(): void {
	const now = Date.now()
	for(const [address, data] of nonceStore.entries()) {
		if(now > data.expiresAt) {
			nonceStore.delete(address)
		}
	}
}

/**
 * Validate Ethereum address format
 */
export function isValidAddress(address: string): boolean {
	return /^0x[a-fA-F0-9]{40}$/.test(address)
}

/**
 * Normalize address to checksum format
 */
export function normalizeAddress(address: string): string {
	return utils.getAddress(address)
}
