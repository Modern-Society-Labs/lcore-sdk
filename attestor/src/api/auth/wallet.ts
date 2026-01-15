/**
 * Wallet-based authentication for admin users
 *
 * Uses EIP-191 message signing to verify wallet ownership.
 * Similar pattern to existing auth in src/utils/auth.ts but adapted for admin sessions.
 *
 * Nonces are stored in Supabase for multi-node deployment support.
 */

import { randomBytes } from 'crypto'
import { utils } from 'ethers'

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/client.ts'
import { logger as LOGGER } from '#src/utils/index.ts'

/** Nonce validity in milliseconds (5 minutes) */
const NONCE_VALIDITY_MS = 5 * 60 * 1000

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
 * Stores nonce in Supabase for multi-node safe operation
 */
export async function generateNonce(walletAddress: string): Promise<{
	nonce: string
	expiresAt: Date
}> {
	const address = walletAddress.toLowerCase()
	const nonce = randomBytes(32).toString('hex')
	const expiresAt = new Date(Date.now() + NONCE_VALIDITY_MS)

	if(!isDatabaseConfigured()) {
		throw new Error('Database not configured. Cannot generate authentication nonce.')
	}

	const supabase = getSupabaseClient()

	// Upsert nonce (overwrite any existing for this address)
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('auth_nonces') as any)
		.upsert({
			wallet_address: address,
			nonce,
			expires_at: expiresAt.toISOString(),
		}, {
			onConflict: 'wallet_address',
		})

	if(error) {
		LOGGER.error({ error, walletAddress: address }, 'Failed to store auth nonce')
		throw new Error('Failed to generate authentication nonce')
	}

	// Clean up expired nonces periodically (async, don't await)
	cleanupExpiredNonces().catch(err => {
		LOGGER.warn({ err }, 'Failed to cleanup expired nonces')
	})

	return { nonce, expiresAt }
}

/**
 * Verify a wallet signature and consume the nonce
 */
export async function verifyWalletSignature(params: {
	walletAddress: string
	signature: string
	domain: string
}): Promise<{ success: boolean, error?: string }> {
	const address = params.walletAddress.toLowerCase()

	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured.' }
	}

	const supabase = getSupabaseClient()

	// Get stored nonce
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { data: stored, error: fetchError } = await (supabase.from('auth_nonces') as any)
		.select('nonce, expires_at')
		.eq('wallet_address', address)
		.single() as { data: { nonce: string, expires_at: string } | null, error: unknown }

	if(fetchError || !stored) {
		LOGGER.warn({ walletAddress: address, error: 'Nonce not found' }, 'Auth failure')
		return { success: false, error: 'No authentication request found. Please request a new nonce.' }
	}

	// Check expiration
	const expiresAt = new Date(stored.expires_at).getTime()
	if(Date.now() > expiresAt) {
		// Delete expired nonce
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await (supabase.from('auth_nonces') as any)
			.delete()
			.eq('wallet_address', address)

		LOGGER.warn({ walletAddress: address, error: 'Nonce expired' }, 'Auth failure')
		return { success: false, error: 'Authentication request expired. Please request a new nonce.' }
	}

	// Reconstruct the message that was signed
	const issuedAt = new Date(expiresAt - NONCE_VALIDITY_MS).toISOString()
	const expiresAtStr = new Date(expiresAt).toISOString()

	const message = createSignMessage({
		domain: params.domain,
		address: params.walletAddress,
		nonce: stored.nonce,
		issuedAt,
		expiresAt: expiresAtStr,
	})

	try {
		// Recover the signer address from the signature
		const recoveredAddress = utils.verifyMessage(message, params.signature)

		// Compare addresses (case-insensitive)
		if(recoveredAddress.toLowerCase() !== address) {
			LOGGER.warn({ walletAddress: address, error: 'Address mismatch' }, 'Auth failure')
			return { success: false, error: 'Signature verification failed. Address mismatch.' }
		}

		// Consume the nonce (one-time use)
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const { error: deleteError } = await (supabase.from('auth_nonces') as any)
			.delete()
			.eq('wallet_address', address)

		if(deleteError) {
			LOGGER.warn({ error: deleteError, walletAddress: address }, 'Failed to delete consumed nonce')
		}

		return { success: true }
	} catch(err) {
		LOGGER.warn({ walletAddress: address, error: 'Invalid signature format' }, 'Auth failure')
		return { success: false, error: 'Invalid signature format.' }
	}
}

/**
 * Get the message to be signed by the wallet
 */
export async function getSignMessage(params: {
	walletAddress: string
	domain: string
}): Promise<{ message: string, expiresAt: Date } | null> {
	const address = params.walletAddress.toLowerCase()

	if(!isDatabaseConfigured()) {
		return null
	}

	const supabase = getSupabaseClient()

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { data: stored, error } = await (supabase.from('auth_nonces') as any)
		.select('nonce, expires_at')
		.eq('wallet_address', address)
		.single() as { data: { nonce: string, expires_at: string } | null, error: unknown }

	if(error || !stored) {
		return null
	}

	const expiresAt = new Date(stored.expires_at).getTime()
	if(Date.now() > expiresAt) {
		return null
	}

	const issuedAt = new Date(expiresAt - NONCE_VALIDITY_MS).toISOString()
	const expiresAtStr = new Date(expiresAt).toISOString()

	const message = createSignMessage({
		domain: params.domain,
		address: params.walletAddress,
		nonce: stored.nonce,
		issuedAt,
		expiresAt: expiresAtStr,
	})

	return { message, expiresAt: new Date(expiresAt) }
}

/**
 * Clean up expired nonces from Supabase
 */
async function cleanupExpiredNonces(): Promise<void> {
	if(!isDatabaseConfigured()) {
		return
	}

	const supabase = getSupabaseClient()

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('auth_nonces') as any)
		.delete()
		.lt('expires_at', new Date().toISOString())

	if(error) {
		LOGGER.warn({ error }, 'Failed to cleanup expired nonces')
	}
}

/**
 * Validate Ethereum address format
 * Uses checksum validation when address contains mixed case
 */
export function isValidAddress(address: string): boolean {
	if(!/^0x[a-fA-F0-9]{40}$/.test(address)) {
		return false
	}

	try {
		// This will throw if the checksum is invalid for mixed-case addresses
		normalizeAddress(address)
		return true
	} catch{
		return false
	}
}

/**
 * Normalize address to checksum format
 */
export function normalizeAddress(address: string): string {
	return utils.getAddress(address)
}
