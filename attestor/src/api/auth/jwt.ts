/**
 * JWT utilities for admin authentication
 *
 * Uses wallet signature for initial auth, then issues JWT session tokens
 * for subsequent requests.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'crypto'

import { getEnvVariable } from '#src/utils/env.ts'

const JWT_ALGORITHM = 'HS256'
const SESSION_EXPIRY_HOURS = 24
const REFRESH_THRESHOLD_HOURS = 6 // Refresh if less than 6 hours remaining

export interface JWTPayload {
	/** Admin UUID from database */
	sub: string
	/** Wallet address (lowercase) */
	wallet: string
	/** Admin role */
	role: 'super_admin' | 'admin' | 'viewer'
	/** Display name */
	name?: string
	/** Issued at (unix timestamp) */
	iat: number
	/** Expires at (unix timestamp) */
	exp: number
}

export interface SessionToken {
	token: string
	expiresAt: Date
	shouldRefresh: boolean
}

/**
 * Base64URL encode (JWT-compatible)
 */
function base64UrlEncode(data: string | Buffer): string {
	const base64 = Buffer.isBuffer(data)
		? data.toString('base64')
		: Buffer.from(data).toString('base64')
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Base64URL decode
 */
function base64UrlDecode(str: string): string {
	const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
	const padding = '='.repeat((4 - (base64.length % 4)) % 4)
	return Buffer.from(base64 + padding, 'base64').toString('utf8')
}

/** Flag to track if entropy warning has been shown */
let entropyWarningShown = false

/**
 * Get JWT secret from environment
 */
function getJWTSecret(): string {
	const secret = getEnvVariable('JWT_SECRET')
	if(!secret || secret.length < 32) {
		throw new Error('JWT_SECRET must be at least 32 characters')
	}

	// Entropy warning (don't break existing deployments, just warn once)
	if(!entropyWarningShown) {
		const uniqueChars = new Set(secret).size
		if(uniqueChars < 16) {
			console.warn('[SECURITY] JWT_SECRET has low entropy (%d unique characters). Consider using a stronger secret with more character variety.', uniqueChars)
		}

		entropyWarningShown = true
	}

	return secret
}

/**
 * Create HMAC signature for JWT
 */
function createSignature(input: string): string {
	const secret = getJWTSecret()
	const hmac = createHmac('sha256', secret)
	hmac.update(input)
	return base64UrlEncode(hmac.digest())
}

/**
 * Create a JWT token for an authenticated admin
 */
export function createJWT(payload: Omit<JWTPayload, 'iat' | 'exp'>): SessionToken {
	const now = Math.floor(Date.now() / 1000)
	const expiresAt = now + SESSION_EXPIRY_HOURS * 60 * 60

	const fullPayload: JWTPayload = {
		...payload,
		iat: now,
		exp: expiresAt,
	}

	const header = { alg: JWT_ALGORITHM, typ: 'JWT' }
	const headerB64 = base64UrlEncode(JSON.stringify(header))
	const payloadB64 = base64UrlEncode(JSON.stringify(fullPayload))
	const signature = createSignature(`${headerB64}.${payloadB64}`)

	const token = `${headerB64}.${payloadB64}.${signature}`
	const expiresAtDate = new Date(expiresAt * 1000)

	// Check if token should be refreshed (less than threshold remaining)
	const remainingHours = (expiresAt - now) / 3600
	const shouldRefresh = remainingHours < REFRESH_THRESHOLD_HOURS

	return { token, expiresAt: expiresAtDate, shouldRefresh }
}

/**
 * Verify and decode a JWT token
 */
export function verifyJWT(token: string): JWTPayload {
	const parts = token.split('.')
	if(parts.length !== 3) {
		throw new Error('Invalid token format')
	}

	const [headerB64, payloadB64, signatureB64] = parts

	// Verify signature
	const expectedSignature = createSignature(`${headerB64}.${payloadB64}`)

	// Use timing-safe comparison to prevent timing attacks
	const expectedBuf = Buffer.from(expectedSignature)
	const actualBuf = Buffer.from(signatureB64)

	if(expectedBuf.length !== actualBuf.length ||
		!timingSafeEqual(expectedBuf, actualBuf)) {
		throw new Error('Invalid token signature')
	}

	// Decode payload
	const payload: JWTPayload = JSON.parse(base64UrlDecode(payloadB64))

	// Check expiration
	const now = Math.floor(Date.now() / 1000)
	if(payload.exp < now) {
		throw new Error('Token expired')
	}

	return payload
}

/**
 * Check if a token should be refreshed
 */
export function shouldRefreshToken(payload: JWTPayload): boolean {
	const now = Math.floor(Date.now() / 1000)
	const remainingHours = (payload.exp - now) / 3600
	return remainingHours < REFRESH_THRESHOLD_HOURS
}

/**
 * Refresh a token (creates new token with same payload but new expiry)
 */
export function refreshJWT(payload: JWTPayload): SessionToken {
	return createJWT({
		sub: payload.sub,
		wallet: payload.wallet,
		role: payload.role,
		name: payload.name,
	})
}

/**
 * Generate a secure random session ID
 */
export function generateSessionId(): string {
	return randomBytes(32).toString('hex')
}

/**
 * Hash a session token for storage (don't store raw tokens)
 * This is v1 (HMAC-SHA256) - kept for backwards compatibility
 */
export function hashSessionToken(token: string): string {
	const hash = createHmac('sha256', getJWTSecret())
	hash.update(token)
	return hash.digest('hex')
}

/**
 * Hash version constants
 */
export const HASH_VERSION = {
	HMAC_SHA256: 1,
	BCRYPT: 2,
} as const

/** Bcrypt interface for dynamic import */
interface BcryptModule {
	hash: (data: string, rounds: number) => Promise<string>
	compare: (data: string, encrypted: string) => Promise<boolean>
}

/** Cached bcrypt module (null = not checked yet, undefined = not available) */
let bcryptModule: BcryptModule | undefined | null = null

/**
 * Try to load bcrypt module
 */
async function tryLoadBcrypt(): Promise<BcryptModule | undefined> {
	if(bcryptModule === null) {
		try {
			// Dynamic import - bcrypt is an optional dependency
			// Use string variable to prevent TypeScript from resolving the module at compile time
			const moduleName = 'bcrypt'
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			bcryptModule = await import(/* webpackIgnore: true */ moduleName) as BcryptModule
		} catch{
			bcryptModule = undefined
		}
	}

	return bcryptModule
}

/**
 * Hash a session token using v2 (bcrypt) for new sessions.
 * Provides better security with per-hash salt.
 *
 * Note: Requires bcrypt package to be installed:
 * npm install bcrypt @types/bcrypt
 *
 * Until bcrypt is installed, this falls back to v1 hash with a warning.
 */
export async function hashSessionTokenV2(token: string): Promise<{ hash: string, version: number }> {
	const bcrypt = await tryLoadBcrypt()
	if(bcrypt) {
		const hash = await bcrypt.hash(token, 12)
		return { hash, version: HASH_VERSION.BCRYPT }
	}

	// Fallback to v1 if bcrypt not installed
	console.warn('[SECURITY] bcrypt not available, using HMAC-SHA256 for token hash. Install bcrypt for better security.')
	return { hash: hashSessionToken(token), version: HASH_VERSION.HMAC_SHA256 }
}

/**
 * Verify a session token against a stored hash.
 * Supports both v1 (HMAC-SHA256) and v2 (bcrypt) hashes.
 *
 * @param token - The raw session token to verify
 * @param storedHash - The hash stored in the database
 * @param hashVersion - The hash version (1 = HMAC-SHA256, 2 = bcrypt)
 * @returns true if the token matches the hash
 */
export async function verifySessionTokenHash(
	token: string,
	storedHash: string,
	hashVersion: number
): Promise<boolean> {
	if(hashVersion === HASH_VERSION.BCRYPT) {
		const bcrypt = await tryLoadBcrypt()
		if(bcrypt) {
			return bcrypt.compare(token, storedHash)
		}

		// bcrypt not available, can't verify v2 hash
		return false
	}

	// v1: HMAC-SHA256 comparison
	const computedHash = hashSessionToken(token)

	// Use timing-safe comparison
	const expectedBuf = Buffer.from(storedHash)
	const actualBuf = Buffer.from(computedHash)

	if(expectedBuf.length !== actualBuf.length) {
		return false
	}

	return timingSafeEqual(expectedBuf, actualBuf)
}
