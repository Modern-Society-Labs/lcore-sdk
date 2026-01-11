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
	role: 'super_admin' | 'admin' | 'operator_manager' | 'viewer'
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

/**
 * Get JWT secret from environment
 */
function getJWTSecret(): string {
	const secret = getEnvVariable('JWT_SECRET')
	if(!secret || secret.length < 32) {
		throw new Error('JWT_SECRET must be at least 32 characters')
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
 */
export function hashSessionToken(token: string): string {
	const hash = createHmac('sha256', getJWTSecret())
	hash.update(token)
	return hash.digest('hex')
}
