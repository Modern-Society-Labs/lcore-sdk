/**
 * Authentication middleware for admin API routes
 *
 * Validates JWT tokens and enforces role-based access control.
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { verifyJWT, shouldRefreshToken, refreshJWT, hashSessionToken } from './jwt.ts'
import type { JWTPayload } from './jwt.ts'
import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import type { AdminRole } from '#src/db/types.ts'

/** Role hierarchy (higher index = more permissions) */
const ROLE_HIERARCHY: AdminRole[] = ['viewer', 'operator_manager', 'admin', 'super_admin']

export interface AuthenticatedRequest extends IncomingMessage {
	/** Authenticated admin info */
	admin: JWTPayload
	/** Whether the token should be refreshed */
	shouldRefreshToken: boolean
	/** Session ID for audit logging */
	sessionId?: string
}

export interface AuthMiddlewareOptions {
	/** Minimum required role */
	requiredRole?: AdminRole
	/** Specific permissions required (checked via API key permissions) */
	requiredPermissions?: string[]
	/** Allow API key authentication */
	allowApiKey?: boolean
}

/**
 * Extract bearer token from Authorization header
 */
function extractBearerToken(req: IncomingMessage): string | null {
	const authHeader = req.headers.authorization
	if(!authHeader?.startsWith('Bearer ')) {
		return null
	}

	return authHeader.slice(7)
}

/**
 * Extract API key from X-API-Key header
 */
function extractApiKey(req: IncomingMessage): string | null {
	const apiKey = req.headers['x-api-key']
	if(typeof apiKey !== 'string') {
		return null
	}

	return apiKey
}

/**
 * Check if a role meets the minimum required role
 */
export function hasRequiredRole(userRole: AdminRole, requiredRole: AdminRole): boolean {
	const userIndex = ROLE_HIERARCHY.indexOf(userRole)
	const requiredIndex = ROLE_HIERARCHY.indexOf(requiredRole)
	return userIndex >= requiredIndex
}

/**
 * Authenticate request using JWT token
 */
async function authenticateJWT(
	token: string,
	options: AuthMiddlewareOptions
): Promise<{ success: true; payload: JWTPayload } | { success: false; error: string; status: number }> {
	try {
		const payload = verifyJWT(token)

		// Check role if required
		if(options.requiredRole && !hasRequiredRole(payload.role, options.requiredRole)) {
			return {
				success: false,
				error: `Insufficient permissions. Required role: ${options.requiredRole}`,
				status: 403,
			}
		}

		// Optionally verify session still exists in database
		if(isDatabaseConfigured()) {
			const supabase = getSupabaseClient()
			const tokenHash = hashSessionToken(token)

			const { data: sessionData } = await supabase
				.from('admin_sessions')
				.select('id, revoked_at')
				.eq('token_hash', tokenHash)
				.single()

			const session = sessionData as { id: string; revoked_at: string | null } | null

			if(session?.revoked_at) {
				return { success: false, error: 'Session has been revoked', status: 401 }
			}
		}

		return { success: true, payload }
	} catch(err) {
		const message = err instanceof Error ? err.message : 'Authentication failed'
		return { success: false, error: message, status: 401 }
	}
}

/**
 * Authenticate request using API key
 */
async function authenticateApiKey(
	apiKey: string,
	options: AuthMiddlewareOptions
): Promise<{ success: true; payload: JWTPayload } | { success: false; error: string; status: number }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured', status: 500 }
	}

	const supabase = getSupabaseClient()

	// API keys are stored as: prefix (first 8 chars) + hash
	const prefix = apiKey.slice(0, 8)
	const keyHash = hashSessionToken(apiKey)

	const { data: keyData, error } = await supabase
		.from('api_keys')
		.select('id, admin_id, permissions, rate_limit_per_minute, expires_at, last_used_at')
		.eq('key_prefix', prefix)
		.eq('key_hash', keyHash)
		.single()

	const key = keyData as {
		id: string
		admin_id: string
		permissions: unknown
		rate_limit_per_minute: number
		expires_at: string | null
		last_used_at: string | null
	} | null

	if(error || !key) {
		return { success: false, error: 'Invalid API key', status: 401 }
	}

	// Check expiration
	if(key.expires_at && new Date(key.expires_at) < new Date()) {
		return { success: false, error: 'API key expired', status: 401 }
	}

	// Check permissions if required
	if(options.requiredPermissions?.length) {
		const keyPermissions = (key.permissions as string[]) || []
		const hasAllPermissions = options.requiredPermissions.every(
			p => keyPermissions.includes(p) || keyPermissions.includes('*')
		)
		if(!hasAllPermissions) {
			return {
				success: false,
				error: 'API key lacks required permissions',
				status: 403,
			}
		}
	}

	// Get admin info
	const { data: adminData } = await supabase
		.from('admins')
		.select('id, wallet_address, display_name, role')
		.eq('id', key.admin_id)
		.single()

	const admin = adminData as {
		id: string
		wallet_address: string
		display_name: string | null
		role: AdminRole
	} | null

	if(!admin) {
		return { success: false, error: 'Admin not found', status: 401 }
	}

	// Check role if required
	if(options.requiredRole && !hasRequiredRole(admin.role, options.requiredRole)) {
		return {
			success: false,
			error: `Insufficient permissions. Required role: ${options.requiredRole}`,
			status: 403,
		}
	}

	// Update last used timestamp (fire and forget)
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	;(supabase.from('api_keys') as any)
		.update({ last_used_at: new Date().toISOString() })
		.eq('id', key.id)
		.then(() => { /* ignore result */ })

	// Create payload from admin data
	const payload: JWTPayload = {
		sub: admin.id,
		wallet: admin.wallet_address.toLowerCase(),
		role: admin.role,
		name: admin.display_name || undefined,
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600, // API keys don't expire per-request
	}

	return { success: true, payload }
}

/**
 * Authentication middleware factory
 */
export function createAuthMiddleware(options: AuthMiddlewareOptions = {}) {
	return async(
		req: IncomingMessage,
		res: ServerResponse
	): Promise<AuthenticatedRequest | null> => {
		// Try JWT authentication first
		const bearerToken = extractBearerToken(req)
		if(bearerToken) {
			const result = await authenticateJWT(bearerToken, options)
			if(result.success) {
				const authReq = req as AuthenticatedRequest
				authReq.admin = result.payload
				authReq.shouldRefreshToken = shouldRefreshToken(result.payload)
				return authReq
			}

			sendError(res, result.status, result.error)
			return null
		}

		// Try API key authentication if allowed
		if(options.allowApiKey) {
			const apiKey = extractApiKey(req)
			if(apiKey) {
				const result = await authenticateApiKey(apiKey, options)
				if(result.success) {
					const authReq = req as AuthenticatedRequest
					authReq.admin = result.payload
					authReq.shouldRefreshToken = false // API keys don't need refresh
					return authReq
				}

				sendError(res, result.status, result.error)
				return null
			}
		}

		sendError(res, 401, 'Authentication required')
		return null
	}
}

/**
 * Send JSON error response
 */
function sendError(res: ServerResponse, status: number, message: string): void {
	res.writeHead(status, { 'Content-Type': 'application/json' })
	res.end(JSON.stringify({ error: message }))
}

/**
 * Create middleware for specific roles
 */
export const requireSuperAdmin = createAuthMiddleware({ requiredRole: 'super_admin' })
export const requireAdmin = createAuthMiddleware({ requiredRole: 'admin' })
export const requireOperatorManager = createAuthMiddleware({ requiredRole: 'operator_manager' })
export const requireViewer = createAuthMiddleware({ requiredRole: 'viewer' })

/**
 * Create middleware that allows API key authentication
 */
export const requireAuthWithApiKey = createAuthMiddleware({ allowApiKey: true })
