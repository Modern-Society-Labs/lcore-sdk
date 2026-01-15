/**
 * Authentication API routes
 *
 * POST /api/auth/nonce    - Request nonce for wallet signature
 * POST /api/auth/login    - Login with wallet signature
 * POST /api/auth/logout   - Logout current session
 * GET  /api/auth/me       - Get current admin info
 * POST /api/auth/refresh  - Refresh session token
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { getClientInfo, parseJsonBody, sendError, sendJson } from 'src/api/utils/http.ts'

import type { AuthenticatedRequest } from '#src/api/auth/index.ts'
import {
	auditFromRequest,
	createAuthMiddleware,
	getAdminById,
	hashSessionToken,
	loginWithWallet,
	refreshJWT,
	requestLoginNonce,
	revokeSession,
} from '#src/api/auth/index.ts'
import { checkRateLimit, getRateLimitHeaders, resetRateLimit } from '#src/api/auth/rate-limit.ts'

/**
 * POST /api/auth/nonce
 * Request a nonce for wallet-based login
 */
export async function handleNonceRequest(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const body = await parseJsonBody<{ walletAddress: string }>(req)

	if(!body?.walletAddress) {
		return sendError(res, 400, 'walletAddress is required')
	}

	// Get domain from request headers
	const host = req.headers.host || 'localhost'
	const protocol = req.headers['x-forwarded-proto'] || 'http'
	const domain = `${protocol}://${host}`

	const result = await requestLoginNonce(body.walletAddress, domain)

	if('error' in result) {
		return sendError(res, 400, result.error)
	}

	sendJson(res, {
		nonce: result.nonce,
		message: result.message,
		expiresAt: result.expiresAt.toISOString(),
	})
}

/**
 * POST /api/auth/login
 * Login with wallet signature
 */
export async function handleLogin(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const { ipAddress, userAgent } = getClientInfo(req)

	// Rate limit by IP address to prevent brute force attacks
	const rateLimitId = `login:${ipAddress || 'unknown'}`
	const rateLimit = checkRateLimit(rateLimitId, 5, 15 * 60 * 1000) // 5 attempts per 15 minutes

	// Add rate limit headers to response
	const rateLimitHeaders = getRateLimitHeaders(rateLimit)
	for(const [key, value] of Object.entries(rateLimitHeaders)) {
		res.setHeader(key, value)
	}

	if(!rateLimit.allowed) {
		res.setHeader('Retry-After', String(Math.ceil((rateLimit.resetAt.getTime() - Date.now()) / 1000)))
		return sendError(res, 429, 'Too many login attempts. Please try again later.')
	}

	const body = await parseJsonBody<{
		walletAddress: string
		signature: string
	}>(req)

	if(!body?.walletAddress || !body?.signature) {
		return sendError(res, 400, 'walletAddress and signature are required')
	}

	// Get domain from request headers
	const host = req.headers.host || 'localhost'
	const protocol = req.headers['x-forwarded-proto'] || 'http'
	const domain = `${protocol}://${host}`

	const result = await loginWithWallet({
		walletAddress: body.walletAddress,
		signature: body.signature,
		domain,
		ipAddress,
		userAgent,
	})

	if(!result.success) {
		return sendError(res, 401, result.error || 'Login failed')
	}

	// Reset rate limit on successful login
	resetRateLimit(rateLimitId)

	// Log the login
	if(result.admin && result.session) {
		await auditFromRequest(
			{
				sub: result.admin.id,
				wallet: result.admin.walletAddress,
				role: result.admin.role,
				iat: 0,
				exp: 0,
			},
			'admin.login',
			{ ipAddress, userAgent }
		)
	}

	sendJson(res, {
		admin: result.admin,
		token: result.session?.token,
		expiresAt: result.session?.expiresAt.toISOString(),
	})
}

/**
 * POST /api/auth/logout
 * Logout current session
 */
export async function handleLogout(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const auth = createAuthMiddleware()
	const authReq = await auth(req, res)
	if(!authReq) {
		return
	}

	// Get the token from Authorization header
	const authHeader = req.headers.authorization
	if(authHeader?.startsWith('Bearer ')) {
		const token = authHeader.slice(7)
		const tokenHash = hashSessionToken(token)
		await revokeSession(tokenHash)
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'admin.logout', { ipAddress, userAgent })

	sendJson(res, { success: true })
}

/**
 * GET /api/auth/me
 * Get current admin info
 */
export async function handleGetMe(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const auth = createAuthMiddleware()
	const authReq = await auth(req, res)
	if(!authReq) {
		return
	}

	const admin = await getAdminById(authReq.admin.sub)
	if(!admin) {
		return sendError(res, 404, 'Admin not found')
	}

	sendJson(res, {
		admin,
		shouldRefreshToken: authReq.shouldRefreshToken,
	})
}

/**
 * POST /api/auth/refresh
 * Refresh session token with atomic locking to prevent race conditions
 */
export async function handleRefresh(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const auth = createAuthMiddleware()
	const authReq = await auth(req, res)
	if(!authReq) {
		return
	}

	// Get the current token to find the session
	const authHeader = req.headers.authorization
	if(!authHeader?.startsWith('Bearer ')) {
		return sendError(res, 401, 'No token provided')
	}

	const currentToken = authHeader.slice(7)
	const currentTokenHash = hashSessionToken(currentToken)

	// Try to acquire refresh lock atomically
	// Only proceed if last_refresh_at is null (not currently being refreshed)
	const { ipAddress, userAgent } = getClientInfo(req)

	// Import Supabase client
	const { getSupabaseClient, isDatabaseConfigured } = await import('#src/db/client.ts')

	if(isDatabaseConfigured()) {
		const supabase = getSupabaseClient()

		// Atomic update to acquire lock - only succeeds if not already refreshing
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const { data: lockResult, error: lockError } = await (supabase.from('admin_sessions') as any)
			.update({ last_refresh_at: new Date().toISOString() })
			.eq('token_hash', currentTokenHash)
			.is('last_refresh_at', null)
			.select('id')
			.single()

		if(lockError || !lockResult) {
			// Another refresh is in progress or session not found
			// Return success with a message to retry
			return sendError(res, 409, 'Token refresh already in progress. Please retry.')
		}

		// Create new token
		const newSession = refreshJWT(authReq.admin)
		const newTokenHash = hashSessionToken(newSession.token)

		// Create new session record
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await (supabase.from('admin_sessions') as any)
			.insert({
				admin_id: authReq.admin.sub,
				token_hash: newTokenHash,
				hash_version: 1,
				ip_address: ipAddress,
				user_agent: userAgent,
				expires_at: newSession.expiresAt.toISOString(),
			})

		// Revoke old session
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await (supabase.from('admin_sessions') as any)
			.update({ revoked_at: new Date().toISOString() })
			.eq('token_hash', currentTokenHash)

		sendJson(res, {
			token: newSession.token,
			expiresAt: newSession.expiresAt.toISOString(),
		})
	} else {
		// No database - just create new token (stateless mode)
		const newSession = refreshJWT(authReq.admin)

		sendJson(res, {
			token: newSession.token,
			expiresAt: newSession.expiresAt.toISOString(),
		})
	}
}

/**
 * Route handler for /api/auth/*
 */
export async function handleAuthRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	if(path === '/api/auth/nonce' && method === 'POST') {
		await handleNonceRequest(req, res)
		return true
	}

	if(path === '/api/auth/login' && method === 'POST') {
		await handleLogin(req, res)
		return true
	}

	if(path === '/api/auth/logout' && method === 'POST') {
		await handleLogout(req, res)
		return true
	}

	if(path === '/api/auth/me' && method === 'GET') {
		await handleGetMe(req, res)
		return true
	}

	if(path === '/api/auth/refresh' && method === 'POST') {
		await handleRefresh(req, res)
		return true
	}

	return false
}
