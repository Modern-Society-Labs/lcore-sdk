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
import {
	requestLoginNonce,
	loginWithWallet,
	getAdminById,
	revokeSession,
	refreshJWT,
	hashSessionToken,
	auditFromRequest,
	createAuthMiddleware,
} from '#src/api/auth/index.ts'
import type { AuthenticatedRequest } from '#src/api/auth/index.ts'
import { parseJsonBody, sendJson, sendError, getClientInfo } from '../utils/http.ts'

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

	const { ipAddress, userAgent } = getClientInfo(req)

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
 * Refresh session token
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

	// Create new token
	const newSession = refreshJWT(authReq.admin)

	sendJson(res, {
		token: newSession.token,
		expiresAt: newSession.expiresAt.toISOString(),
	})
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
