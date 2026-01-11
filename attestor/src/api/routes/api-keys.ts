/**
 * API key management routes
 *
 * GET    /api/api-keys       - List my API keys
 * POST   /api/api-keys       - Create new API key
 * DELETE /api/api-keys/:id   - Revoke API key
 * PUT    /api/api-keys/:id   - Update API key permissions
 */

import type { IncomingMessage, ServerResponse } from 'http'
import {
	createApiKey,
	listApiKeys,
	revokeApiKey,
	updateApiKeyPermissions,
	API_KEY_PERMISSIONS,
	createAuthMiddleware,
	auditFromRequest,
} from '#src/api/auth/index.ts'
import { parseJsonBody, sendJson, sendError, getClientInfo } from '../utils/http.ts'

const auth = createAuthMiddleware()

/**
 * GET /api/api-keys
 * List current user's API keys
 */
export async function handleListApiKeys(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const keys = await listApiKeys(authReq.admin.sub)
	sendJson(res, {
		keys,
		availablePermissions: API_KEY_PERMISSIONS,
	})
}

/**
 * POST /api/api-keys
 * Create new API key
 */
export async function handleCreateApiKey(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const body = await parseJsonBody<{
		name: string
		permissions?: string[]
		rateLimitPerMinute?: number
		expiresInDays?: number
	}>(req)

	if(!body?.name) {
		return sendError(res, 400, 'name is required')
	}

	// Validate permissions
	const validPermissions = Object.keys(API_KEY_PERMISSIONS)
	if(body.permissions) {
		const invalid = body.permissions.filter(p => !validPermissions.includes(p))
		if(invalid.length) {
			return sendError(res, 400, `Invalid permissions: ${invalid.join(', ')}`)
		}
	}

	const result = await createApiKey({
		adminId: authReq.admin.sub,
		name: body.name,
		permissions: body.permissions,
		rateLimitPerMinute: body.rateLimitPerMinute,
		expiresInDays: body.expiresInDays,
	})

	if('error' in result) {
		return sendError(res, 400, result.error)
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'api_key.create', {
		resourceType: 'api_key',
		resourceId: result.info.id,
		details: {
			name: result.info.name,
			permissions: result.info.permissions,
		},
		ipAddress,
		userAgent,
	})

	// Return the full key only once
	sendJson(res, {
		key: result.key,
		info: result.info,
		warning: 'Store this API key securely. It will not be shown again.',
	}, 201)
}

/**
 * DELETE /api/api-keys/:id
 * Revoke API key
 */
export async function handleRevokeApiKey(
	req: IncomingMessage,
	res: ServerResponse,
	keyId: string
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const result = await revokeApiKey(keyId, authReq.admin.sub)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to revoke API key')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'api_key.revoke', {
		resourceType: 'api_key',
		resourceId: keyId,
		ipAddress,
		userAgent,
	})

	sendJson(res, { success: true })
}

/**
 * PUT /api/api-keys/:id
 * Update API key permissions
 */
export async function handleUpdateApiKey(
	req: IncomingMessage,
	res: ServerResponse,
	keyId: string
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const body = await parseJsonBody<{ permissions: string[] }>(req)

	if(!body?.permissions) {
		return sendError(res, 400, 'permissions is required')
	}

	// Validate permissions
	const validPermissions = Object.keys(API_KEY_PERMISSIONS)
	const invalid = body.permissions.filter(p => !validPermissions.includes(p))
	if(invalid.length) {
		return sendError(res, 400, `Invalid permissions: ${invalid.join(', ')}`)
	}

	const result = await updateApiKeyPermissions(keyId, authReq.admin.sub, body.permissions)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to update API key')
	}

	sendJson(res, { success: true })
}

/**
 * Route handler for /api/api-keys/*
 */
export async function handleApiKeysRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// /api/api-keys
	if(path === '/api/api-keys') {
		if(method === 'GET') {
			await handleListApiKeys(req, res)
			return true
		}
		if(method === 'POST') {
			await handleCreateApiKey(req, res)
			return true
		}
	}

	// /api/api-keys/:id
	const keyIdMatch = path.match(/^\/api\/api-keys\/([a-f0-9-]+)$/)
	if(keyIdMatch) {
		const keyId = keyIdMatch[1]
		if(method === 'DELETE') {
			await handleRevokeApiKey(req, res, keyId)
			return true
		}
		if(method === 'PUT') {
			await handleUpdateApiKey(req, res, keyId)
			return true
		}
	}

	return false
}
