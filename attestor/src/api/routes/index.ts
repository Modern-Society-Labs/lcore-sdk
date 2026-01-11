/**
 * API routes index
 *
 * Main router for all admin API endpoints.
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { handleAuthRoute } from './auth.ts'
import { handleAdminsRoute } from './admins.ts'
import { handleApiKeysRoute } from './api-keys.ts'
import { handleAuditRoute } from './audit.ts'
import { handleOperatorsRoute } from './operators.ts'
import { handleStatsRoute } from './stats.ts'
import { sendError, handleCorsPrelight, setCorsHeaders } from '../utils/http.ts'

/**
 * Main API router
 *
 * Routes requests to appropriate handlers based on path.
 */
export async function handleApiRequest(
	req: IncomingMessage,
	res: ServerResponse
): Promise<boolean> {
	const url = req.url || ''
	const path = url.split('?')[0]

	// Only handle /api/* routes
	if(!path.startsWith('/api/')) {
		return false
	}

	// Set CORS headers
	setCorsHeaders(res, req.headers.origin)

	// Handle preflight
	if(handleCorsPrelight(req, res)) {
		return true
	}

	try {
		// Route to appropriate handler
		if(path.startsWith('/api/auth/')) {
			return await handleAuthRoute(req, res, path)
		}

		if(path.startsWith('/api/admins')) {
			return await handleAdminsRoute(req, res, path)
		}

		if(path.startsWith('/api/api-keys')) {
			return await handleApiKeysRoute(req, res, path)
		}

		if(path.startsWith('/api/audit')) {
			return await handleAuditRoute(req, res, path)
		}

		if(path.startsWith('/api/operators')) {
			return await handleOperatorsRoute(req, res, path)
		}

		if(path.startsWith('/api/stats')) {
			return await handleStatsRoute(req, res, path)
		}

		// No handler found
		sendError(res, 404, 'Not found')
		return true
	} catch(err) {
		console.error('[API ERROR]', err)
		sendError(res, 500, 'Internal server error')
		return true
	}
}

/**
 * Health check endpoint
 */
export function handleHealthCheck(
	req: IncomingMessage,
	res: ServerResponse
): boolean {
	if(req.url === '/api/health' && req.method === 'GET') {
		res.writeHead(200, { 'Content-Type': 'application/json' })
		res.end(JSON.stringify({
			status: 'ok',
			timestamp: new Date().toISOString(),
			version: process.env.npm_package_version || 'unknown',
		}))
		return true
	}

	return false
}
