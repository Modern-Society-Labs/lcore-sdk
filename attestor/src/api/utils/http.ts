/**
 * HTTP utilities for API routes
 */

import type { IncomingMessage, ServerResponse } from 'http'

/**
 * Parse JSON body from request
 */
export async function parseJsonBody<T>(req: IncomingMessage): Promise<T | null> {
	return new Promise((resolve) => {
		let body = ''

		req.on('data', chunk => {
			body += chunk.toString()
			// Limit body size to 1MB
			if(body.length > 1024 * 1024) {
				resolve(null)
			}
		})

		req.on('end', () => {
			try {
				resolve(JSON.parse(body) as T)
			} catch{
				resolve(null)
			}
		})

		req.on('error', () => {
			resolve(null)
		})
	})
}

/**
 * Send JSON response
 */
export function sendJson(res: ServerResponse, data: unknown, status = 200): void {
	res.writeHead(status, {
		'Content-Type': 'application/json',
		'Cache-Control': 'no-store',
	})
	res.end(JSON.stringify(data))
}

/**
 * Send error response
 */
export function sendError(res: ServerResponse, status: number, message: string): void {
	res.writeHead(status, {
		'Content-Type': 'application/json',
		'Cache-Control': 'no-store',
	})
	res.end(JSON.stringify({ error: message }))
}

/**
 * Get client IP and user agent from request
 */
export function getClientInfo(req: IncomingMessage): {
	ipAddress: string | undefined
	userAgent: string | undefined
} {
	// Check forwarded headers first (for proxies)
	const forwardedFor = req.headers['x-forwarded-for']
	const realIp = req.headers['x-real-ip']

	let ipAddress: string | undefined

	if(typeof forwardedFor === 'string') {
		// Take the first IP in the chain
		ipAddress = forwardedFor.split(',')[0].trim()
	} else if(typeof realIp === 'string') {
		ipAddress = realIp
	} else {
		ipAddress = req.socket.remoteAddress
	}

	const userAgent = typeof req.headers['user-agent'] === 'string'
		? req.headers['user-agent']
		: undefined

	return { ipAddress, userAgent }
}

/**
 * Parse query string
 */
export function parseQuery(url: string): Record<string, string> {
	const query: Record<string, string> = {}
	const questionIndex = url.indexOf('?')

	if(questionIndex === -1) {
		return query
	}

	const queryString = url.slice(questionIndex + 1)
	const pairs = queryString.split('&')

	for(const pair of pairs) {
		const [key, value] = pair.split('=')
		if(key) {
			query[decodeURIComponent(key)] = value ? decodeURIComponent(value) : ''
		}
	}

	return query
}

/**
 * CORS headers for API routes
 */
export function setCorsHeaders(res: ServerResponse, origin?: string): void {
	const allowedOrigins = process.env.CORS_ALLOWED_ORIGINS?.split(',') || ['*']
	const requestOrigin = origin || '*'

	const allowOrigin = allowedOrigins.includes('*')
		? '*'
		: allowedOrigins.includes(requestOrigin)
			? requestOrigin
			: allowedOrigins[0]

	res.setHeader('Access-Control-Allow-Origin', allowOrigin)
	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
	res.setHeader('Access-Control-Max-Age', '86400')
}

/**
 * Handle CORS preflight
 */
export function handleCorsPrelight(req: IncomingMessage, res: ServerResponse): boolean {
	if(req.method === 'OPTIONS') {
		setCorsHeaders(res, req.headers.origin)
		res.writeHead(204)
		res.end()
		return true
	}

	return false
}
