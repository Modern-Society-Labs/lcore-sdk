import type { IncomingMessage, ServerResponse } from 'http'
import { createServer as createHttpServer } from 'http'
import serveStatic from 'serve-static'
import type { Duplex } from 'stream'
import type { WebSocket } from 'ws'
import { WebSocketServer } from 'ws'

import { handleApiRequest, handleHealthCheck } from '#src/api/routes/index.ts'
import { API_SERVER_PORT, BROWSER_RPC_PATHNAME, WS_PATHNAME } from '#src/config/index.ts'
import { initDecryption } from '#src/lcore/index.ts'
import { AttestorServerSocket } from '#src/server/socket.ts'
import { getAttestorAddress } from '#src/server/utils/generics.ts'
import { addKeepAlive } from '#src/server/utils/keep-alive.ts'
import type { BGPListener } from '#src/types/index.ts'
import { createBgpListener } from '#src/utils/bgp-listener.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { sanitizeError } from '#src/utils/error-sanitizer.ts'
import { logger as LOGGER } from '#src/utils/index.ts'
import { SelectedServiceSignatureType } from '#src/utils/signatures/index.ts'
import { promisifySend } from '#src/utils/ws.ts'

// Support both PORT (standard) and APP_PORT (EigenCompute convention)
const PORT = +(getEnvVariable('APP_PORT') || getEnvVariable('PORT') || API_SERVER_PORT)
const DISABLE_BGP_CHECKS = getEnvVariable('DISABLE_BGP_CHECKS') === '1'

// CORS configuration from environment variable
const ALLOWED_ORIGINS = getEnvVariable('CORS_ALLOWED_ORIGINS')?.split(',').map(s => s.trim()) || ['*']

// Maximum request body size (100KB)
const MAX_BODY_SIZE = 100 * 1024

/**
 * Set security headers on HTTP response
 */
function setSecurityHeaders(res: ServerResponse): void {
	res.setHeader('X-Content-Type-Options', 'nosniff')
	res.setHeader('X-Frame-Options', 'DENY')
	res.setHeader('X-XSS-Protection', '1; mode=block')
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
}

/**
 * Set CORS headers based on request origin and configuration
 */
function setCorsHeaders(req: IncomingMessage, res: ServerResponse): void {
	const origin = req.headers.origin

	if(ALLOWED_ORIGINS.includes('*')) {
		res.setHeader('Access-Control-Allow-Origin', '*')
	} else if(origin && ALLOWED_ORIGINS.includes(origin)) {
		res.setHeader('Access-Control-Allow-Origin', origin)
		res.setHeader('Vary', 'Origin')
	} else if(ALLOWED_ORIGINS.length > 0) {
		// Default to first allowed origin if request origin not in list
		res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0])
	}

	res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
	res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
	res.setHeader('Access-Control-Max-Age', '86400')
}

/**
 * Check if request body exceeds maximum size
 */
function isBodyTooLarge(req: IncomingMessage): boolean {
	const contentLength = parseInt(req.headers['content-length'] || '0', 10)
	return contentLength > MAX_BODY_SIZE
}

/**
 * Creates the WebSocket API server,
 * creates a fileserver to serve the browser RPC client,
 * and listens on the given port.
 */
export async function createServer(port = PORT) {
	// Initialize L{CORE} decryption for privacy-preserving responses
	initDecryption()

	const http = createHttpServer()
	const serveBrowserRpc = serveStatic(
		'browser',
		{
			index: ['index.html'],
			setHeaders(res, _path, _stat) {
				// Security headers for static files
				res.setHeader('X-Content-Type-Options', 'nosniff')
				res.setHeader('Access-Control-Allow-Origin', '*')
			},
		}
	)
	const bgpListener = !DISABLE_BGP_CHECKS
		? createBgpListener(LOGGER.child({ service: 'bgp-listener' }))
		: undefined

	const wss = new WebSocketServer({ noServer: true })
	http.on('upgrade', handleUpgrade.bind(wss))
	http.on('request', async(req, res) => {
		// Apply security headers to all responses
		setSecurityHeaders(res)

		// Handle CORS preflight requests
		if(req.method === 'OPTIONS') {
			setCorsHeaders(req, res)
			res.statusCode = 204
			res.end()
			return
		}

		// Handle Admin API routes
		if(req.url?.startsWith('/api/')) {
			setCorsHeaders(req, res)

			try {
				// Handle health check first (no auth required)
				if(handleHealthCheck(req, res)) {
					return
				}

				// Check payload size for POST/PUT requests
				if(['POST', 'PUT', 'PATCH'].includes(req.method || '') && isBodyTooLarge(req)) {
					res.statusCode = 413
					res.setHeader('Content-Type', 'application/json')
					res.end(JSON.stringify({ error: 'Payload too large' }))
					return
				}

				// Handle authenticated API routes
				const handled = await handleApiRequest(req, res)
				if(handled) {
					return
				}

				// No handler found for this API route
				res.statusCode = 404
				res.setHeader('Content-Type', 'application/json')
				res.end(JSON.stringify({ error: 'Not found' }))
			} catch(err) {
				// Sanitize error before logging to prevent sensitive data leaks
				const sanitizedErr = err instanceof Error ? sanitizeError(err) : err
				LOGGER.error({ err: sanitizedErr, url: req.url }, 'API error')
				res.statusCode = 500
				res.setHeader('Content-Type', 'application/json')
				res.end(JSON.stringify({ error: 'Internal server error' }))
			}

			return
		}

		// simple way to serve files at the browser RPC path
		if(!req.url?.startsWith(BROWSER_RPC_PATHNAME)) {
			res.statusCode = 404
			res.end('Not found')
			return
		}

		req.url = req.url.slice(BROWSER_RPC_PATHNAME.length) || '/'

		serveBrowserRpc(req, res, (err) => {
			if(err) {
				LOGGER.error(
					{ err, url: req.url },
					'Failed to serve file'
				)
			}

			res.statusCode = err?.statusCode ?? 404
			res.end(err?.message ?? 'Not found')
		})
	})

	// wait for us to start listening
	http.listen(port)
	await new Promise<void>((resolve, reject) => {
		http.once('listening', () => resolve())
		http.once('error', reject)
	})

	wss.on('connection', (ws, req) => handleNewClient(ws, req, bgpListener))

	LOGGER.info(
		{
			port,
			apiPath: WS_PATHNAME,
			browserRpcPath: BROWSER_RPC_PATHNAME,
			signerAddress: getAttestorAddress(SelectedServiceSignatureType)
		},
		'WS server listening'
	)

	const wssClose = wss.close.bind(wss)
	wss.close = (cb) => {
		wssClose(() => http.close(cb))
		bgpListener?.close()
	}

	return wss
}

async function handleNewClient(
	ws: WebSocket,
	req: IncomingMessage,
	bgpListener: BGPListener | undefined
) {
	promisifySend(ws)
	const client = await AttestorServerSocket.acceptConnection(
		ws,
		{ req, bgpListener, logger: LOGGER }
	)
	// if initialisation fails, don't store the client
	if(!client) {
		return
	}

	ws.serverSocket = client
	addKeepAlive(ws, LOGGER.child({ sessionId: client.sessionId }))
}

function handleUpgrade(
	this: WebSocketServer,
	request: IncomingMessage,
	socket: Duplex,
	head: Buffer
) {
	const { pathname } = new URL(request.url!, 'wss://base.url')

	if(pathname === WS_PATHNAME) {
		this.handleUpgrade(request, socket, head, (ws) => {
			this.emit('connection', ws, request)
		})
		return
	}

	socket.destroy()
}