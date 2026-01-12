/**
 * L{CORE} Admin API routes
 *
 * Admin endpoints for managing the Cartesi L{CORE} layer.
 *
 * POST   /api/lcore/schema-admin           - Bootstrap or add schema admin
 * POST   /api/lcore/provider-schema        - Register new provider schema
 * GET    /api/lcore/provider-schemas       - List all provider schemas
 * GET    /api/lcore/schema-admins          - List all schema admins
 * GET    /api/lcore/status                 - Get L{CORE} status
 * GET    /api/lcore/health                 - Health check for L{CORE}
 */

import type { IncomingMessage, ServerResponse } from 'http'
import {
	requireSuperAdmin,
	requireAdmin,
	auditFromRequest,
} from '#src/api/auth/index.ts'
import { parseJsonBody, sendJson, sendError, getClientInfo } from '../utils/http.ts'
import { getEnvVariable } from '#src/utils/env.ts'

// L{CORE} rollup server URL
const LCORE_ROLLUP_URL = getEnvVariable('LCORE_ROLLUP_URL') || 'http://127.0.0.1:5004'
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'

// Default sender for admin operations (attestor address)
const ADMIN_SENDER = getEnvVariable('LCORE_ADMIN_ADDRESS') || '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266'

interface BucketDefinition {
	boundaries: number[]
	labels: string[]
}

interface ProviderSchemaInput {
	provider: string
	flowType: string
	domain: string
	bucketDefinitions: Record<string, BucketDefinition>
	dataKeys: string[]
	freshnessHalfLife: number
	minFreshness?: number
}

/**
 * Submit an advance request to the L{CORE} rollup
 */
async function submitToLCore(
	action: string,
	payload: Record<string, unknown>,
	sender = ADMIN_SENDER
): Promise<{ success: boolean; data?: unknown; error?: string }> {
	if (!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/input/advance`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				sender,
				payload: { action, ...payload },
			}),
		})

		if (!response.ok) {
			return {
				success: false,
				error: `HTTP ${response.status}: ${response.statusText}`,
			}
		}

		const result = await response.json() as {
			status: 'accept' | 'reject'
			notices: Array<{ payload: string; payloadJson: unknown }>
			reports: Array<{ payload: string; payloadJson: unknown }>
		}

		if (result.status === 'reject') {
			const errorReport = result.reports.find(r =>
				r.payloadJson && typeof r.payloadJson === 'object' && 'error' in (r.payloadJson as object)
			)
			const errorPayload = errorReport?.payloadJson as { error?: string } | undefined

			return {
				success: false,
				error: errorPayload?.error || 'Request rejected',
			}
		}

		return {
			success: true,
			data: result.notices[0]?.payloadJson,
		}
	} catch (error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : String(error),
		}
	}
}

/**
 * Submit an inspect query to the L{CORE} rollup
 */
async function queryLCore(
	type: string,
	params: Record<string, string> = {}
): Promise<{ success: boolean; data?: unknown; error?: string }> {
	if (!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/input/inspect`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ type, params }),
		})

		if (!response.ok) {
			return {
				success: false,
				error: `HTTP ${response.status}: ${response.statusText}`,
			}
		}

		const result = await response.json() as {
			reports: Array<{ payload: string; payloadJson: unknown }>
		}

		return {
			success: true,
			data: result.reports[0]?.payloadJson,
		}
	} catch (error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : String(error),
		}
	}
}

/**
 * POST /api/lcore/schema-admin
 * Add a schema admin (first call bootstraps with full permissions)
 */
export async function handleAddSchemaAdmin(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireSuperAdmin(req, res)
	if (!authReq) {
		return
	}

	const body = await parseJsonBody<{
		walletAddress: string
		canAddProviders?: boolean
		canAddAdmins?: boolean
	}>(req)

	if (!body?.walletAddress) {
		return sendError(res, 400, 'walletAddress is required')
	}

	const result = await submitToLCore('add_schema_admin', {
		wallet_address: body.walletAddress,
		can_add_providers: body.canAddProviders ?? true,
		can_add_admins: body.canAddAdmins ?? false,
	})

	if (!result.success) {
		return sendError(res, 400, result.error || 'Failed to add schema admin')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'lcore.add_schema_admin', {
		resourceType: 'lcore_schema_admin',
		resourceId: body.walletAddress,
		details: {
			walletAddress: body.walletAddress,
			canAddProviders: body.canAddProviders ?? true,
			canAddAdmins: body.canAddAdmins ?? false,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, result.data, 201)
}

/**
 * POST /api/lcore/provider-schema
 * Register a new provider schema
 */
export async function handleRegisterProviderSchema(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireSuperAdmin(req, res)
	if (!authReq) {
		return
	}

	const body = await parseJsonBody<ProviderSchemaInput>(req)

	if (!body?.provider || !body?.flowType || !body?.domain) {
		return sendError(res, 400, 'provider, flowType, and domain are required')
	}

	if (!body?.bucketDefinitions || Object.keys(body.bucketDefinitions).length === 0) {
		return sendError(res, 400, 'bucketDefinitions is required and must not be empty')
	}

	if (!body?.dataKeys || body.dataKeys.length === 0) {
		return sendError(res, 400, 'dataKeys is required and must not be empty')
	}

	if (!body?.freshnessHalfLife || body.freshnessHalfLife <= 0) {
		return sendError(res, 400, 'freshnessHalfLife is required and must be positive')
	}

	// Validate bucket definitions
	for (const [key, def] of Object.entries(body.bucketDefinitions)) {
		if (!def.boundaries || !def.labels) {
			return sendError(res, 400, `Invalid bucket definition for key '${key}': must have boundaries and labels`)
		}
		if (def.boundaries.length !== def.labels.length + 1) {
			return sendError(res, 400, `Invalid bucket definition for key '${key}': boundaries length must be labels length + 1`)
		}
	}

	const result = await submitToLCore('register_provider_schema', {
		provider: body.provider.toLowerCase(),
		flow_type: body.flowType.toLowerCase(),
		domain: body.domain.toLowerCase(),
		bucket_definitions: body.bucketDefinitions,
		data_keys: body.dataKeys,
		freshness_half_life: body.freshnessHalfLife,
		min_freshness: body.minFreshness,
	})

	if (!result.success) {
		return sendError(res, 400, result.error || 'Failed to register provider schema')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'lcore.register_provider_schema', {
		resourceType: 'lcore_provider_schema',
		resourceId: `${body.provider}:${body.flowType}`,
		details: {
			provider: body.provider,
			flowType: body.flowType,
			domain: body.domain,
			bucketKeys: Object.keys(body.bucketDefinitions),
			dataKeys: body.dataKeys,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, result.data, 201)
}

/**
 * GET /api/lcore/provider-schemas
 * List all registered provider schemas
 */
export async function handleListProviderSchemas(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if (!authReq) {
		return
	}

	const url = new URL(req.url || '', 'http://localhost')
	const domain = url.searchParams.get('domain') || undefined
	const activeOnly = url.searchParams.get('active_only') !== 'false'

	const result = await queryLCore('all_provider_schemas', {
		domain: domain || '',
		active_only: String(activeOnly),
	})

	if (!result.success) {
		return sendError(res, 500, result.error || 'Failed to query provider schemas')
	}

	sendJson(res, result.data)
}

/**
 * GET /api/lcore/schema-admins
 * List all schema admins
 */
export async function handleListSchemaAdmins(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if (!authReq) {
		return
	}

	const result = await queryLCore('all_schema_admins')

	if (!result.success) {
		return sendError(res, 500, result.error || 'Failed to query schema admins')
	}

	sendJson(res, result.data)
}

/**
 * GET /api/lcore/status
 * Get L{CORE} status
 */
export async function handleLCoreStatus(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if (!LCORE_ENABLED) {
		return sendJson(res, { enabled: false, status: 'disabled' })
	}

	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/status`, {
			method: 'GET',
			signal: AbortSignal.timeout(5000),
		})

		if (!response.ok) {
			return sendJson(res, {
				enabled: true,
				status: 'error',
				error: `HTTP ${response.status}`,
			})
		}

		const status = await response.json()
		sendJson(res, { enabled: true, status: 'running', ...status })
	} catch (error) {
		sendJson(res, {
			enabled: true,
			status: 'unavailable',
			error: error instanceof Error ? error.message : String(error),
		})
	}
}

/**
 * GET /api/lcore/health
 * Health check for L{CORE}
 */
export async function handleLCoreHealth(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if (!LCORE_ENABLED) {
		return sendJson(res, { healthy: false, reason: 'disabled' })
	}

	try {
		const response = await fetch(`${LCORE_ROLLUP_URL}/health`, {
			method: 'GET',
			signal: AbortSignal.timeout(5000),
		})

		sendJson(res, { healthy: response.ok })
	} catch {
		sendJson(res, { healthy: false, reason: 'connection_failed' })
	}
}

/**
 * Route handler for /api/lcore/*
 */
export async function handleLCoreRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// POST /api/lcore/schema-admin
	if (path === '/api/lcore/schema-admin' && method === 'POST') {
		await handleAddSchemaAdmin(req, res)
		return true
	}

	// POST /api/lcore/provider-schema
	if (path === '/api/lcore/provider-schema' && method === 'POST') {
		await handleRegisterProviderSchema(req, res)
		return true
	}

	// GET /api/lcore/provider-schemas
	if (path === '/api/lcore/provider-schemas' && method === 'GET') {
		await handleListProviderSchemas(req, res)
		return true
	}

	// GET /api/lcore/schema-admins
	if (path === '/api/lcore/schema-admins' && method === 'GET') {
		await handleListSchemaAdmins(req, res)
		return true
	}

	// GET /api/lcore/status
	if (path === '/api/lcore/status' && method === 'GET') {
		await handleLCoreStatus(req, res)
		return true
	}

	// GET /api/lcore/health
	if (path === '/api/lcore/health' && method === 'GET') {
		await handleLCoreHealth(req, res)
		return true
	}

	return false
}
