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

import { ethers, Wallet } from 'ethers'
import type { IncomingMessage, ServerResponse } from 'http'
import { getClientInfo, parseJsonBody, sendError, sendJson } from '#src/api/utils/http.ts'

import {
	auditFromRequest,
	requireAdmin,
	requireSuperAdmin,
} from '#src/api/auth/index.ts'
import { getEnvVariable } from '#src/utils/env.ts'

// Production Cartesi node configuration
const LCORE_NODE_URL = getEnvVariable('LCORE_NODE_URL') || 'http://127.0.0.1:10000'
const LCORE_RPC_URL = getEnvVariable('LCORE_RPC_URL') || ''
const LCORE_DAPP_ADDRESS = getEnvVariable('LCORE_DAPP_ADDRESS') || ''
const LCORE_INPUTBOX_ADDRESS = getEnvVariable('LCORE_INPUTBOX_ADDRESS') || '0x59b22D57D4f067708AB0c00552767405926dc768'
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'

// InputBox ABI (minimal)
const INPUT_BOX_ABI = [
	'function addInput(address _dapp, bytes calldata _input) external returns (bytes32)'
]

// Wallet for signing transactions
let _wallet: Wallet | null = null
let _provider: ethers.providers.JsonRpcProvider | null = null

function getProvider(): ethers.providers.JsonRpcProvider {
	if(!_provider) {
		if(!LCORE_RPC_URL) {
			throw new Error('LCORE_RPC_URL is required for production mode')
		}

		_provider = new ethers.providers.JsonRpcProvider(LCORE_RPC_URL)
	}

	return _provider
}

function getWallet(): Wallet {
	if(!_wallet) {
		const mnemonic = getEnvVariable('MNEMONIC')
		if(!mnemonic) {
			throw new Error('MNEMONIC is required for signing transactions')
		}

		_wallet = Wallet.fromMnemonic(mnemonic).connect(getProvider())
	}

	return _wallet
}

function hexEncode(data: unknown): string {
	const jsonStr = JSON.stringify(data)
	return '0x' + Buffer.from(jsonStr, 'utf-8').toString('hex')
}

function hexDecode(hex: string): unknown {
	const str = Buffer.from(hex.slice(2), 'hex').toString('utf-8')
	return JSON.parse(str)
}

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
 * Submit an advance request to the L{CORE} rollup via InputBox contract
 */
async function submitToLCore(
	action: string,
	payload: Record<string, unknown>,
	_sender?: string
): Promise<{ success: boolean, data?: unknown, error?: string }> {
	if(!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	if(!LCORE_DAPP_ADDRESS) {
		return { success: false, error: 'LCORE_DAPP_ADDRESS is required' }
	}

	try {
		const wallet = getWallet()
		const inputBox = new ethers.Contract(LCORE_INPUTBOX_ADDRESS, INPUT_BOX_ABI, wallet)
		const inputData = hexEncode({ action, ...payload })

		// Submit to InputBox contract
		const tx = await inputBox.addInput(LCORE_DAPP_ADDRESS, inputData)
		const receipt = await tx.wait()

		if(!receipt) {
			return { success: false, error: 'Transaction failed - no receipt' }
		}

		return {
			success: true,
			data: { txHash: tx.hash, blockNumber: receipt.blockNumber },
		}
	} catch(error) {
		return {
			success: false,
			error: error instanceof Error ? error.message : String(error),
		}
	}
}

/**
 * Submit an inspect query to the L{CORE} Cartesi node
 */
async function queryLCore(
	type: string,
	params: Record<string, string> = {}
): Promise<{ success: boolean, data?: unknown, error?: string }> {
	if(!LCORE_ENABLED) {
		return { success: false, error: 'L{CORE} is not enabled' }
	}

	try {
		// Build inspect query as hex-encoded JSON
		const query = { type, params }
		const hexPayload = hexEncode(query).slice(2) // Remove 0x prefix for URL

		const response = await fetch(`${LCORE_NODE_URL}/inspect/${hexPayload}`, {
			method: 'GET',
		})

		if(!response.ok) {
			return {
				success: false,
				error: `HTTP ${response.status}: ${response.statusText}`,
			}
		}

		const result = await response.json() as {
			reports?: Array<{ payload: string }>
		}

		if(!result.reports || result.reports.length === 0) {
			return { success: true, data: null }
		}

		// Decode hex payload
		const data = hexDecode(result.reports[0].payload)

		return {
			success: true,
			data,
		}
	} catch(error) {
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
	if(!authReq) {
		return
	}

	const body = await parseJsonBody<{
		walletAddress: string
		canAddProviders?: boolean
		canAddAdmins?: boolean
	}>(req)

	if(!body?.walletAddress) {
		return sendError(res, 400, 'walletAddress is required')
	}

	const result = await submitToLCore('add_schema_admin', {
		wallet_address: body.walletAddress,
		can_add_providers: body.canAddProviders ?? true,
		can_add_admins: body.canAddAdmins ?? false,
	})

	if(!result.success) {
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
	if(!authReq) {
		return
	}

	const body = await parseJsonBody<ProviderSchemaInput>(req)

	if(!body?.provider || !body?.flowType || !body?.domain) {
		return sendError(res, 400, 'provider, flowType, and domain are required')
	}

	if(!body?.bucketDefinitions || Object.keys(body.bucketDefinitions).length === 0) {
		return sendError(res, 400, 'bucketDefinitions is required and must not be empty')
	}

	if(!body?.dataKeys || body.dataKeys.length === 0) {
		return sendError(res, 400, 'dataKeys is required and must not be empty')
	}

	if(!body?.freshnessHalfLife || body.freshnessHalfLife <= 0) {
		return sendError(res, 400, 'freshnessHalfLife is required and must be positive')
	}

	// Validate bucket definitions
	for(const [key, def] of Object.entries(body.bucketDefinitions)) {
		if(!def.boundaries || !def.labels) {
			return sendError(res, 400, `Invalid bucket definition for key '${key}': must have boundaries and labels`)
		}

		if(def.boundaries.length !== def.labels.length + 1) {
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

	if(!result.success) {
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
	if(!authReq) {
		return
	}

	const url = new URL(req.url || '', 'http://localhost')
	const domain = url.searchParams.get('domain') || undefined
	const activeOnly = url.searchParams.get('active_only') !== 'false'

	const result = await queryLCore('all_provider_schemas', {
		domain: domain || '',
		active_only: String(activeOnly),
	})

	if(!result.success) {
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
	if(!authReq) {
		return
	}

	const result = await queryLCore('all_schema_admins')

	if(!result.success) {
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
	if(!LCORE_ENABLED) {
		return sendJson(res, { enabled: false, status: 'disabled' })
	}

	try {
		const response = await fetch(`${LCORE_NODE_URL}/graphql`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ query: '{ inputs { totalCount } }' }),
			signal: AbortSignal.timeout(5000),
		})

		if(!response.ok) {
			return sendJson(res, {
				enabled: true,
				status: 'error',
				error: `HTTP ${response.status}`,
			})
		}

		const data = await response.json()
		sendJson(res, {
			enabled: true,
			status: 'running',
			nodeUrl: LCORE_NODE_URL,
			dappAddress: LCORE_DAPP_ADDRESS,
			...data,
		})
	} catch(error) {
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
	if(!LCORE_ENABLED) {
		return sendJson(res, { healthy: false, reason: 'disabled' })
	}

	try {
		const response = await fetch(`${LCORE_NODE_URL}/graphql`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ query: '{ inputs { totalCount } }' }),
			signal: AbortSignal.timeout(5000),
		})

		sendJson(res, { healthy: response.ok })
	} catch{
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
	if(path === '/api/lcore/schema-admin' && method === 'POST') {
		await handleAddSchemaAdmin(req, res)
		return true
	}

	// POST /api/lcore/provider-schema
	if(path === '/api/lcore/provider-schema' && method === 'POST') {
		await handleRegisterProviderSchema(req, res)
		return true
	}

	// GET /api/lcore/provider-schemas
	if(path === '/api/lcore/provider-schemas' && method === 'GET') {
		await handleListProviderSchemas(req, res)
		return true
	}

	// GET /api/lcore/schema-admins
	if(path === '/api/lcore/schema-admins' && method === 'GET') {
		await handleListSchemaAdmins(req, res)
		return true
	}

	// GET /api/lcore/status
	if(path === '/api/lcore/status' && method === 'GET') {
		await handleLCoreStatus(req, res)
		return true
	}

	// GET /api/lcore/health
	if(path === '/api/lcore/health' && method === 'GET') {
		await handleLCoreHealth(req, res)
		return true
	}

	return false
}
