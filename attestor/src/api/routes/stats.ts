/**
 * Public stats API routes
 *
 * These endpoints provide public access to indexed network statistics.
 * No authentication required.
 *
 * GET /api/stats                - Network overview
 * GET /api/stats/tasks          - Task statistics
 * GET /api/stats/operators      - Operator statistics
 * GET /api/stats/daily/:date    - Daily statistics
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { parseQuery, sendError, sendJson } from '#src/api/utils/http.ts'

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'

/**
 * GET /api/stats
 * Get network overview statistics
 */
export async function handleNetworkStats(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if(!isDatabaseConfigured()) {
		return sendJson(res, {
			message: 'Database not configured. Stats unavailable.',
			totalOperators: 0,
			activeOperators: 0,
			totalTasks: 0,
			completedTasks: 0,
			totalFeesCollected: '0',
		})
	}

	const supabase = getSupabaseClient()

	// Get operator counts
	const { count: totalOperators } = await supabase
		.from('indexed_operators')
		.select('*', { count: 'exact', head: true })

	const { count: activeOperators } = await supabase
		.from('indexed_operators')
		.select('*', { count: 'exact', head: true })
		.eq('is_registered', true)

	// Get task counts
	const { count: totalTasks } = await supabase
		.from('indexed_tasks')
		.select('*', { count: 'exact', head: true })

	const { count: completedTasks } = await supabase
		.from('indexed_tasks')
		.select('*', { count: 'exact', head: true })
		.eq('status', 'completed')

	// Get config values for fees
	const { data: feeConfig } = await supabase
		.from('system_config')
		.select('value')
		.eq('key', 'subgraph_total_fees_collected')
		.single()

	const { data: lastSyncConfig } = await supabase
		.from('system_config')
		.select('value')
		.eq('key', 'subgraph_last_sync')
		.single()

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const feeValue = (feeConfig as any)?.value?.data || '0'
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const lastSync = (lastSyncConfig as any)?.value?.data || null

	sendJson(res, {
		totalOperators: totalOperators || 0,
		activeOperators: activeOperators || 0,
		totalTasks: totalTasks || 0,
		completedTasks: completedTasks || 0,
		pendingTasks: (totalTasks || 0) - (completedTasks || 0),
		totalFeesCollected: feeValue,
		lastSynced: lastSync,
	})
}

/**
 * GET /api/stats/tasks
 * Get task statistics with optional time range
 */
export async function handleTaskStats(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if(!isDatabaseConfigured()) {
		return sendJson(res, { tasks: [], total: 0 })
	}

	const query = parseQuery(req.url || '')
	const limit = query.limit ? parseInt(query.limit, 10) : 20
	const offset = query.offset ? parseInt(query.offset, 10) : 0
	const status = query.status || undefined
	const provider = query.provider || undefined

	const supabase = getSupabaseClient()
	let dbQuery = supabase
		.from('indexed_tasks')
		.select('*', { count: 'exact' })
		.order('created_at', { ascending: false })
		.range(offset, offset + limit - 1)

	if(status) {
		dbQuery = dbQuery.eq('status', status)
	}

	if(provider) {
		dbQuery = dbQuery.eq('provider_name', provider)
	}

	const { data, count, error } = await dbQuery

	if(error) {
		console.error('[STATS] Task query error:', error)
		return sendError(res, 500, 'Failed to fetch task statistics')
	}

	sendJson(res, {
		tasks: data || [],
		total: count || 0,
		limit,
		offset,
	})
}

/**
 * GET /api/stats/operators
 * Get operator leaderboard
 */
export async function handleOperatorLeaderboard(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	if(!isDatabaseConfigured()) {
		return sendJson(res, { operators: [], total: 0 })
	}

	const query = parseQuery(req.url || '')
	const limit = query.limit ? parseInt(query.limit, 10) : 20
	const offset = query.offset ? parseInt(query.offset, 10) : 0
	const sortBy = query.sort || 'tasks_completed'
	const registeredOnly = query.registered === 'true'

	const supabase = getSupabaseClient()
	let dbQuery = supabase
		.from('indexed_operators')
		.select('*', { count: 'exact' })
		.order(sortBy as 'tasks_completed' | 'tasks_assigned', { ascending: false })
		.range(offset, offset + limit - 1)

	if(registeredOnly) {
		dbQuery = dbQuery.eq('is_registered', true)
	}

	const { data, count, error } = await dbQuery

	if(error) {
		console.error('[STATS] Operator query error:', error)
		return sendError(res, 500, 'Failed to fetch operator statistics')
	}

	// Define type for indexed operator
	interface IndexedOperator {
		wallet_address: string
		is_whitelisted: boolean
		is_registered: boolean
		rpc_url: string | null
		tasks_assigned: number
		tasks_completed: number
		tasks_slashed: number
		registered_at: string | null
	}

	// Calculate additional metrics
	const operators = ((data || []) as IndexedOperator[]).map(op => ({
		walletAddress: op.wallet_address,
		isWhitelisted: op.is_whitelisted,
		isRegistered: op.is_registered,
		rpcUrl: op.rpc_url,
		tasksAssigned: op.tasks_assigned,
		tasksCompleted: op.tasks_completed,
		tasksSlashed: op.tasks_slashed,
		completionRate: op.tasks_assigned > 0
			? ((op.tasks_completed / op.tasks_assigned) * 100).toFixed(2)
			: '0.00',
		registeredAt: op.registered_at,
	}))

	sendJson(res, {
		operators,
		total: count || 0,
		limit,
		offset,
	})
}

/**
 * GET /api/stats/daily/:date
 * Get daily statistics for a specific date
 */
export async function handleDailyStats(
	req: IncomingMessage,
	res: ServerResponse,
	dateStr: string
): Promise<void> {
	// Validate date format (YYYY-MM-DD)
	if(!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
		return sendError(res, 400, 'Invalid date format. Use YYYY-MM-DD')
	}

	if(!isDatabaseConfigured()) {
		return sendJson(res, {
			date: dateStr,
			tasksCreated: 0,
			tasksCompleted: 0,
			feesCollected: '0',
		})
	}

	const startOfDay = new Date(dateStr + 'T00:00:00Z')
	const endOfDay = new Date(dateStr + 'T23:59:59Z')

	const supabase = getSupabaseClient()

	// Count tasks created on this day
	const { count: tasksCreated } = await supabase
		.from('indexed_tasks')
		.select('*', { count: 'exact', head: true })
		.gte('created_at', startOfDay.toISOString())
		.lte('created_at', endOfDay.toISOString())

	// Count tasks completed on this day
	const { count: tasksCompleted } = await supabase
		.from('indexed_tasks')
		.select('*', { count: 'exact', head: true })
		.gte('completed_at', startOfDay.toISOString())
		.lte('completed_at', endOfDay.toISOString())

	// Sum fees collected on this day
	const { data: feeData } = await supabase
		.from('indexed_tasks')
		.select('fee_paid')
		.gte('created_at', startOfDay.toISOString())
		.lte('created_at', endOfDay.toISOString())

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const totalFees = (feeData || []).reduce((sum: bigint, task: any) => {
		return sum + BigInt(task.fee_paid || '0')
	}, BigInt(0))

	sendJson(res, {
		date: dateStr,
		tasksCreated: tasksCreated || 0,
		tasksCompleted: tasksCompleted || 0,
		feesCollected: totalFees.toString(),
	})
}

/**
 * Route handler for /api/stats/*
 */
export async function handleStatsRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// Only GET methods allowed
	if(method !== 'GET') {
		return false
	}

	// GET /api/stats
	if(path === '/api/stats') {
		await handleNetworkStats(req, res)
		return true
	}

	// GET /api/stats/tasks
	if(path === '/api/stats/tasks') {
		await handleTaskStats(req, res)
		return true
	}

	// GET /api/stats/operators
	if(path === '/api/stats/operators') {
		await handleOperatorLeaderboard(req, res)
		return true
	}

	// GET /api/stats/daily/:date
	const dailyMatch = path.match(/^\/api\/stats\/daily\/(\d{4}-\d{2}-\d{2})$/)
	if(dailyMatch) {
		await handleDailyStats(req, res, dailyMatch[1])
		return true
	}

	return false
}
