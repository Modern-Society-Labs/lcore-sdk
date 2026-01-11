/**
 * Sync Service
 *
 * Syncs data from The Graph subgraph to Supabase database.
 * This provides faster queries and allows for additional business logic.
 */

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import { getEnvVariable } from '#src/utils/env.ts'

// GraphQL endpoint for The Graph
const SUBGRAPH_URL = getEnvVariable('SUBGRAPH_URL') || 'https://api.studio.thegraph.com/query/YOUR_ID/locale-avs-holesky/version/latest'

// Sync interval in milliseconds (default: 30 seconds)
const SYNC_INTERVAL_MS = parseInt(getEnvVariable('SYNC_INTERVAL_MS') || '30000', 10)

interface GraphQLResponse<T> {
	data?: T
	errors?: Array<{ message: string }>
}

interface SubgraphOperator {
	id: string
	address: string
	isWhitelisted: boolean
	isRegistered: boolean
	rpcUrl: string | null
	tasksAssigned: string
	tasksCompleted: string
	tasksSlashed: string
	totalSlashedWads: string
	whitelistedAt: string | null
	registeredAt: string | null
}

interface SubgraphTask {
	id: string
	taskIndex: string
	taskHash: string
	provider: string
	claimHash: string
	owner: string
	status: string
	feePaid: string
	createdAt: string
	completedAt: string | null
	expiresAt: string
	createdBlock: string
	createdTxHash: string
}

interface SubgraphGlobalStats {
	totalTasks: string
	completedTasks: string
	totalOperators: string
	activeOperators: string
	totalFeesCollected: string
	totalFeesDistributed: string
	totalSlashingEvents: string
	totalWadsSlashed: string
}

interface OperatorsQueryResult {
	operators: SubgraphOperator[]
}

interface TasksQueryResult {
	tasks: SubgraphTask[]
}

interface GlobalStatsQueryResult {
	globalStats: SubgraphGlobalStats | null
}

/**
 * Execute a GraphQL query against The Graph
 */
async function querySubgraph<T>(query: string, variables: Record<string, unknown> = {}): Promise<T | null> {
	try {
		const response = await fetch(SUBGRAPH_URL, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ query, variables }),
		})

		const result = await response.json() as GraphQLResponse<T>

		if(result.errors?.length) {
			console.error('[SYNC] GraphQL errors:', result.errors)
			return null
		}

		return result.data || null
	} catch(err) {
		console.error('[SYNC] Query failed:', err)
		return null
	}
}

/**
 * Sync operators from subgraph to database
 */
async function syncOperators(): Promise<number> {
	if(!isDatabaseConfigured()) {
		return 0
	}

	const query = `
		query GetOperators($first: Int!, $skip: Int!) {
			operators(first: $first, skip: $skip, orderBy: registeredAt, orderDirection: desc) {
				id
				address
				isWhitelisted
				isRegistered
				rpcUrl
				tasksAssigned
				tasksCompleted
				tasksSlashed
				totalSlashedWads
				whitelistedAt
				registeredAt
			}
		}
	`

	let totalSynced = 0
	let skip = 0
	const first = 100

	const supabase = getSupabaseClient()

	while(true) {
		const result = await querySubgraph<OperatorsQueryResult>(query, { first, skip })
		if(!result?.operators?.length) {
			break
		}

		const operators = result.operators

		// Upsert operators to database
		for(const op of operators) {
			const upsertData = {
				wallet_address: op.address.toLowerCase(),
				is_whitelisted: op.isWhitelisted,
				is_registered: op.isRegistered,
				rpc_url: op.rpcUrl || null,
				tasks_assigned: parseInt(op.tasksAssigned, 10),
				tasks_completed: parseInt(op.tasksCompleted, 10),
				tasks_slashed: parseInt(op.tasksSlashed, 10),
				total_slashed_wads: op.totalSlashedWads,
				whitelisted_at: op.whitelistedAt ? new Date(parseInt(op.whitelistedAt, 10) * 1000).toISOString() : null,
				registered_at: op.registeredAt ? new Date(parseInt(op.registeredAt, 10) * 1000).toISOString() : null,
				last_synced_at: new Date().toISOString(),
			}

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			await (supabase.from('indexed_operators') as any)
				.upsert(upsertData, { onConflict: 'wallet_address' })
		}

		totalSynced += operators.length
		skip += first

		if(operators.length < first) {
			break
		}
	}

	return totalSynced
}

/**
 * Sync tasks from subgraph to database
 */
async function syncTasks(): Promise<number> {
	if(!isDatabaseConfigured()) {
		return 0
	}

	const query = `
		query GetTasks($first: Int!, $skip: Int!) {
			tasks(first: $first, skip: $skip, orderBy: createdAt, orderDirection: desc) {
				id
				taskIndex
				taskHash
				provider
				claimHash
				owner
				status
				feePaid
				createdAt
				completedAt
				expiresAt
				createdBlock
				createdTxHash
			}
		}
	`

	let totalSynced = 0
	let skip = 0
	const first = 100

	const supabase = getSupabaseClient()

	while(true) {
		const result = await querySubgraph<TasksQueryResult>(query, { first, skip })
		if(!result?.tasks?.length) {
			break
		}

		const tasks = result.tasks

		// Upsert tasks to database
		for(const task of tasks) {
			const upsertData = {
				task_index: parseInt(task.taskIndex, 10),
				task_hash: task.taskHash,
				provider_name: task.provider,
				claim_hash: task.claimHash,
				owner_address: task.owner.toLowerCase(),
				status: task.status.toLowerCase(),
				fee_paid: task.feePaid,
				created_at: new Date(parseInt(task.createdAt, 10) * 1000).toISOString(),
				completed_at: task.completedAt ? new Date(parseInt(task.completedAt, 10) * 1000).toISOString() : null,
				expires_at: new Date(parseInt(task.expiresAt, 10) * 1000).toISOString(),
				block_number: parseInt(task.createdBlock, 10),
				tx_hash: task.createdTxHash,
			}

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			await (supabase.from('indexed_tasks') as any)
				.upsert(upsertData, { onConflict: 'task_index' })
		}

		totalSynced += tasks.length
		skip += first

		if(tasks.length < first) {
			break
		}
	}

	return totalSynced
}

/**
 * Sync global stats from subgraph
 */
async function syncGlobalStats(): Promise<void> {
	if(!isDatabaseConfigured()) {
		return
	}

	const query = `
		query GetGlobalStats {
			globalStats(id: "global") {
				totalTasks
				completedTasks
				totalOperators
				activeOperators
				totalFeesCollected
				totalFeesDistributed
				totalSlashingEvents
				totalWadsSlashed
			}
		}
	`

	const result = await querySubgraph<GlobalStatsQueryResult>(query)
	if(!result?.globalStats) {
		return
	}

	const stats = result.globalStats
	const supabase = getSupabaseClient()

	// Update system config with stats
	const configValues = [
		{ key: 'subgraph_total_tasks', value: stats.totalTasks },
		{ key: 'subgraph_completed_tasks', value: stats.completedTasks },
		{ key: 'subgraph_total_operators', value: stats.totalOperators },
		{ key: 'subgraph_active_operators', value: stats.activeOperators },
		{ key: 'subgraph_total_fees_collected', value: stats.totalFeesCollected },
		{ key: 'subgraph_total_fees_distributed', value: stats.totalFeesDistributed },
		{ key: 'subgraph_total_slashing_events', value: stats.totalSlashingEvents },
		{ key: 'subgraph_last_sync', value: new Date().toISOString() },
	]

	for(const config of configValues) {
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await (supabase.from('system_config') as any)
			.upsert({
				key: config.key,
				value: { data: config.value },
				updated_at: new Date().toISOString(),
			}, { onConflict: 'key' })
	}
}

/**
 * Run a full sync cycle
 */
export async function runSyncCycle(): Promise<{
	operators: number
	tasks: number
}> {
	console.log('[SYNC] Starting sync cycle...')

	const [operators, tasks] = await Promise.all([
		syncOperators(),
		syncTasks(),
	])

	await syncGlobalStats()

	console.log(`[SYNC] Completed: ${operators} operators, ${tasks} tasks`)

	return { operators, tasks }
}

/**
 * Start the sync service (runs continuously)
 */
export function startSyncService(): NodeJS.Timeout {
	console.log(`[SYNC] Starting sync service (interval: ${SYNC_INTERVAL_MS}ms)`)

	// Run immediately
	runSyncCycle().catch(err => console.error('[SYNC] Initial sync failed:', err))

	// Then run on interval
	return setInterval(() => {
		runSyncCycle().catch(err => console.error('[SYNC] Sync cycle failed:', err))
	}, SYNC_INTERVAL_MS)
}

/**
 * Stop the sync service
 */
export function stopSyncService(timer: NodeJS.Timeout): void {
	clearInterval(timer)
	console.log('[SYNC] Sync service stopped')
}
