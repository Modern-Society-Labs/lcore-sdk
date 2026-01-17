/**
 * Audit logging for admin actions
 *
 * All admin actions should be logged for accountability and compliance.
 */

import type { JWTPayload } from '#src/api/auth/jwt.ts'

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import type { AuditLog } from '#src/db/types.ts'

export type AuditAction =
	// Admin management
	| 'admin.login'
	| 'admin.logout'
	| 'admin.create'
	| 'admin.update'
	| 'admin.delete'
	| 'admin.role_change'
	// Session management
	| 'session.revoke'
	| 'session.revoke_all'
	// API key management
	| 'api_key.create'
	| 'api_key.revoke'
	// Operator management
	| 'operator.whitelist'
	| 'operator.remove'
	| 'operator.application_approve'
	| 'operator.application_reject'
	// System configuration
	| 'config.update'
	| 'config.feature_flag'
	// Contract interactions
	| 'contract.update_fee'
	| 'contract.update_slashing'
	| 'contract.pause'
	| 'contract.unpause'
	| 'contract.distribute_fees'
	// Emergency actions
	| 'emergency.pause'
	| 'emergency.withdrawal'
	// L{CORE} management
	| 'lcore.add_schema_admin'
	| 'lcore.remove_schema_admin'
	| 'lcore.register_provider_schema'
	| 'lcore.deprecate_provider_schema'

export interface AuditLogEntry {
	adminId: string
	action: AuditAction
	resourceType?: string
	resourceId?: string
	details?: Record<string, unknown>
	ipAddress?: string
	userAgent?: string
	txHash?: string
}

/**
 * Create an audit log entry
 */
export async function createAuditLog(entry: AuditLogEntry): Promise<void> {
	if(!isDatabaseConfigured()) {
		// Log to console if database not configured
		console.log('[AUDIT]', JSON.stringify(entry))
		return
	}

	const supabase = getSupabaseClient()

	try {
		const logInsert = {
			admin_id: entry.adminId,
			action: entry.action,
			resource_type: entry.resourceType || null,
			resource_id: entry.resourceId || null,
			details: entry.details || null,
			ip_address: entry.ipAddress || null,
			user_agent: entry.userAgent || null,
			tx_hash: entry.txHash || null,
		}
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await supabase.from('audit_logs').insert(logInsert as any)
	} catch(err) {
		// Don't throw on audit log failure, but log the error
		console.error('[AUDIT ERROR]', err)
	}
}

/**
 * Create audit log from request context
 */
export function auditFromRequest(
	admin: JWTPayload,
	action: AuditAction,
	options: {
		resourceType?: string
		resourceId?: string
		details?: Record<string, unknown>
		ipAddress?: string
		userAgent?: string
		txHash?: string
	} = {}
): Promise<void> {
	return createAuditLog({
		adminId: admin.sub,
		action,
		...options,
	})
}

/**
 * Query audit logs
 */
export async function queryAuditLogs(params: {
	adminId?: string
	action?: AuditAction
	resourceType?: string
	resourceId?: string
	startDate?: Date
	endDate?: Date
	limit?: number
	offset?: number
}): Promise<{ logs: AuditLog[], total: number }> {
	if(!isDatabaseConfigured()) {
		return { logs: [], total: 0 }
	}

	const supabase = getSupabaseClient()
	let query = supabase.from('audit_logs').select('*', { count: 'exact' })

	if(params.adminId) {
		query = query.eq('admin_id', params.adminId)
	}

	if(params.action) {
		query = query.eq('action', params.action)
	}

	if(params.resourceType) {
		query = query.eq('resource_type', params.resourceType)
	}

	if(params.resourceId) {
		query = query.eq('resource_id', params.resourceId)
	}

	if(params.startDate) {
		query = query.gte('created_at', params.startDate.toISOString())
	}

	if(params.endDate) {
		query = query.lte('created_at', params.endDate.toISOString())
	}

	query = query.order('created_at', { ascending: false })

	if(params.limit) {
		query = query.limit(params.limit)
	}

	if(params.offset) {
		query = query.range(params.offset, params.offset + (params.limit || 50) - 1)
	}

	const { data, count, error } = await query

	if(error) {
		console.error('[AUDIT QUERY ERROR]', error)
		return { logs: [], total: 0 }
	}

	return { logs: (data || []) as AuditLog[], total: count || 0 }
}

/**
 * Get recent activity for dashboard
 */
export async function getRecentActivity(limit = 10): Promise<AuditLog[]> {
	if(!isDatabaseConfigured()) {
		return []
	}

	const supabase = getSupabaseClient()

	const { data } = await supabase
		.from('audit_logs')
		.select('*')
		.order('created_at', { ascending: false })
		.limit(limit)

	return (data || []) as AuditLog[]
}

/**
 * Get activity summary for a time period
 */
export async function getActivitySummary(startDate: Date, endDate: Date): Promise<{
	totalActions: number
	actionCounts: Record<string, number>
	activeAdmins: number
}> {
	if(!isDatabaseConfigured()) {
		return { totalActions: 0, actionCounts: {}, activeAdmins: 0 }
	}

	const supabase = getSupabaseClient()

	// Get all logs in period
	const { data, count } = await supabase
		.from('audit_logs')
		.select('action, admin_id', { count: 'exact' })
		.gte('created_at', startDate.toISOString())
		.lte('created_at', endDate.toISOString())

	const logs = (data || []) as Array<{ action: string, admin_id: string | null }>

	// Count actions
	const actionCounts: Record<string, number> = {}
	const uniqueAdmins = new Set<string>()

	for(const log of logs) {
		actionCounts[log.action] = (actionCounts[log.action] || 0) + 1
		if(log.admin_id) {
			uniqueAdmins.add(log.admin_id)
		}
	}

	return {
		totalActions: count || 0,
		actionCounts,
		activeAdmins: uniqueAdmins.size,
	}
}
