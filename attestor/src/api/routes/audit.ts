/**
 * Audit log API routes
 *
 * GET /api/audit          - Query audit logs (admin+)
 * GET /api/audit/recent   - Get recent activity (admin+)
 * GET /api/audit/summary  - Get activity summary (admin+)
 */

import type { IncomingMessage, ServerResponse } from 'http'
import {
	queryAuditLogs,
	getRecentActivity,
	getActivitySummary,
	requireAdmin,
} from '#src/api/auth/index.ts'
import type { AuditAction } from '#src/api/auth/index.ts'
import { sendJson, sendError, parseQuery } from '../utils/http.ts'

/**
 * GET /api/audit
 * Query audit logs with filters
 */
export async function handleQueryAuditLogs(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if(!authReq) {
 return
}

	const query = parseQuery(req.url || '')

	const params: Parameters<typeof queryAuditLogs>[0] = {}

	if(query.adminId) {
		params.adminId = query.adminId
	}

	if(query.action) {
		params.action = query.action as AuditAction
	}

	if(query.resourceType) {
		params.resourceType = query.resourceType
	}

	if(query.resourceId) {
		params.resourceId = query.resourceId
	}

	if(query.startDate) {
		const date = new Date(query.startDate)
		if(!isNaN(date.getTime())) {
			params.startDate = date
		}
	}

	if(query.endDate) {
		const date = new Date(query.endDate)
		if(!isNaN(date.getTime())) {
			params.endDate = date
		}
	}

	if(query.limit) {
		const limit = parseInt(query.limit, 10)
		if(!isNaN(limit) && limit > 0 && limit <= 100) {
			params.limit = limit
		}
	}

	if(query.offset) {
		const offset = parseInt(query.offset, 10)
		if(!isNaN(offset) && offset >= 0) {
			params.offset = offset
		}
	}

	const result = await queryAuditLogs(params)
	sendJson(res, result)
}

/**
 * GET /api/audit/recent
 * Get recent activity
 */
export async function handleRecentActivity(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if(!authReq) {
 return
}

	const query = parseQuery(req.url || '')
	const limit = query.limit ? parseInt(query.limit, 10) : 10

	const logs = await getRecentActivity(Math.min(limit, 50))
	sendJson(res, { logs })
}

/**
 * GET /api/audit/summary
 * Get activity summary for a period
 */
export async function handleActivitySummary(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if(!authReq) {
 return
}

	const query = parseQuery(req.url || '')

	// Default to last 7 days
	const endDate = query.endDate ? new Date(query.endDate) : new Date()
	const startDate = query.startDate
		? new Date(query.startDate)
		: new Date(endDate.getTime() - 7 * 24 * 60 * 60 * 1000)

	if(isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
		return sendError(res, 400, 'Invalid date format')
	}

	const summary = await getActivitySummary(startDate, endDate)
	sendJson(res, {
		...summary,
		period: {
			start: startDate.toISOString(),
			end: endDate.toISOString(),
		},
	})
}

/**
 * Route handler for /api/audit/*
 */
export async function handleAuditRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	if(method !== 'GET') {
		return false
	}

	if(path === '/api/audit') {
		await handleQueryAuditLogs(req, res)
		return true
	}

	if(path === '/api/audit/recent') {
		await handleRecentActivity(req, res)
		return true
	}

	if(path === '/api/audit/summary') {
		await handleActivitySummary(req, res)
		return true
	}

	return false
}
