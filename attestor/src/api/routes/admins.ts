/**
 * Admin management API routes
 *
 * GET    /api/admins           - List all admins (admin+)
 * POST   /api/admins           - Create new admin (super_admin only)
 * GET    /api/admins/:id       - Get admin details (admin+)
 * PUT    /api/admins/:id/role  - Update admin role (super_admin only)
 * DELETE /api/admins/:id       - Delete admin (super_admin only)
 * POST   /api/admins/:id/revoke-sessions - Revoke all sessions (super_admin only)
 */

import type { IncomingMessage, ServerResponse } from 'http'
import { getClientInfo, parseJsonBody, sendError, sendJson } from '#src/api/utils/http.ts'

import {
	auditFromRequest,
	deleteAdmin,
	getAdminById,
	listAdmins,
	registerAdmin,
	requireAdmin,
	requireSuperAdmin,
	revokeAllSessions,
	updateAdminRole,
} from '#src/api/auth/index.ts'
import type { AdminRole } from '#src/db/types.ts'

const VALID_ROLES: AdminRole[] = ['super_admin', 'admin', 'operator_manager', 'viewer']

/**
 * GET /api/admins
 * List all admins
 */
export async function handleListAdmins(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if(!authReq) {
		return
	}

	const admins = await listAdmins()
	sendJson(res, { admins })
}

/**
 * POST /api/admins
 * Create new admin
 */
export async function handleCreateAdmin(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireSuperAdmin(req, res)
	if(!authReq) {
		return
	}

	const body = await parseJsonBody<{
		walletAddress: string
		email?: string
		displayName?: string
		role: AdminRole
	}>(req)

	if(!body?.walletAddress || !body?.role) {
		return sendError(res, 400, 'walletAddress and role are required')
	}

	if(!VALID_ROLES.includes(body.role)) {
		return sendError(res, 400, `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}`)
	}

	const result = await registerAdmin({
		walletAddress: body.walletAddress,
		email: body.email,
		displayName: body.displayName,
		role: body.role,
		createdBy: authReq.admin.sub,
	})

	if(!result.success) {
		return sendError(res, 400, result.error)
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'admin.create', {
		resourceType: 'admin',
		resourceId: result.admin.id,
		details: {
			walletAddress: result.admin.walletAddress,
			role: result.admin.role,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, { admin: result.admin }, 201)
}

/**
 * GET /api/admins/:id
 * Get admin details
 */
export async function handleGetAdmin(
	req: IncomingMessage,
	res: ServerResponse,
	adminId: string
): Promise<void> {
	const authReq = await requireAdmin(req, res)
	if(!authReq) {
		return
	}

	const admin = await getAdminById(adminId)
	if(!admin) {
		return sendError(res, 404, 'Admin not found')
	}

	sendJson(res, { admin })
}

/**
 * PUT /api/admins/:id/role
 * Update admin role
 */
export async function handleUpdateRole(
	req: IncomingMessage,
	res: ServerResponse,
	adminId: string
): Promise<void> {
	const authReq = await requireSuperAdmin(req, res)
	if(!authReq) {
		return
	}

	const body = await parseJsonBody<{ role: AdminRole }>(req)

	if(!body?.role) {
		return sendError(res, 400, 'role is required')
	}

	if(!VALID_ROLES.includes(body.role)) {
		return sendError(res, 400, `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}`)
	}

	// Get current admin info for audit
	const targetAdmin = await getAdminById(adminId)
	if(!targetAdmin) {
		return sendError(res, 404, 'Admin not found')
	}

	const oldRole = targetAdmin.role

	const result = await updateAdminRole(adminId, body.role, authReq.admin.sub)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to update role')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'admin.role_change', {
		resourceType: 'admin',
		resourceId: adminId,
		details: {
			walletAddress: targetAdmin.walletAddress,
			oldRole,
			newRole: body.role,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, { success: true })
}

/**
 * DELETE /api/admins/:id
 * Delete admin
 */
export async function handleDeleteAdmin(
	req: IncomingMessage,
	res: ServerResponse,
	adminId: string
): Promise<void> {
	const authReq = await requireSuperAdmin(req, res)
	if(!authReq) {
		return
	}

	// Get admin info for audit before deletion
	const targetAdmin = await getAdminById(adminId)
	if(!targetAdmin) {
		return sendError(res, 404, 'Admin not found')
	}

	const result = await deleteAdmin(adminId, authReq.admin.sub)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to delete admin')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'admin.delete', {
		resourceType: 'admin',
		resourceId: adminId,
		details: {
			walletAddress: targetAdmin.walletAddress,
			role: targetAdmin.role,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, { success: true })
}

/**
 * POST /api/admins/:id/revoke-sessions
 * Revoke all sessions for an admin
 */
export async function handleRevokeSessions(
	req: IncomingMessage,
	res: ServerResponse,
	adminId: string
): Promise<void> {
	const authReq = await requireSuperAdmin(req, res)
	if(!authReq) {
		return
	}

	const targetAdmin = await getAdminById(adminId)
	if(!targetAdmin) {
		return sendError(res, 404, 'Admin not found')
	}

	const result = await revokeAllSessions(adminId)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to revoke sessions')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'session.revoke_all', {
		resourceType: 'admin',
		resourceId: adminId,
		details: { walletAddress: targetAdmin.walletAddress },
		ipAddress,
		userAgent,
	})

	sendJson(res, { success: true })
}

/**
 * Route handler for /api/admins/*
 */
export async function handleAdminsRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// /api/admins
	if(path === '/api/admins') {
		if(method === 'GET') {
			await handleListAdmins(req, res)
			return true
		}

		if(method === 'POST') {
			await handleCreateAdmin(req, res)
			return true
		}
	}

	// /api/admins/:id
	const adminIdMatch = path.match(/^\/api\/admins\/([a-f0-9-]+)$/)
	if(adminIdMatch) {
		const adminId = adminIdMatch[1]
		if(method === 'GET') {
			await handleGetAdmin(req, res, adminId)
			return true
		}

		if(method === 'DELETE') {
			await handleDeleteAdmin(req, res, adminId)
			return true
		}
	}

	// /api/admins/:id/role
	const roleMatch = path.match(/^\/api\/admins\/([a-f0-9-]+)\/role$/)
	if(roleMatch && method === 'PUT') {
		await handleUpdateRole(req, res, roleMatch[1])
		return true
	}

	// /api/admins/:id/revoke-sessions
	const revokeMatch = path.match(/^\/api\/admins\/([a-f0-9-]+)\/revoke-sessions$/)
	if(revokeMatch && method === 'POST') {
		await handleRevokeSessions(req, res, revokeMatch[1])
		return true
	}

	return false
}
