/**
 * Operator API routes
 *
 * Public:
 * GET  /api/operators              - List operators
 * GET  /api/operators/:address     - Get operator profile
 * GET  /api/operators/stats        - Get operator statistics
 *
 * Authenticated (operator):
 * POST /api/operators/apply        - Submit application
 * GET  /api/operators/application  - Get my application status
 * POST /api/operators/application/withdraw - Withdraw application
 * PUT  /api/operators/profile      - Update my profile
 *
 * Admin:
 * GET  /api/operators/applications           - List all applications
 * GET  /api/operators/applications/stats     - Application statistics
 * GET  /api/operators/applications/:id       - Get application details
 * POST /api/operators/applications/:id/review - Start review
 * POST /api/operators/applications/:id/approve - Approve application
 * POST /api/operators/applications/:id/reject  - Reject application
 */

import type { IncomingMessage, ServerResponse } from 'http'
import {
	submitApplication,
	getApplicationById,
	getApplicationByWallet,
	listApplications,
	startReview,
	reviewApplication,
	withdrawApplication,
	getApplicationStats,
} from '#src/api/operators/application-service.ts'
import {
	getOperatorProfile,
	updateOperatorProfile,
	listOperators,
	getOperatorStats,
} from '#src/api/operators/profile-service.ts'
import {
	createAuthMiddleware,
	requireOperatorManager,
	auditFromRequest,
} from '#src/api/auth/index.ts'
import type { ApplicationStatus } from '#src/db/types.ts'
import { parseJsonBody, sendJson, sendError, parseQuery, getClientInfo } from '../utils/http.ts'

const auth = createAuthMiddleware()

// ============================================================================
// Public endpoints
// ============================================================================

/**
 * GET /api/operators
 * List operators (public)
 */
export async function handleListOperators(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const query = parseQuery(req.url || '')

	const params = {
		whitelistedOnly: query.whitelisted === 'true',
		registeredOnly: query.registered === 'true',
		limit: query.limit ? parseInt(query.limit, 10) : undefined,
		offset: query.offset ? parseInt(query.offset, 10) : undefined,
	}

	const result = await listOperators(params)
	sendJson(res, result)
}

/**
 * GET /api/operators/stats
 * Get operator statistics (public)
 */
export async function handleOperatorStats(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const stats = await getOperatorStats()
	sendJson(res, stats)
}

/**
 * GET /api/operators/:address
 * Get operator profile (public)
 */
export async function handleGetOperator(
	req: IncomingMessage,
	res: ServerResponse,
	address: string
): Promise<void> {
	const profile = await getOperatorProfile(address)

	if(!profile) {
		return sendError(res, 404, 'Operator not found')
	}

	sendJson(res, { operator: profile })
}

// ============================================================================
// Authenticated operator endpoints
// ============================================================================

/**
 * POST /api/operators/apply
 * Submit operator application
 */
export async function handleSubmitApplication(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const body = await parseJsonBody<{
		walletAddress: string
		companyName?: string
		contactEmail: string
		contactTelegram?: string
		contactDiscord?: string
		website?: string
		infrastructureDetails?: Record<string, unknown>
		motivation?: string
	}>(req)

	if(!body?.walletAddress || !body?.contactEmail) {
		return sendError(res, 400, 'walletAddress and contactEmail are required')
	}

	const result = await submitApplication(body)

	if(!result.success) {
		return sendError(res, 400, result.error)
	}

	sendJson(res, { application: result.application }, 201)
}

/**
 * GET /api/operators/application
 * Get my application status (requires auth)
 */
export async function handleGetMyApplication(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const application = await getApplicationByWallet(authReq.admin.wallet)

	if(!application) {
		return sendError(res, 404, 'No application found for your wallet address')
	}

	sendJson(res, { application })
}

/**
 * POST /api/operators/application/withdraw
 * Withdraw my application
 */
export async function handleWithdrawApplication(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const body = await parseJsonBody<{ applicationId: string }>(req)

	if(!body?.applicationId) {
		return sendError(res, 400, 'applicationId is required')
	}

	const result = await withdrawApplication(body.applicationId, authReq.admin.wallet)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to withdraw application')
	}

	sendJson(res, { success: true })
}

/**
 * PUT /api/operators/profile
 * Update my operator profile
 */
export async function handleUpdateProfile(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await auth(req, res)
	if(!authReq) {
 return
}

	const body = await parseJsonBody<{
		displayName?: string
		description?: string
		logoUrl?: string
		bannerUrl?: string
		website?: string
		twitterHandle?: string
		discordServer?: string
		telegramGroup?: string
		geographicRegions?: string[]
		supportedProviders?: string[]
		termsOfServiceUrl?: string
		privacyPolicyUrl?: string
	}>(req)

	if(!body) {
		return sendError(res, 400, 'Request body is required')
	}

	const result = await updateOperatorProfile({
		walletAddress: authReq.admin.wallet,
		...body,
	})

	if(!result.success) {
		return sendError(res, 400, result.error)
	}

	sendJson(res, { profile: result.profile })
}

// ============================================================================
// Admin endpoints
// ============================================================================

/**
 * GET /api/operators/applications
 * List all applications (admin)
 */
export async function handleListApplications(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireOperatorManager(req, res)
	if(!authReq) {
 return
}

	const query = parseQuery(req.url || '')

	const params = {
		status: query.status as ApplicationStatus | undefined,
		limit: query.limit ? parseInt(query.limit, 10) : undefined,
		offset: query.offset ? parseInt(query.offset, 10) : undefined,
	}

	const result = await listApplications(params)
	sendJson(res, result)
}

/**
 * GET /api/operators/applications/stats
 * Get application statistics (admin)
 */
export async function handleApplicationStats(
	req: IncomingMessage,
	res: ServerResponse
): Promise<void> {
	const authReq = await requireOperatorManager(req, res)
	if(!authReq) {
 return
}

	const stats = await getApplicationStats()
	sendJson(res, stats)
}

/**
 * GET /api/operators/applications/:id
 * Get application details (admin)
 */
export async function handleGetApplication(
	req: IncomingMessage,
	res: ServerResponse,
	applicationId: string
): Promise<void> {
	const authReq = await requireOperatorManager(req, res)
	if(!authReq) {
 return
}

	const application = await getApplicationById(applicationId)

	if(!application) {
		return sendError(res, 404, 'Application not found')
	}

	sendJson(res, { application })
}

/**
 * POST /api/operators/applications/:id/review
 * Start review of application (admin)
 */
export async function handleStartReview(
	req: IncomingMessage,
	res: ServerResponse,
	applicationId: string
): Promise<void> {
	const authReq = await requireOperatorManager(req, res)
	if(!authReq) {
 return
}

	const result = await startReview(applicationId, authReq.admin.sub)

	if(!result.success) {
		return sendError(res, 400, result.error || 'Failed to start review')
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'operator.application_approve', {
		resourceType: 'operator_application',
		resourceId: applicationId,
		details: { action: 'start_review' },
		ipAddress,
		userAgent,
	})

	sendJson(res, { success: true })
}

/**
 * POST /api/operators/applications/:id/approve
 * Approve application (admin)
 */
export async function handleApproveApplication(
	req: IncomingMessage,
	res: ServerResponse,
	applicationId: string
): Promise<void> {
	const authReq = await requireOperatorManager(req, res)
	if(!authReq) {
 return
}

	const body = await parseJsonBody<{ notes?: string }>(req)

	const result = await reviewApplication({
		applicationId,
		reviewerId: authReq.admin.sub,
		action: 'approve',
		notes: body?.notes,
	})

	if(!result.success) {
		return sendError(res, 400, result.error)
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'operator.application_approve', {
		resourceType: 'operator_application',
		resourceId: applicationId,
		details: {
			walletAddress: result.application.walletAddress,
			notes: body?.notes,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, { application: result.application })
}

/**
 * POST /api/operators/applications/:id/reject
 * Reject application (admin)
 */
export async function handleRejectApplication(
	req: IncomingMessage,
	res: ServerResponse,
	applicationId: string
): Promise<void> {
	const authReq = await requireOperatorManager(req, res)
	if(!authReq) {
 return
}

	const body = await parseJsonBody<{
		notes?: string
		rejectionReason: string
	}>(req)

	if(!body?.rejectionReason) {
		return sendError(res, 400, 'rejectionReason is required')
	}

	const result = await reviewApplication({
		applicationId,
		reviewerId: authReq.admin.sub,
		action: 'reject',
		notes: body.notes,
		rejectionReason: body.rejectionReason,
	})

	if(!result.success) {
		return sendError(res, 400, result.error)
	}

	const { ipAddress, userAgent } = getClientInfo(req)
	await auditFromRequest(authReq.admin, 'operator.application_reject', {
		resourceType: 'operator_application',
		resourceId: applicationId,
		details: {
			walletAddress: result.application.walletAddress,
			rejectionReason: body.rejectionReason,
		},
		ipAddress,
		userAgent,
	})

	sendJson(res, { application: result.application })
}

/**
 * Route handler for /api/operators/*
 */
export async function handleOperatorsRoute(
	req: IncomingMessage,
	res: ServerResponse,
	path: string
): Promise<boolean> {
	const method = req.method?.toUpperCase()

	// Public: GET /api/operators
	if(path === '/api/operators' && method === 'GET') {
		await handleListOperators(req, res)
		return true
	}

	// Public: GET /api/operators/stats
	if(path === '/api/operators/stats' && method === 'GET') {
		await handleOperatorStats(req, res)
		return true
	}

	// Operator: POST /api/operators/apply
	if(path === '/api/operators/apply' && method === 'POST') {
		await handleSubmitApplication(req, res)
		return true
	}

	// Operator: GET /api/operators/application
	if(path === '/api/operators/application' && method === 'GET') {
		await handleGetMyApplication(req, res)
		return true
	}

	// Operator: POST /api/operators/application/withdraw
	if(path === '/api/operators/application/withdraw' && method === 'POST') {
		await handleWithdrawApplication(req, res)
		return true
	}

	// Operator: PUT /api/operators/profile
	if(path === '/api/operators/profile' && method === 'PUT') {
		await handleUpdateProfile(req, res)
		return true
	}

	// Admin: GET /api/operators/applications
	if(path === '/api/operators/applications' && method === 'GET') {
		await handleListApplications(req, res)
		return true
	}

	// Admin: GET /api/operators/applications/stats
	if(path === '/api/operators/applications/stats' && method === 'GET') {
		await handleApplicationStats(req, res)
		return true
	}

	// Admin: GET /api/operators/applications/:id
	const appIdMatch = path.match(/^\/api\/operators\/applications\/([a-f0-9-]+)$/)
	if(appIdMatch && method === 'GET') {
		await handleGetApplication(req, res, appIdMatch[1])
		return true
	}

	// Admin: POST /api/operators/applications/:id/review
	const reviewMatch = path.match(/^\/api\/operators\/applications\/([a-f0-9-]+)\/review$/)
	if(reviewMatch && method === 'POST') {
		await handleStartReview(req, res, reviewMatch[1])
		return true
	}

	// Admin: POST /api/operators/applications/:id/approve
	const approveMatch = path.match(/^\/api\/operators\/applications\/([a-f0-9-]+)\/approve$/)
	if(approveMatch && method === 'POST') {
		await handleApproveApplication(req, res, approveMatch[1])
		return true
	}

	// Admin: POST /api/operators/applications/:id/reject
	const rejectMatch = path.match(/^\/api\/operators\/applications\/([a-f0-9-]+)\/reject$/)
	if(rejectMatch && method === 'POST') {
		await handleRejectApplication(req, res, rejectMatch[1])
		return true
	}

	// Public: GET /api/operators/:address
	const addressMatch = path.match(/^\/api\/operators\/(0x[a-fA-F0-9]{40})$/)
	if(addressMatch && method === 'GET') {
		await handleGetOperator(req, res, addressMatch[1])
		return true
	}

	return false
}
