/**
 * Operator application service
 *
 * Handles the operator application workflow:
 * 1. Operator submits application with wallet address and details
 * 2. Admin reviews application
 * 3. Admin approves/rejects application
 * 4. On approval, operator is whitelisted on-chain
 */

import { isValidAddress, normalizeAddress } from '#src/api/auth/wallet.ts'
import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import type {
	ApplicationStatus,
	OperatorApplication,
	OperatorApplicationInsert,
	OperatorProfile,
} from '#src/db/types.ts'

export interface ApplicationInfo {
	id: string
	walletAddress: string
	companyName: string | null
	contactEmail: string
	contactTelegram: string | null
	contactDiscord: string | null
	website: string | null
	infrastructureDetails: Record<string, unknown> | null
	motivation: string | null
	status: ApplicationStatus
	reviewedBy: string | null
	reviewedAt: Date | null
	reviewNotes: string | null
	rejectionReason: string | null
	createdAt: Date
	updatedAt: Date
}

export interface SubmitApplicationParams {
	walletAddress: string
	companyName?: string
	contactEmail: string
	contactTelegram?: string
	contactDiscord?: string
	website?: string
	infrastructureDetails?: Record<string, unknown>
	motivation?: string
}

export interface ReviewApplicationParams {
	applicationId: string
	reviewerId: string
	action: 'approve' | 'reject'
	notes?: string
	rejectionReason?: string
}

/**
 * Convert database row to ApplicationInfo
 */
function toApplicationInfo(app: OperatorApplication): ApplicationInfo {
	return {
		id: app.id,
		walletAddress: app.wallet_address,
		companyName: app.company_name,
		contactEmail: app.contact_email,
		contactTelegram: app.contact_telegram,
		contactDiscord: app.contact_discord,
		website: app.website,
		infrastructureDetails: app.infrastructure_details as Record<string, unknown> | null,
		motivation: app.motivation,
		status: app.status,
		reviewedBy: app.reviewed_by,
		reviewedAt: app.reviewed_at ? new Date(app.reviewed_at) : null,
		reviewNotes: app.review_notes,
		rejectionReason: app.rejection_reason,
		createdAt: new Date(app.created_at),
		updatedAt: new Date(app.updated_at),
	}
}

/**
 * Submit a new operator application
 */
export async function submitApplication(
	params: SubmitApplicationParams
): Promise<{ success: true, application: ApplicationInfo } | { success: false, error: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	if(!isValidAddress(params.walletAddress)) {
		return { success: false, error: 'Invalid wallet address format' }
	}

	if(!params.contactEmail?.includes('@')) {
		return { success: false, error: 'Valid contact email is required' }
	}

	const supabase = getSupabaseClient()
	const normalizedAddress = normalizeAddress(params.walletAddress).toLowerCase()

	// Check if application already exists for this wallet
	const { data: existing } = await supabase
		.from('operator_applications')
		.select('id, status')
		.eq('wallet_address', normalizedAddress)
		.single()

	const existingApp = existing as { id: string, status: ApplicationStatus } | null

	if(existingApp) {
		if(existingApp.status === 'pending' || existingApp.status === 'under_review') {
			return { success: false, error: 'An application is already pending for this wallet address' }
		}

		if(existingApp.status === 'approved') {
			return { success: false, error: 'This wallet address has already been approved' }
		}
		// If rejected or withdrawn, allow reapplication
	}

	// Check if already whitelisted (in indexed_operators)
	const { data: operatorData } = await supabase
		.from('indexed_operators')
		.select('wallet_address, is_whitelisted')
		.eq('wallet_address', normalizedAddress)
		.single()

	const operator = operatorData as { wallet_address: string, is_whitelisted: boolean } | null

	if(operator?.is_whitelisted) {
		return { success: false, error: 'This wallet address is already whitelisted as an operator' }
	}

	// Create application
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const appInsert: any = {
		wallet_address: normalizedAddress,
		company_name: params.companyName || null,
		contact_email: params.contactEmail,
		contact_telegram: params.contactTelegram || null,
		contact_discord: params.contactDiscord || null,
		website: params.website || null,
		infrastructure_details: params.infrastructureDetails || null,
		motivation: params.motivation || null,
		status: 'pending',
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { data: appData, error } = await (supabase.from('operator_applications') as any)
		.insert(appInsert)
		.select()
		.single()

	const application = appData as OperatorApplication | null

	if(error || !application) {
		return { success: false, error: error?.message || 'Failed to submit application' }
	}

	return { success: true, application: toApplicationInfo(application) }
}

/**
 * Get application by ID
 */
export async function getApplicationById(applicationId: string): Promise<ApplicationInfo | null> {
	if(!isDatabaseConfigured()) {
		return null
	}

	const supabase = getSupabaseClient()
	const { data: appData } = await supabase
		.from('operator_applications')
		.select('*')
		.eq('id', applicationId)
		.single()

	const application = appData as OperatorApplication | null

	if(!application) {
		return null
	}

	return toApplicationInfo(application)
}

/**
 * Get application by wallet address
 */
export async function getApplicationByWallet(walletAddress: string): Promise<ApplicationInfo | null> {
	if(!isDatabaseConfigured()) {
		return null
	}

	if(!isValidAddress(walletAddress)) {
		return null
	}

	const supabase = getSupabaseClient()
	const normalizedAddress = normalizeAddress(walletAddress).toLowerCase()

	const { data: appData } = await supabase
		.from('operator_applications')
		.select('*')
		.eq('wallet_address', normalizedAddress)
		.order('created_at', { ascending: false })
		.limit(1)
		.single()

	const application = appData as OperatorApplication | null

	if(!application) {
		return null
	}

	return toApplicationInfo(application)
}

/**
 * List applications with filters
 */
export async function listApplications(params: {
	status?: ApplicationStatus
	limit?: number
	offset?: number
}): Promise<{ applications: ApplicationInfo[], total: number }> {
	if(!isDatabaseConfigured()) {
		return { applications: [], total: 0 }
	}

	const supabase = getSupabaseClient()
	let query = supabase.from('operator_applications').select('*', { count: 'exact' })

	if(params.status) {
		query = query.eq('status', params.status)
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
		console.error('[APPLICATION QUERY ERROR]', error)
		return { applications: [], total: 0 }
	}

	const applications = ((data || []) as OperatorApplication[]).map(toApplicationInfo)

	return { applications, total: count || 0 }
}

/**
 * Start review of an application
 */
export async function startReview(
	applicationId: string,
	reviewerId: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()

	// Check current status
	const { data: appData } = await supabase
		.from('operator_applications')
		.select('status')
		.eq('id', applicationId)
		.single()

	const app = appData as { status: ApplicationStatus } | null

	if(!app) {
		return { success: false, error: 'Application not found' }
	}

	if(app.status !== 'pending') {
		return { success: false, error: `Cannot start review: application is ${app.status}` }
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('operator_applications') as any)
		.update({
			status: 'under_review',
			reviewed_by: reviewerId,
			updated_at: new Date().toISOString(),
		})
		.eq('id', applicationId)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * Review and approve/reject an application
 */
export async function reviewApplication(
	params: ReviewApplicationParams
): Promise<{ success: true, application: ApplicationInfo } | { success: false, error: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()

	// Get current application
	const { data: appData } = await supabase
		.from('operator_applications')
		.select('*')
		.eq('id', params.applicationId)
		.single()

	const application = appData as OperatorApplication | null

	if(!application) {
		return { success: false, error: 'Application not found' }
	}

	if(application.status !== 'pending' && application.status !== 'under_review') {
		return { success: false, error: `Cannot review: application is ${application.status}` }
	}

	if(params.action === 'reject' && !params.rejectionReason) {
		return { success: false, error: 'Rejection reason is required' }
	}

	const newStatus: ApplicationStatus = params.action === 'approve' ? 'approved' : 'rejected'

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { data: updatedData, error } = await (supabase.from('operator_applications') as any)
		.update({
			status: newStatus,
			reviewed_by: params.reviewerId,
			reviewed_at: new Date().toISOString(),
			review_notes: params.notes || null,
			rejection_reason: params.action === 'reject' ? params.rejectionReason : null,
			updated_at: new Date().toISOString(),
		})
		.eq('id', params.applicationId)
		.select()
		.single()

	const updated = updatedData as OperatorApplication | null

	if(error || !updated) {
		return { success: false, error: error?.message || 'Failed to update application' }
	}

	// If approved, create operator profile
	if(params.action === 'approve') {
		const profileInsert = {
			wallet_address: application.wallet_address,
			display_name: application.company_name,
			website: application.website,
		}

		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		await (supabase.from('operator_profiles') as any)
			.upsert(profileInsert, { onConflict: 'wallet_address' })
	}

	return { success: true, application: toApplicationInfo(updated) }
}

/**
 * Withdraw an application (by the applicant)
 */
export async function withdrawApplication(
	applicationId: string,
	walletAddress: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()
	const normalizedAddress = normalizeAddress(walletAddress).toLowerCase()

	// Verify ownership and status
	const { data: appData } = await supabase
		.from('operator_applications')
		.select('wallet_address, status')
		.eq('id', applicationId)
		.single()

	const app = appData as { wallet_address: string, status: ApplicationStatus } | null

	if(!app) {
		return { success: false, error: 'Application not found' }
	}

	if(app.wallet_address !== normalizedAddress) {
		return { success: false, error: 'Not authorized to withdraw this application' }
	}

	if(app.status !== 'pending' && app.status !== 'under_review') {
		return { success: false, error: `Cannot withdraw: application is ${app.status}` }
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('operator_applications') as any)
		.update({
			status: 'withdrawn',
			updated_at: new Date().toISOString(),
		})
		.eq('id', applicationId)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * Get application statistics
 */
export async function getApplicationStats(): Promise<{
	pending: number
	underReview: number
	approved: number
	rejected: number
	withdrawn: number
	total: number
}> {
	if(!isDatabaseConfigured()) {
		return { pending: 0, underReview: 0, approved: 0, rejected: 0, withdrawn: 0, total: 0 }
	}

	const supabase = getSupabaseClient()

	const { data } = await supabase
		.from('operator_applications')
		.select('status')

	const apps = (data || []) as Array<{ status: ApplicationStatus }>

	const stats = {
		pending: 0,
		underReview: 0,
		approved: 0,
		rejected: 0,
		withdrawn: 0,
		total: apps.length,
	}

	for(const app of apps) {
		switch (app.status) {
		case 'pending':
			stats.pending++
			break
		case 'under_review':
			stats.underReview++
			break
		case 'approved':
			stats.approved++
			break
		case 'rejected':
			stats.rejected++
			break
		case 'withdrawn':
			stats.withdrawn++
			break
		}
	}

	return stats
}
