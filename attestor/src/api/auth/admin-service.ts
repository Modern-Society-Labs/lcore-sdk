/**
 * Admin service for managing admin users and sessions
 */

import type { JWTPayload, SessionToken } from 'src/api/auth/jwt.ts'
import { createJWT, generateSessionId, hashSessionToken } from 'src/api/auth/jwt.ts'
import { generateNonce, isValidAddress, normalizeAddress, verifyWalletSignature } from 'src/api/auth/wallet.ts'

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import type { Admin, AdminInsert, AdminRole, AdminSessionInsert } from '#src/db/types.ts'

export interface AdminInfo {
	id: string
	walletAddress: string
	email: string | null
	displayName: string | null
	role: AdminRole
	createdAt: Date
	lastLoginAt: Date | null
}

export interface LoginResult {
	success: boolean
	admin?: AdminInfo
	session?: SessionToken
	error?: string
}

export interface NonceResult {
	nonce: string
	expiresAt: Date
	message: string
}

/**
 * Request a nonce for wallet-based login
 */
export async function requestLoginNonce(
	walletAddress: string,
	domain: string
): Promise<NonceResult | { error: string }> {
	if(!isValidAddress(walletAddress)) {
		return { error: 'Invalid wallet address format' }
	}

	const normalizedAddress = normalizeAddress(walletAddress)

	try {
		const { nonce, expiresAt } = await generateNonce(normalizedAddress)

		// Generate the message to be signed
		const message = `Locale L{CORE} Admin Authentication

Domain: ${domain}
Address: ${normalizedAddress}
Nonce: ${nonce}
Issued At: ${new Date(expiresAt.getTime() - 5 * 60 * 1000).toISOString()}
Expires At: ${expiresAt.toISOString()}

Sign this message to authenticate as an admin.
This signature will not trigger any blockchain transaction.`

		return { nonce, expiresAt, message }
	} catch(err) {
		return { error: err instanceof Error ? err.message : 'Failed to generate nonce' }
	}
}

/**
 * Login with wallet signature
 */
export async function loginWithWallet(params: {
	walletAddress: string
	signature: string
	domain: string
	ipAddress?: string
	userAgent?: string
}): Promise<LoginResult> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	if(!isValidAddress(params.walletAddress)) {
		return { success: false, error: 'Invalid wallet address format' }
	}

	const normalizedAddress = normalizeAddress(params.walletAddress)

	// Verify signature
	const verification = await verifyWalletSignature({
		walletAddress: normalizedAddress,
		signature: params.signature,
		domain: params.domain,
	})

	if(!verification.success) {
		return { success: false, error: verification.error }
	}

	const supabase = getSupabaseClient()

	// Find admin by wallet address
	const { data: adminData, error: adminError } = await supabase
		.from('admins')
		.select('*')
		.eq('wallet_address', normalizedAddress.toLowerCase())
		.single()

	const admin = adminData as Admin | null

	if(adminError || !admin) {
		return { success: false, error: 'Admin not found. Contact a super admin to register.' }
	}

	// Create JWT session
	const session = createJWT({
		sub: admin.id,
		wallet: admin.wallet_address,
		role: admin.role,
		name: admin.display_name || undefined,
	})

	// Store session in database
	const tokenHash = hashSessionToken(session.token)

	const sessionInsert: AdminSessionInsert = {
		admin_id: admin.id,
		token_hash: tokenHash,
		hash_version: 1, // 1 = HMAC-SHA256, 2 = bcrypt (future)
		ip_address: params.ipAddress || null,
		user_agent: params.userAgent || null,
		expires_at: session.expiresAt.toISOString(),
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	await supabase.from('admin_sessions').insert(sessionInsert as any)

	// Update last login
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	await (supabase.from('admins') as any)
		.update({ last_login_at: new Date().toISOString() })
		.eq('id', admin.id)

	return {
		success: true,
		admin: {
			id: admin.id,
			walletAddress: admin.wallet_address,
			email: admin.email,
			displayName: admin.display_name,
			role: admin.role,
			createdAt: new Date(admin.created_at),
			lastLoginAt: new Date(),
		},
		session,
	}
}

/**
 * Get admin by ID
 */
export async function getAdminById(adminId: string): Promise<AdminInfo | null> {
	if(!isDatabaseConfigured()) {
		return null
	}

	const supabase = getSupabaseClient()
	const { data: adminData } = await supabase
		.from('admins')
		.select('*')
		.eq('id', adminId)
		.single()

	const admin = adminData as Admin | null

	if(!admin) {
		return null
	}

	return {
		id: admin.id,
		walletAddress: admin.wallet_address,
		email: admin.email,
		displayName: admin.display_name,
		role: admin.role,
		createdAt: new Date(admin.created_at),
		lastLoginAt: admin.last_login_at ? new Date(admin.last_login_at) : null,
	}
}

/**
 * Register a new admin (super_admin only)
 */
export async function registerAdmin(params: {
	walletAddress: string
	email?: string
	displayName?: string
	role: AdminRole
	createdBy: string
}): Promise<{ success: true, admin: AdminInfo } | { success: false, error: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	if(!isValidAddress(params.walletAddress)) {
		return { success: false, error: 'Invalid wallet address format' }
	}

	const supabase = getSupabaseClient()
	const normalizedAddress = normalizeAddress(params.walletAddress).toLowerCase()

	// Check if admin already exists
	const { data: existing } = await supabase
		.from('admins')
		.select('id')
		.eq('wallet_address', normalizedAddress)
		.single()

	if(existing) {
		return { success: false, error: 'Admin with this wallet address already exists' }
	}

	// Create admin
	const adminInsert: AdminInsert = {
		wallet_address: normalizedAddress,
		email: params.email || null,
		display_name: params.displayName || null,
		role: params.role,
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { data: adminData, error } = await (supabase.from('admins') as any)
		.insert(adminInsert)
		.select()
		.single()

	const admin = adminData as Admin | null

	if(error || !admin) {
		return { success: false, error: error?.message || 'Failed to create admin' }
	}

	return {
		success: true,
		admin: {
			id: admin.id,
			walletAddress: admin.wallet_address,
			email: admin.email,
			displayName: admin.display_name,
			role: admin.role,
			createdAt: new Date(admin.created_at),
			lastLoginAt: null,
		},
	}
}

/**
 * Update admin role (super_admin only)
 */
export async function updateAdminRole(
	adminId: string,
	newRole: AdminRole,
	updatedBy: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()

	// Can't demote self if super_admin
	if(adminId === updatedBy) {
		return { success: false, error: 'Cannot change your own role' }
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('admins') as any)
		.update({ role: newRole })
		.eq('id', adminId)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * Revoke admin session
 */
export async function revokeSession(
	tokenHash: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('admin_sessions') as any)
		.update({ revoked_at: new Date().toISOString() })
		.eq('token_hash', tokenHash)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * Revoke all sessions for an admin
 */
export async function revokeAllSessions(
	adminId: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('admin_sessions') as any)
		.update({ revoked_at: new Date().toISOString() })
		.eq('admin_id', adminId)
		.is('revoked_at', null)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * List all admins
 */
export async function listAdmins(): Promise<AdminInfo[]> {
	if(!isDatabaseConfigured()) {
		return []
	}

	const supabase = getSupabaseClient()
	const { data: adminsData } = await supabase
		.from('admins')
		.select('*')
		.order('created_at', { ascending: false })

	const admins = (adminsData || []) as Admin[]

	return admins.map(admin => ({
		id: admin.id,
		walletAddress: admin.wallet_address,
		email: admin.email,
		displayName: admin.display_name,
		role: admin.role,
		createdAt: new Date(admin.created_at),
		lastLoginAt: admin.last_login_at ? new Date(admin.last_login_at) : null,
	}))
}

/**
 * Delete admin (super_admin only)
 */
export async function deleteAdmin(
	adminId: string,
	deletedBy: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	// Can't delete self
	if(adminId === deletedBy) {
		return { success: false, error: 'Cannot delete yourself' }
	}

	const supabase = getSupabaseClient()

	// Revoke all sessions first
	await revokeAllSessions(adminId)

	// Delete admin
	const { error } = await supabase
		.from('admins')
		.delete()
		.eq('id', adminId)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}
