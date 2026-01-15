/**
 * API key management for programmatic access
 */

import { randomBytes } from 'crypto'
import { hashSessionToken } from 'src/api/auth/jwt.ts'

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import type { ApiKey, ApiKeyInsert } from '#src/db/types.ts'

export interface ApiKeyInfo {
	id: string
	name: string
	prefix: string
	permissions: string[]
	rateLimitPerMinute: number
	expiresAt: Date | null
	createdAt: Date
	lastUsedAt: Date | null
}

export interface CreateApiKeyResult {
	/** Full API key (only shown once) */
	key: string
	/** API key info */
	info: ApiKeyInfo
}

/**
 * Generate a new API key
 * Format: lc_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
 * Where lc = locale, first 8 chars are prefix, rest is secret
 */
function generateApiKey(): { key: string, prefix: string, hash: string } {
	const secret = randomBytes(32).toString('hex')
	const key = `lc_${secret}`
	const prefix = key.slice(0, 11) // lc_xxxxxxx (11 chars)
	const hash = hashSessionToken(key)

	return { key, prefix, hash }
}

/**
 * Create a new API key
 */
export async function createApiKey(params: {
	adminId: string
	name: string
	permissions?: string[]
	rateLimitPerMinute?: number
	expiresInDays?: number
}): Promise<CreateApiKeyResult | { error: string }> {
	if(!isDatabaseConfigured()) {
		return { error: 'Database not configured' }
	}

	const { key, prefix, hash } = generateApiKey()
	const supabase = getSupabaseClient()

	const expiresAt = params.expiresInDays
		? new Date(Date.now() + params.expiresInDays * 24 * 60 * 60 * 1000)
		: null

	const keyInsert: ApiKeyInsert = {
		admin_id: params.adminId,
		key_prefix: prefix,
		key_hash: hash,
		name: params.name,
		permissions: params.permissions || ['read'],
		rate_limit_per_minute: params.rateLimitPerMinute || 60,
		expires_at: expiresAt?.toISOString() || null,
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { data: keyData, error } = await (supabase.from('api_keys') as any)
		.insert(keyInsert)
		.select()
		.single()

	const data = keyData as ApiKey | null

	if(error || !data) {
		return { error: error?.message || 'Failed to create API key' }
	}

	return {
		key,
		info: {
			id: data.id,
			name: data.name,
			prefix: data.key_prefix,
			permissions: data.permissions as string[],
			rateLimitPerMinute: data.rate_limit_per_minute,
			expiresAt: data.expires_at ? new Date(data.expires_at) : null,
			createdAt: new Date(data.created_at),
			lastUsedAt: null,
		},
	}
}

/**
 * List API keys for an admin
 */
export async function listApiKeys(adminId: string): Promise<ApiKeyInfo[]> {
	if(!isDatabaseConfigured()) {
		return []
	}

	const supabase = getSupabaseClient()

	const { data: keysData } = await supabase
		.from('api_keys')
		.select('*')
		.eq('admin_id', adminId)
		.order('created_at', { ascending: false })

	const data = (keysData || []) as ApiKey[]

	return data.map(key => ({
		id: key.id,
		name: key.name,
		prefix: key.key_prefix,
		permissions: key.permissions as string[],
		rateLimitPerMinute: key.rate_limit_per_minute,
		expiresAt: key.expires_at ? new Date(key.expires_at) : null,
		createdAt: new Date(key.created_at),
		lastUsedAt: key.last_used_at ? new Date(key.last_used_at) : null,
	}))
}

/**
 * Revoke an API key
 */
export async function revokeApiKey(
	keyId: string,
	adminId: string
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()

	// Verify ownership
	const { data: keyData } = await supabase
		.from('api_keys')
		.select('admin_id')
		.eq('id', keyId)
		.single()

	const key = keyData as { admin_id: string } | null

	if(!key) {
		return { success: false, error: 'API key not found' }
	}

	if(key.admin_id !== adminId) {
		return { success: false, error: 'Not authorized to revoke this key' }
	}

	// Delete the key
	const { error } = await supabase
		.from('api_keys')
		.delete()
		.eq('id', keyId)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * Update API key permissions
 */
export async function updateApiKeyPermissions(
	keyId: string,
	adminId: string,
	permissions: string[]
): Promise<{ success: boolean, error?: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	const supabase = getSupabaseClient()

	// Verify ownership
	const { data: keyData } = await supabase
		.from('api_keys')
		.select('admin_id')
		.eq('id', keyId)
		.single()

	const key = keyData as { admin_id: string } | null

	if(!key) {
		return { success: false, error: 'API key not found' }
	}

	if(key.admin_id !== adminId) {
		return { success: false, error: 'Not authorized to update this key' }
	}

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('api_keys') as any)
		.update({ permissions })
		.eq('id', keyId)

	if(error) {
		return { success: false, error: error.message }
	}

	return { success: true }
}

/**
 * Available permissions for API keys
 */
export const API_KEY_PERMISSIONS = {
	// Read permissions
	'read': 'Read public data (operators, stats)',
	'read:operators': 'Read operator details',
	'read:tasks': 'Read task history',
	'read:analytics': 'Read analytics data',

	// Write permissions
	'write:operators': 'Manage operator whitelist',
	'write:config': 'Update system configuration',

	// Admin permissions
	'admin:users': 'Manage admin users',
	'admin:sessions': 'Manage sessions',

	// Wildcard
	'*': 'Full access (all permissions)',
} as const

export type ApiKeyPermission = keyof typeof API_KEY_PERMISSIONS
