/**
 * Operator profile service
 *
 * Manages operator public profiles displayed on the platform.
 */

import { getSupabaseClient, isDatabaseConfigured } from '#src/db/index.ts'
import type { OperatorProfile, IndexedOperator } from '#src/db/types.ts'
import { isValidAddress, normalizeAddress } from '#src/api/auth/wallet.ts'

export interface OperatorInfo {
	walletAddress: string
	displayName: string | null
	description: string | null
	logoUrl: string | null
	bannerUrl: string | null
	website: string | null
	twitterHandle: string | null
	discordServer: string | null
	telegramGroup: string | null
	geographicRegions: string[] | null
	supportedProviders: string[] | null
	termsOfServiceUrl: string | null
	privacyPolicyUrl: string | null
	// From indexed_operators
	isWhitelisted: boolean
	isRegistered: boolean
	rpcUrl: string | null
	stakeWeight: string
}

export interface UpdateProfileParams {
	walletAddress: string
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
}

/**
 * Get operator profile with indexed data
 */
export async function getOperatorProfile(walletAddress: string): Promise<OperatorInfo | null> {
	if(!isDatabaseConfigured()) {
		return null
	}

	if(!isValidAddress(walletAddress)) {
		return null
	}

	const supabase = getSupabaseClient()
	const normalizedAddress = normalizeAddress(walletAddress).toLowerCase()

	// Get profile
	const { data: profileData } = await supabase
		.from('operator_profiles')
		.select('*')
		.eq('wallet_address', normalizedAddress)
		.single()

	const profile = profileData as OperatorProfile | null

	// Get indexed operator data
	const { data: operatorData } = await supabase
		.from('indexed_operators')
		.select('*')
		.eq('wallet_address', normalizedAddress)
		.single()

	const operator = operatorData as IndexedOperator | null

	// If neither exists, return null
	if(!profile && !operator) {
		return null
	}

	return {
		walletAddress: normalizedAddress,
		displayName: profile?.display_name || null,
		description: profile?.description || null,
		logoUrl: profile?.logo_url || null,
		bannerUrl: profile?.banner_url || null,
		website: profile?.website || null,
		twitterHandle: profile?.twitter_handle || null,
		discordServer: profile?.discord_server || null,
		telegramGroup: profile?.telegram_group || null,
		geographicRegions: profile?.geographic_regions as string[] | null,
		supportedProviders: profile?.supported_providers as string[] | null,
		termsOfServiceUrl: profile?.terms_of_service_url || null,
		privacyPolicyUrl: profile?.privacy_policy_url || null,
		isWhitelisted: operator?.is_whitelisted || false,
		isRegistered: operator?.is_registered || false,
		rpcUrl: operator?.rpc_url || null,
		stakeWeight: operator?.stake_weight || '0',
	}
}

/**
 * Update operator profile
 */
export async function updateOperatorProfile(
	params: UpdateProfileParams
): Promise<{ success: true; profile: OperatorInfo } | { success: false; error: string }> {
	if(!isDatabaseConfigured()) {
		return { success: false, error: 'Database not configured' }
	}

	if(!isValidAddress(params.walletAddress)) {
		return { success: false, error: 'Invalid wallet address format' }
	}

	const supabase = getSupabaseClient()
	const normalizedAddress = normalizeAddress(params.walletAddress).toLowerCase()

	// Build update object (only include provided fields)
	const updateData: Record<string, unknown> = {
		updated_at: new Date().toISOString(),
	}

	if(params.displayName !== undefined) {
		updateData.display_name = params.displayName || null
	}
	if(params.description !== undefined) {
		updateData.description = params.description || null
	}
	if(params.logoUrl !== undefined) {
		updateData.logo_url = params.logoUrl || null
	}
	if(params.bannerUrl !== undefined) {
		updateData.banner_url = params.bannerUrl || null
	}
	if(params.website !== undefined) {
		updateData.website = params.website || null
	}
	if(params.twitterHandle !== undefined) {
		updateData.twitter_handle = params.twitterHandle || null
	}
	if(params.discordServer !== undefined) {
		updateData.discord_server = params.discordServer || null
	}
	if(params.telegramGroup !== undefined) {
		updateData.telegram_group = params.telegramGroup || null
	}
	if(params.geographicRegions !== undefined) {
		updateData.geographic_regions = params.geographicRegions
	}
	if(params.supportedProviders !== undefined) {
		updateData.supported_providers = params.supportedProviders
	}
	if(params.termsOfServiceUrl !== undefined) {
		updateData.terms_of_service_url = params.termsOfServiceUrl || null
	}
	if(params.privacyPolicyUrl !== undefined) {
		updateData.privacy_policy_url = params.privacyPolicyUrl || null
	}

	// Upsert profile
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const { error } = await (supabase.from('operator_profiles') as any)
		.upsert(
			{ wallet_address: normalizedAddress, ...updateData },
			{ onConflict: 'wallet_address' }
		)

	if(error) {
		return { success: false, error: error.message }
	}

	// Fetch updated profile
	const profile = await getOperatorProfile(normalizedAddress)
	if(!profile) {
		return { success: false, error: 'Failed to fetch updated profile' }
	}

	return { success: true, profile }
}

/**
 * List all operators (with optional filters)
 */
export async function listOperators(params: {
	whitelistedOnly?: boolean
	registeredOnly?: boolean
	limit?: number
	offset?: number
}): Promise<{ operators: OperatorInfo[]; total: number }> {
	if(!isDatabaseConfigured()) {
		return { operators: [], total: 0 }
	}

	const supabase = getSupabaseClient()

	// Query indexed operators first (source of truth for whitelist/registration)
	let query = supabase.from('indexed_operators').select('*', { count: 'exact' })

	if(params.whitelistedOnly) {
		query = query.eq('is_whitelisted', true)
	}

	if(params.registeredOnly) {
		query = query.eq('is_registered', true)
	}

	query = query.order('stake_weight', { ascending: false })

	if(params.limit) {
		query = query.limit(params.limit)
	}

	if(params.offset) {
		query = query.range(params.offset, params.offset + (params.limit || 50) - 1)
	}

	const { data: operatorsData, count, error } = await query

	if(error) {
		console.error('[OPERATORS QUERY ERROR]', error)
		return { operators: [], total: 0 }
	}

	const operators = (operatorsData || []) as IndexedOperator[]

	// Get profiles for these operators
	const walletAddresses = operators.map(o => o.wallet_address)

	const { data: profilesData } = await supabase
		.from('operator_profiles')
		.select('*')
		.in('wallet_address', walletAddresses)

	const profiles = (profilesData || []) as OperatorProfile[]
	const profileMap = new Map(profiles.map(p => [p.wallet_address, p]))

	// Combine data
	const result: OperatorInfo[] = operators.map(operator => {
		const profile = profileMap.get(operator.wallet_address)
		return {
			walletAddress: operator.wallet_address,
			displayName: profile?.display_name || null,
			description: profile?.description || null,
			logoUrl: profile?.logo_url || null,
			bannerUrl: profile?.banner_url || null,
			website: profile?.website || null,
			twitterHandle: profile?.twitter_handle || null,
			discordServer: profile?.discord_server || null,
			telegramGroup: profile?.telegram_group || null,
			geographicRegions: profile?.geographic_regions as string[] | null,
			supportedProviders: profile?.supported_providers as string[] | null,
			termsOfServiceUrl: profile?.terms_of_service_url || null,
			privacyPolicyUrl: profile?.privacy_policy_url || null,
			isWhitelisted: operator.is_whitelisted,
			isRegistered: operator.is_registered,
			rpcUrl: operator.rpc_url,
			stakeWeight: operator.stake_weight,
		}
	})

	return { operators: result, total: count || 0 }
}

/**
 * Get operator statistics
 */
export async function getOperatorStats(): Promise<{
	totalWhitelisted: number
	totalRegistered: number
	totalStake: string
}> {
	if(!isDatabaseConfigured()) {
		return { totalWhitelisted: 0, totalRegistered: 0, totalStake: '0' }
	}

	const supabase = getSupabaseClient()

	const { data } = await supabase
		.from('indexed_operators')
		.select('is_whitelisted, is_registered, stake_weight')

	const operators = (data || []) as Array<{
		is_whitelisted: boolean
		is_registered: boolean
		stake_weight: string
	}>

	let totalWhitelisted = 0
	let totalRegistered = 0
	let totalStake = BigInt(0)

	for(const op of operators) {
		if(op.is_whitelisted) {
			totalWhitelisted++
		}
		if(op.is_registered) {
			totalRegistered++
		}
		try {
			totalStake += BigInt(op.stake_weight || '0')
		} catch {
			// Ignore invalid stake values
		}
	}

	return {
		totalWhitelisted,
		totalRegistered,
		totalStake: totalStake.toString(),
	}
}
