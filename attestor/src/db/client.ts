import type { SupabaseClient } from '@supabase/supabase-js'
import { createClient } from '@supabase/supabase-js'
import type { Database } from 'src/db/types.ts'

import { getEnvVariable } from '#src/utils/env.ts'

let supabaseClient: SupabaseClient<Database> | null = null

/**
 * Get the Supabase client instance.
 * Uses lazy initialization to avoid errors when env vars aren't set.
 */
export function getSupabaseClient(): SupabaseClient<Database> {
	if(!supabaseClient) {
		const supabaseUrl = getEnvVariable('SUPABASE_URL')
		const supabaseKey = getEnvVariable('SUPABASE_SERVICE_KEY')

		if(!supabaseUrl || !supabaseKey) {
			throw new Error(
				'Missing Supabase configuration. Set SUPABASE_URL and SUPABASE_SERVICE_KEY environment variables.'
			)
		}

		supabaseClient = createClient<Database>(supabaseUrl, supabaseKey, {
			auth: {
				autoRefreshToken: false,
				persistSession: false,
			},
		})
	}

	return supabaseClient
}

/**
 * Get an anonymous Supabase client for public queries.
 * Uses the anon key instead of service key.
 */
export function getPublicSupabaseClient(): SupabaseClient<Database> {
	const supabaseUrl = getEnvVariable('SUPABASE_URL')
	const supabaseAnonKey = getEnvVariable('SUPABASE_ANON_KEY')

	if(!supabaseUrl || !supabaseAnonKey) {
		throw new Error(
			'Missing Supabase configuration. Set SUPABASE_URL and SUPABASE_ANON_KEY environment variables.'
		)
	}

	return createClient<Database>(supabaseUrl, supabaseAnonKey, {
		auth: {
			autoRefreshToken: false,
			persistSession: false,
		},
	})
}

/**
 * Check if database is configured (synchronous check for env vars).
 */
export function isDatabaseConfigured(): boolean {
	try {
		const supabaseUrl = getEnvVariable('SUPABASE_URL')
		const supabaseKey = getEnvVariable('SUPABASE_SERVICE_KEY')
		return !!(supabaseUrl && supabaseKey)
	} catch{
		return false
	}
}

/**
 * Test database connection.
 */
export async function testDatabaseConnection(): Promise<{ ok: boolean, error?: string }> {
	try {
		const client = getSupabaseClient()
		const { error } = await client.from('system_config').select('key').limit(1)

		if(error) {
			return { ok: false, error: error.message }
		}

		return { ok: true }
	} catch(err) {
		return { ok: false, error: err instanceof Error ? err.message : 'Unknown error' }
	}
}
