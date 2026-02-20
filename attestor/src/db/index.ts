/**
 * Database module for L{CORE}
 *
 * Provides Supabase client and type-safe database operations.
 */

export {
	getSupabaseClient,
	getPublicSupabaseClient,
	isDatabaseConfigured,
	testDatabaseConnection,
} from './client.ts'

export * from './types.ts'
