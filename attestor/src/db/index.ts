/**
 * Database module for Locale L{CORE} AVS
 *
 * Provides Supabase client and type-safe database operations.
 *
 * Data Classification:
 * - indexed_* tables: Read cache from on-chain events (synced via The Graph)
 * - admin_* tables: Internal platform administration
 * - operator_* tables: Operator management workflow
 * - analytics tables: Metrics and reporting
 */

export {
	getSupabaseClient,
	getPublicSupabaseClient,
	isDatabaseConfigured,
	testDatabaseConnection,
} from './client.ts'

export * from './types.ts'
