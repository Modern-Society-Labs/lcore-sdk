/**
 * Database types for Supabase
 * Generated from schema.sql
 *
 * Run `npx supabase gen types typescript` to regenerate from live schema.
 */

export type Json =
	| string
	| number
	| boolean
	| null
	| { [key: string]: Json | undefined }
	| Json[]

export type AdminRole = 'super_admin' | 'admin' | 'operator_manager' | 'viewer'
export type ApplicationStatus = 'pending' | 'under_review' | 'approved' | 'rejected' | 'withdrawn'
export type TaskStatus = 'pending' | 'completed' | 'expired' | 'challenged' | 'slashed'
export type AlertSeverity = 'info' | 'warning' | 'error' | 'critical'

// Individual table types for direct use
export interface Admin {
	id: string
	wallet_address: string
	email: string | null
	display_name: string | null
	role: AdminRole
	is_active: boolean
	email_verified: boolean
	created_at: string
	updated_at: string
	last_login_at: string | null
}

export interface AdminInsert {
	id?: string
	wallet_address: string
	email?: string | null
	display_name?: string | null
	role?: AdminRole
	is_active?: boolean
	email_verified?: boolean
	created_at?: string
	updated_at?: string
	last_login_at?: string | null
}

export interface AdminUpdate {
	id?: string
	wallet_address?: string
	email?: string | null
	display_name?: string | null
	role?: AdminRole
	is_active?: boolean
	email_verified?: boolean
	created_at?: string
	updated_at?: string
	last_login_at?: string | null
}

export interface AdminSession {
	id: string
	admin_id: string
	token_hash: string
	ip_address: string | null
	user_agent: string | null
	expires_at: string
	created_at: string
	revoked_at: string | null
}

export interface AdminSessionInsert {
	id?: string
	admin_id: string
	token_hash: string
	ip_address?: string | null
	user_agent?: string | null
	expires_at: string
	created_at?: string
	revoked_at?: string | null
}

export interface ApiKey {
	id: string
	admin_id: string
	name: string
	key_prefix: string
	key_hash: string
	permissions: Json
	rate_limit_per_minute: number
	last_used_at: string | null
	expires_at: string | null
	is_active: boolean
	created_at: string
}

export interface ApiKeyInsert {
	id?: string
	admin_id: string
	name: string
	key_prefix: string
	key_hash: string
	permissions?: Json
	rate_limit_per_minute?: number
	last_used_at?: string | null
	expires_at?: string | null
	is_active?: boolean
	created_at?: string
}

export interface AuditLog {
	id: string
	admin_id: string | null
	action: string
	resource_type: string | null
	resource_id: string | null
	details: Json | null
	ip_address: string | null
	user_agent: string | null
	tx_hash: string | null
	created_at: string
}

export interface AuditLogInsert {
	id?: string
	admin_id?: string | null
	action: string
	resource_type?: string | null
	resource_id?: string | null
	details?: Json | null
	ip_address?: string | null
	user_agent?: string | null
	tx_hash?: string | null
	created_at?: string
}

export interface OperatorApplication {
	id: string
	wallet_address: string
	company_name: string | null
	contact_email: string
	contact_telegram: string | null
	contact_discord: string | null
	website: string | null
	infrastructure_details: Json | null
	motivation: string | null
	status: ApplicationStatus
	reviewed_by: string | null
	reviewed_at: string | null
	review_notes: string | null
	rejection_reason: string | null
	created_at: string
	updated_at: string
}

export interface OperatorApplicationInsert {
	id?: string
	wallet_address: string
	company_name?: string | null
	contact_email: string
	contact_telegram?: string | null
	contact_discord?: string | null
	website?: string | null
	infrastructure_details?: Json | null
	motivation?: string | null
	status?: ApplicationStatus
	reviewed_by?: string | null
	reviewed_at?: string | null
	review_notes?: string | null
	rejection_reason?: string | null
	created_at?: string
	updated_at?: string
}

export interface OperatorProfile {
	wallet_address: string
	display_name: string | null
	description: string | null
	logo_url: string | null
	banner_url: string | null
	website: string | null
	twitter_handle: string | null
	discord_server: string | null
	telegram_group: string | null
	geographic_regions: Json | null
	supported_providers: Json | null
	terms_of_service_url: string | null
	privacy_policy_url: string | null
	created_at: string
	updated_at: string
}

export interface IndexedOperator {
	wallet_address: string
	is_whitelisted: boolean
	is_registered: boolean
	rpc_url: string | null
	stake_weight: string
	registration_block: number | null
	registration_tx: string | null
	whitelist_block: number | null
	whitelist_tx: string | null
	deregistration_block: number | null
	deregistration_tx: string | null
	last_synced_at: string
}

export interface IndexedTask {
	task_index: number
	task_hash: string
	owner_address: string
	provider_name: string | null
	claim_hash: string | null
	claim_user_id: string | null
	fee_paid: string | null
	status: TaskStatus
	created_block: number | null
	created_tx: string | null
	created_at: string | null
	expires_at: string | null
	completed_block: number | null
	completed_tx: string | null
	completed_at: string | null
	assigned_operators: Json | null
	signatures_received: number
	last_synced_at: string
}

export interface IndexedSlashingEvent {
	id: string
	task_index: number
	operator_address: string
	challenger_address: string | null
	wads_slashed: string | null
	reason: string | null
	block_number: number | null
	tx_hash: string | null
	created_at: string | null
	last_synced_at: string
}

export interface DailyMetrics {
	date: string
	total_tasks_created: number
	total_tasks_completed: number
	total_tasks_expired: number
	total_fees_collected: string
	total_fees_distributed: string
	active_operators: number
	total_stake_weight: string
	avg_completion_time_seconds: number | null
	unique_claim_creators: number
	slashing_events: number
	created_at: string
}

export interface SystemConfig {
	key: string
	value: Json
	description: string | null
	is_public: boolean
	updated_by: string | null
	updated_at: string
}

export interface FeatureFlag {
	name: string
	enabled: boolean
	description: string | null
	rollout_percentage: number
	updated_by: string | null
	updated_at: string
}

// Database interface for Supabase client typing
export interface Database {
	public: {
		Tables: {
			admins: {
				Row: Admin
				Insert: AdminInsert
				Update: AdminUpdate
				Relationships: []
			}
			admin_sessions: {
				Row: AdminSession
				Insert: AdminSessionInsert
				Update: Partial<AdminSession>
				Relationships: [
					{
						foreignKeyName: 'admin_sessions_admin_id_fkey'
						columns: ['admin_id']
						referencedRelation: 'admins'
						referencedColumns: ['id']
					}
				]
			}
			api_keys: {
				Row: ApiKey
				Insert: ApiKeyInsert
				Update: Partial<ApiKey>
				Relationships: [
					{
						foreignKeyName: 'api_keys_admin_id_fkey'
						columns: ['admin_id']
						referencedRelation: 'admins'
						referencedColumns: ['id']
					}
				]
			}
			audit_logs: {
				Row: AuditLog
				Insert: AuditLogInsert
				Update: Partial<AuditLog>
				Relationships: [
					{
						foreignKeyName: 'audit_logs_admin_id_fkey'
						columns: ['admin_id']
						referencedRelation: 'admins'
						referencedColumns: ['id']
					}
				]
			}
			operator_applications: {
				Row: OperatorApplication
				Insert: OperatorApplicationInsert
				Update: Partial<OperatorApplication>
				Relationships: [
					{
						foreignKeyName: 'operator_applications_reviewed_by_fkey'
						columns: ['reviewed_by']
						referencedRelation: 'admins'
						referencedColumns: ['id']
					}
				]
			}
			operator_profiles: {
				Row: OperatorProfile
				Insert: Partial<OperatorProfile> & { wallet_address: string }
				Update: Partial<OperatorProfile>
				Relationships: []
			}
			indexed_operators: {
				Row: IndexedOperator
				Insert: Partial<IndexedOperator> & { wallet_address: string }
				Update: Partial<IndexedOperator>
				Relationships: []
			}
			indexed_tasks: {
				Row: IndexedTask
				Insert: Partial<IndexedTask> & { task_index: number; task_hash: string; owner_address: string }
				Update: Partial<IndexedTask>
				Relationships: []
			}
			indexed_slashing_events: {
				Row: IndexedSlashingEvent
				Insert: Partial<IndexedSlashingEvent> & { task_index: number; operator_address: string }
				Update: Partial<IndexedSlashingEvent>
				Relationships: []
			}
			daily_metrics: {
				Row: DailyMetrics
				Insert: Partial<DailyMetrics> & { date: string }
				Update: Partial<DailyMetrics>
				Relationships: []
			}
			system_config: {
				Row: SystemConfig
				Insert: Partial<SystemConfig> & { key: string; value: Json }
				Update: Partial<SystemConfig>
				Relationships: []
			}
			feature_flags: {
				Row: FeatureFlag
				Insert: Partial<FeatureFlag> & { name: string }
				Update: Partial<FeatureFlag>
				Relationships: []
			}
		}
		Views: {
			[_ in never]: never
		}
		Functions: {
			[_ in never]: never
		}
		Enums: {
			admin_role: AdminRole
			application_status: ApplicationStatus
			task_status: TaskStatus
		}
		CompositeTypes: {
			[_ in never]: never
		}
	}
}

// Type helpers for Supabase queries
export type Tables<T extends keyof Database['public']['Tables']> = Database['public']['Tables'][T]['Row']
export type TablesInsert<T extends keyof Database['public']['Tables']> = Database['public']['Tables'][T]['Insert']
export type TablesUpdate<T extends keyof Database['public']['Tables']> = Database['public']['Tables'][T]['Update']
