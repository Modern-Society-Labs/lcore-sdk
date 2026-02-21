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

export type AdminRole = 'super_admin' | 'admin' | 'viewer'

// Individual table types for direct use

export interface AuthNonce {
	wallet_address: string
	nonce: string
	expires_at: string
	created_at: string
}

export interface AuthNonceInsert {
	wallet_address: string
	nonce: string
	expires_at: string
	created_at?: string
}

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
	hash_version: number
	ip_address: string | null
	user_agent: string | null
	expires_at: string
	created_at: string
	revoked_at: string | null
	last_refresh_at: string | null
}

export interface AdminSessionInsert {
	id?: string
	admin_id: string
	token_hash: string
	hash_version?: number
	ip_address?: string | null
	user_agent?: string | null
	expires_at: string
	created_at?: string
	revoked_at?: string | null
	last_refresh_at?: string | null
}

export interface ApiKey {
	id: string
	admin_id: string
	name: string
	key_prefix: string
	key_hash: string
	hash_version: number
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
	hash_version?: number
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
			auth_nonces: {
				Row: AuthNonce
				Insert: AuthNonceInsert
				Update: Partial<AuthNonce>
				Relationships: []
			}
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
			system_config: {
				Row: SystemConfig
				Insert: Partial<SystemConfig> & { key: string, value: Json }
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
