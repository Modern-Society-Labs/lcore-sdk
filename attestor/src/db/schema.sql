-- Locale L{CORE} AVS Database Schema
-- This schema is designed for Supabase (PostgreSQL)
--
-- Data Classification:
-- - indexed_* tables: Read cache from on-chain events (The Graph syncs here)
-- - admin_* tables: Internal platform administration
-- - operator_* tables: Operator management workflow
-- - analytics_* tables: Metrics and reporting

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- ADMIN AUTHENTICATION & AUTHORIZATION
-- =============================================================================

-- Admin roles enum
CREATE TYPE admin_role AS ENUM ('super_admin', 'admin', 'operator_manager', 'viewer');

-- Admin user accounts (wallet + email hybrid auth)
CREATE TABLE admins (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  wallet_address VARCHAR(42) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE,
  display_name VARCHAR(100),
  role admin_role NOT NULL DEFAULT 'viewer',
  is_active BOOLEAN DEFAULT true,
  email_verified BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

-- Create index for wallet lookups
CREATE INDEX idx_admins_wallet ON admins(wallet_address);
CREATE INDEX idx_admins_email ON admins(email);

-- Auth nonces for wallet signature verification (multi-node safe)
CREATE TABLE auth_nonces (
  wallet_address TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_auth_nonces_expires ON auth_nonces(expires_at);

-- Admin sessions (for JWT validation and revocation)
CREATE TABLE admin_sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash VARCHAR(128) NOT NULL, -- Increased for bcrypt hashes
  hash_version INT DEFAULT 1, -- 1 = HMAC-SHA256, 2 = bcrypt
  ip_address INET,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  last_refresh_at TIMESTAMPTZ -- For atomic refresh locking
);

CREATE INDEX idx_admin_sessions_admin ON admin_sessions(admin_id);
CREATE INDEX idx_admin_sessions_token ON admin_sessions(token_hash);

-- API keys for programmatic access
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  key_prefix VARCHAR(8) NOT NULL, -- First 8 chars for identification
  key_hash VARCHAR(128) NOT NULL, -- Increased for bcrypt hashes
  hash_version INT DEFAULT 1, -- 1 = HMAC-SHA256, 2 = bcrypt
  permissions JSONB DEFAULT '[]'::jsonb,
  rate_limit_per_minute INT DEFAULT 60,
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_api_keys_admin ON api_keys(admin_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- Audit logs for all admin actions
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(50),
  resource_id VARCHAR(100),
  details JSONB,
  ip_address INET,
  user_agent TEXT,
  tx_hash VARCHAR(66), -- If action resulted in on-chain transaction
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_admin ON audit_logs(admin_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

-- =============================================================================
-- OPERATOR MANAGEMENT (Pre-Chain Workflow)
-- =============================================================================

-- Application status enum
CREATE TYPE application_status AS ENUM ('pending', 'under_review', 'approved', 'rejected', 'withdrawn');

-- Operator applications (before on-chain whitelist)
CREATE TABLE operator_applications (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  wallet_address VARCHAR(42) NOT NULL,
  company_name VARCHAR(255),
  contact_email VARCHAR(255) NOT NULL,
  contact_telegram VARCHAR(100),
  contact_discord VARCHAR(100),
  website VARCHAR(500),
  infrastructure_details JSONB, -- Server specs, regions, etc.
  motivation TEXT,
  status application_status DEFAULT 'pending',
  reviewed_by UUID REFERENCES admins(id),
  reviewed_at TIMESTAMPTZ,
  review_notes TEXT,
  rejection_reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_operator_apps_wallet ON operator_applications(wallet_address);
CREATE INDEX idx_operator_apps_status ON operator_applications(status);
CREATE INDEX idx_operator_apps_created ON operator_applications(created_at DESC);

-- Operator profiles (additional metadata not stored on-chain)
CREATE TABLE operator_profiles (
  wallet_address VARCHAR(42) PRIMARY KEY,
  display_name VARCHAR(100),
  description TEXT,
  logo_url VARCHAR(500),
  banner_url VARCHAR(500),
  website VARCHAR(500),
  twitter_handle VARCHAR(50),
  discord_server VARCHAR(200),
  telegram_group VARCHAR(200),
  geographic_regions JSONB, -- Array of regions operator serves
  supported_providers JSONB, -- Array of provider types supported
  terms_of_service_url VARCHAR(500),
  privacy_policy_url VARCHAR(500),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- EVENT INDEX CACHE (Synced from The Graph / Chain Events)
-- =============================================================================

-- Indexed operators (cached from on-chain state)
CREATE TABLE indexed_operators (
  wallet_address VARCHAR(42) PRIMARY KEY,
  is_whitelisted BOOLEAN DEFAULT false,
  is_registered BOOLEAN DEFAULT false,
  rpc_url VARCHAR(500),
  stake_weight NUMERIC(78, 0) DEFAULT 0,
  registration_block BIGINT,
  registration_tx VARCHAR(66),
  whitelist_block BIGINT,
  whitelist_tx VARCHAR(66),
  deregistration_block BIGINT,
  deregistration_tx VARCHAR(66),
  last_synced_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_indexed_operators_whitelisted ON indexed_operators(is_whitelisted);
CREATE INDEX idx_indexed_operators_registered ON indexed_operators(is_registered);

-- Task status enum
CREATE TYPE task_status AS ENUM ('pending', 'completed', 'expired', 'challenged', 'slashed');

-- Indexed tasks (cached from NewTaskCreated events)
CREATE TABLE indexed_tasks (
  task_index INT PRIMARY KEY,
  task_hash VARCHAR(66) NOT NULL,
  owner_address VARCHAR(42) NOT NULL,
  provider_name VARCHAR(100),
  claim_hash VARCHAR(66),
  claim_user_id VARCHAR(255),
  fee_paid NUMERIC(78, 0),
  status task_status DEFAULT 'pending',
  created_block BIGINT,
  created_tx VARCHAR(66),
  created_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  completed_block BIGINT,
  completed_tx VARCHAR(66),
  completed_at TIMESTAMPTZ,
  assigned_operators JSONB, -- Array of operator addresses
  signatures_received INT DEFAULT 0,
  last_synced_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_indexed_tasks_owner ON indexed_tasks(owner_address);
CREATE INDEX idx_indexed_tasks_status ON indexed_tasks(status);
CREATE INDEX idx_indexed_tasks_created ON indexed_tasks(created_at DESC);
CREATE INDEX idx_indexed_tasks_provider ON indexed_tasks(provider_name);

-- Indexed slashing events
CREATE TABLE indexed_slashing_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  task_index INT NOT NULL,
  operator_address VARCHAR(42) NOT NULL,
  challenger_address VARCHAR(42),
  wads_slashed NUMERIC(78, 0),
  reason TEXT,
  block_number BIGINT,
  tx_hash VARCHAR(66),
  created_at TIMESTAMPTZ,
  last_synced_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(task_index, operator_address)
);

CREATE INDEX idx_slashing_operator ON indexed_slashing_events(operator_address);
CREATE INDEX idx_slashing_task ON indexed_slashing_events(task_index);

-- Indexed fee distributions
CREATE TABLE indexed_fee_distributions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  amount NUMERIC(78, 0) NOT NULL,
  start_timestamp TIMESTAMPTZ,
  duration_seconds INT,
  block_number BIGINT,
  tx_hash VARCHAR(66),
  created_at TIMESTAMPTZ,
  last_synced_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- ANALYTICS & METRICS
-- =============================================================================

-- Daily network metrics (aggregated)
CREATE TABLE daily_metrics (
  date DATE PRIMARY KEY,
  total_tasks_created INT DEFAULT 0,
  total_tasks_completed INT DEFAULT 0,
  total_tasks_expired INT DEFAULT 0,
  total_fees_collected NUMERIC(78, 0) DEFAULT 0,
  total_fees_distributed NUMERIC(78, 0) DEFAULT 0,
  active_operators INT DEFAULT 0,
  total_stake_weight NUMERIC(78, 0) DEFAULT 0,
  avg_completion_time_seconds INT,
  unique_claim_creators INT DEFAULT 0,
  slashing_events INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Operator daily performance
CREATE TABLE operator_daily_performance (
  wallet_address VARCHAR(42) NOT NULL,
  date DATE NOT NULL,
  tasks_assigned INT DEFAULT 0,
  tasks_signed INT DEFAULT 0,
  tasks_missed INT DEFAULT 0,
  avg_response_time_ms INT,
  uptime_percentage DECIMAL(5, 2),
  fees_earned NUMERIC(78, 0) DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (wallet_address, date)
);

CREATE INDEX idx_operator_perf_date ON operator_daily_performance(date);

-- Provider usage statistics
CREATE TABLE provider_daily_stats (
  provider_name VARCHAR(100) NOT NULL,
  date DATE NOT NULL,
  total_claims INT DEFAULT 0,
  successful_claims INT DEFAULT 0,
  failed_claims INT DEFAULT 0,
  avg_completion_time_ms INT,
  unique_users INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (provider_name, date)
);

-- =============================================================================
-- SYSTEM CONFIGURATION
-- =============================================================================

-- System configuration (admin-controlled settings)
CREATE TABLE system_config (
  key VARCHAR(100) PRIMARY KEY,
  value JSONB NOT NULL,
  description TEXT,
  is_public BOOLEAN DEFAULT false, -- If true, exposed to frontend
  updated_by UUID REFERENCES admins(id),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Feature flags
CREATE TABLE feature_flags (
  name VARCHAR(100) PRIMARY KEY,
  enabled BOOLEAN DEFAULT false,
  description TEXT,
  rollout_percentage INT DEFAULT 100 CHECK (rollout_percentage >= 0 AND rollout_percentage <= 100),
  updated_by UUID REFERENCES admins(id),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- NOTIFICATIONS & ALERTS
-- =============================================================================

-- Admin notification preferences
CREATE TABLE admin_notification_preferences (
  admin_id UUID PRIMARY KEY REFERENCES admins(id) ON DELETE CASCADE,
  email_notifications BOOLEAN DEFAULT true,
  slack_webhook_url VARCHAR(500),
  notify_new_applications BOOLEAN DEFAULT true,
  notify_slashing_events BOOLEAN DEFAULT true,
  notify_low_operator_count BOOLEAN DEFAULT true,
  notify_high_fees BOOLEAN DEFAULT true,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- System alerts
CREATE TABLE system_alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  alert_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
  title VARCHAR(255) NOT NULL,
  message TEXT,
  metadata JSONB,
  acknowledged_by UUID REFERENCES admins(id),
  acknowledged_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alerts_severity ON system_alerts(severity);
CREATE INDEX idx_alerts_type ON system_alerts(alert_type);
CREATE INDEX idx_alerts_unresolved ON system_alerts(resolved_at) WHERE resolved_at IS NULL;

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_applications ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE indexed_operators ENABLE ROW LEVEL SECURITY;
ALTER TABLE indexed_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE indexed_slashing_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_config ENABLE ROW LEVEL SECURITY;

-- Public read access for indexed data (anyone can query)
CREATE POLICY "Public read indexed_operators" ON indexed_operators FOR SELECT USING (true);
CREATE POLICY "Public read indexed_tasks" ON indexed_tasks FOR SELECT USING (true);
CREATE POLICY "Public read indexed_slashing_events" ON indexed_slashing_events FOR SELECT USING (true);
CREATE POLICY "Public read operator_profiles" ON operator_profiles FOR SELECT USING (true);
CREATE POLICY "Public read system_config" ON system_config FOR SELECT USING (is_public = true);

-- Note: Admin-only policies should be configured based on your Supabase auth setup
-- These policies use service role key for admin operations

-- =============================================================================
-- FUNCTIONS & TRIGGERS
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER admins_updated_at BEFORE UPDATE ON admins
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER operator_applications_updated_at BEFORE UPDATE ON operator_applications
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER operator_profiles_updated_at BEFORE UPDATE ON operator_profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER system_config_updated_at BEFORE UPDATE ON system_config
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function to auto-create operator profile when whitelisted
CREATE OR REPLACE FUNCTION create_operator_profile_on_whitelist()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.is_whitelisted = true AND OLD.is_whitelisted = false THEN
    INSERT INTO operator_profiles (wallet_address)
    VALUES (NEW.wallet_address)
    ON CONFLICT (wallet_address) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER auto_create_operator_profile
  AFTER UPDATE ON indexed_operators
  FOR EACH ROW EXECUTE FUNCTION create_operator_profile_on_whitelist();

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert default system configuration
INSERT INTO system_config (key, value, description, is_public) VALUES
  ('task_fee_wei', '"1000000000000000"', 'Default task fee in wei (0.001 ETH)', true),
  ('min_operators_per_task', '3', 'Minimum operators assigned per task', true),
  ('challenge_window_seconds', '604800', 'Challenge window duration (7 days)', true),
  ('slash_proportion_wad', '"150000000000000000"', 'Slash proportion (15%)', true),
  ('challenger_reward_bips', '1000', 'Challenger reward (10%)', true),
  ('max_task_lifetime_seconds', '1800', 'Max task lifetime (30 minutes)', true),
  ('maintenance_mode', 'false', 'System maintenance mode', true),
  ('indexer_last_block', '0', 'Last indexed block number', false)
ON CONFLICT (key) DO NOTHING;

-- Insert default feature flags
INSERT INTO feature_flags (name, enabled, description) VALUES
  ('operator_applications', true, 'Enable operator application workflow'),
  ('email_notifications', true, 'Enable email notifications'),
  ('slack_notifications', false, 'Enable Slack notifications'),
  ('advanced_analytics', false, 'Enable advanced analytics dashboard'),
  ('api_rate_limiting', true, 'Enable API rate limiting')
ON CONFLICT (name) DO NOTHING;
