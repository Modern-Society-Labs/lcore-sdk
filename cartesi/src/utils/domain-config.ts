/**
 * Domain Configuration Registry
 *
 * Provides configurable domain-specific values that were previously hardcoded.
 * Enables the SDK to be customized for different use cases (lending, gaming, governance, etc.)
 */

// ============= Types =============

export interface EntityStatusConfig {
  statuses: string[];
  defaultStatus: string;
  terminalStatuses: string[];  // Statuses that cannot transition
}

export interface ComputationTypeConfig {
  types: string[];
  customTypes?: string[];
}

export interface DataSourceConfig {
  types: string[];
  customTypes?: string[];
}

export interface ApprovalTypeConfig {
  types: string[];
  requiresSignature: string[];  // Types that need cryptographic signatures
}

export interface TimeUnitConfig {
  defaultUnit: 'blocks' | 'seconds' | 'days' | 'epochs';
  allowedUnits: string[];
}

export interface ThresholdConfig {
  default: number;
  min?: number;
  max?: number;
}

export interface DomainConfig {
  name: string;
  version: string;

  // Entity configuration
  entityStatuses: EntityStatusConfig;

  // Computation configuration
  computationTypes: ComputationTypeConfig;

  // Data source configuration
  dataSources: DataSourceConfig;

  // Approval configuration
  approvalTypes: ApprovalTypeConfig;

  // Time configuration
  timeUnits: TimeUnitConfig;

  // Thresholds
  thresholds: Record<string, ThresholdConfig>;

  // Custom domain-specific config
  custom?: Record<string, unknown>;
}

// ============= Preset Configurations =============

/**
 * Lending/Finance domain configuration
 */
export const LENDING_DOMAIN_CONFIG: DomainConfig = {
  name: 'lending',
  version: '1.0.0',

  entityStatuses: {
    statuses: ['active', 'inactive', 'pending', 'suspended', 'completed', 'defaulted'],
    defaultStatus: 'pending',
    terminalStatuses: ['completed', 'defaulted'],
  },

  computationTypes: {
    types: ['aggregate', 'average', 'trend', 'ratio', 'risk_score', 'credit_score'],
  },

  dataSources: {
    types: ['plaid', 'stripe', 'shopify', 'gusto', 'experian', 'custom'],
  },

  approvalTypes: {
    types: ['status_change', 'rate_change', 'limit_change', 'withdrawal', 'custom'],
    requiresSignature: ['withdrawal', 'rate_change'],
  },

  timeUnits: {
    defaultUnit: 'days',
    allowedUnits: ['blocks', 'seconds', 'days', 'months'],
  },

  thresholds: {
    collateral_ratio: { default: 1.25, min: 1.0, max: 3.0 },
    min_credit_score: { default: 600, min: 300, max: 850 },
  },
};

/**
 * Gaming domain configuration
 */
export const GAMING_DOMAIN_CONFIG: DomainConfig = {
  name: 'gaming',
  version: '1.0.0',

  entityStatuses: {
    statuses: ['active', 'inactive', 'banned', 'suspended', 'completed'],
    defaultStatus: 'active',
    terminalStatuses: ['banned'],
  },

  computationTypes: {
    types: ['score', 'rank', 'leaderboard', 'achievement', 'stats', 'progression'],
  },

  dataSources: {
    types: ['steam', 'epic', 'playstation', 'xbox', 'custom'],
  },

  approvalTypes: {
    types: ['ban', 'unban', 'reward', 'penalty', 'custom'],
    requiresSignature: ['ban', 'reward'],
  },

  timeUnits: {
    defaultUnit: 'blocks',
    allowedUnits: ['blocks', 'seconds', 'rounds', 'seasons'],
  },

  thresholds: {
    max_players: { default: 100, min: 2 },
    round_timeout: { default: 300, min: 30 },
  },
};

/**
 * Governance/DAO domain configuration
 */
export const GOVERNANCE_DOMAIN_CONFIG: DomainConfig = {
  name: 'governance',
  version: '1.0.0',

  entityStatuses: {
    statuses: ['draft', 'active', 'passed', 'failed', 'executed', 'cancelled'],
    defaultStatus: 'draft',
    terminalStatuses: ['executed', 'cancelled', 'failed'],
  },

  computationTypes: {
    types: ['vote_count', 'quorum_check', 'approval_rate', 'delegation_power'],
  },

  dataSources: {
    types: ['snapshot', 'on_chain', 'off_chain', 'custom'],
  },

  approvalTypes: {
    types: ['proposal_create', 'proposal_execute', 'parameter_change', 'emergency', 'custom'],
    requiresSignature: ['proposal_execute', 'emergency'],
  },

  timeUnits: {
    defaultUnit: 'blocks',
    allowedUnits: ['blocks', 'seconds', 'days', 'epochs'],
  },

  thresholds: {
    quorum: { default: 0.04, min: 0.01, max: 0.5 },  // 4% default quorum
    approval_threshold: { default: 0.5, min: 0.5, max: 1.0 },  // Simple majority
    voting_period_blocks: { default: 40320, min: 1000 },  // ~7 days at 15s blocks
  },
};

/**
 * Marketplace domain configuration
 */
export const MARKETPLACE_DOMAIN_CONFIG: DomainConfig = {
  name: 'marketplace',
  version: '1.0.0',

  entityStatuses: {
    statuses: ['draft', 'active', 'sold', 'cancelled', 'expired', 'disputed'],
    defaultStatus: 'draft',
    terminalStatuses: ['sold', 'cancelled'],
  },

  computationTypes: {
    types: ['price_history', 'volume', 'floor_price', 'trending', 'rarity'],
  },

  dataSources: {
    types: ['opensea', 'blur', 'custom'],
  },

  approvalTypes: {
    types: ['listing', 'sale', 'cancellation', 'dispute_resolution', 'custom'],
    requiresSignature: ['sale', 'dispute_resolution'],
  },

  timeUnits: {
    defaultUnit: 'seconds',
    allowedUnits: ['blocks', 'seconds', 'days'],
  },

  thresholds: {
    platform_fee: { default: 0.025, min: 0, max: 0.1 },  // 2.5% default fee
    min_listing_duration: { default: 3600, min: 60 },     // 1 hour minimum
    escrow_timeout: { default: 86400, min: 3600 },        // 24 hour timeout
  },
};

/**
 * Attestation/Identity domain configuration (L{CORE})
 */
export const ATTESTATION_DOMAIN_CONFIG: DomainConfig = {
  name: 'attestation',
  version: '1.0.0',

  entityStatuses: {
    statuses: ['active', 'revoked', 'expired', 'superseded'],
    defaultStatus: 'active',
    terminalStatuses: ['revoked'],
  },

  computationTypes: {
    types: ['freshness', 'aggregate', 'bucket_distribution', 'access_count'],
  },

  dataSources: {
    types: ['chase', 'gusto', 'instagram', 'whoop', 'binance', 'custom'],
  },

  approvalTypes: {
    types: ['grant_access', 'revoke_access', 'schema_change', 'custom'],
    requiresSignature: ['schema_change'],
  },

  timeUnits: {
    defaultUnit: 'blocks',
    allowedUnits: ['blocks', 'seconds', 'days'],
  },

  thresholds: {
    min_freshness: { default: 10, min: 0, max: 100 },
    freshness_half_life: { default: 86400, min: 3600 },  // 1 day default
  },
};

// ============= Configuration Registry =============

const configRegistry: Map<string, DomainConfig> = new Map([
  ['lending', LENDING_DOMAIN_CONFIG],
  ['gaming', GAMING_DOMAIN_CONFIG],
  ['governance', GOVERNANCE_DOMAIN_CONFIG],
  ['marketplace', MARKETPLACE_DOMAIN_CONFIG],
  ['attestation', ATTESTATION_DOMAIN_CONFIG],
]);

let activeDomain: string = 'attestation';

/**
 * Register a custom domain configuration
 */
export function registerDomainConfig(config: DomainConfig): void {
  configRegistry.set(config.name, config);
}

/**
 * Get a domain configuration by name
 */
export function getDomainConfig(name?: string): DomainConfig {
  const configName = name || activeDomain;
  const config = configRegistry.get(configName);

  if (!config) {
    throw new Error(`Domain configuration not found: ${configName}`);
  }

  return config;
}

/**
 * Set the active domain
 */
export function setActiveDomain(name: string): void {
  if (!configRegistry.has(name)) {
    throw new Error(`Domain not registered: ${name}`);
  }
  activeDomain = name;
}

/**
 * Get the active domain name
 */
export function getActiveDomain(): string {
  return activeDomain;
}

/**
 * List all registered domains
 */
export function listDomains(): string[] {
  return Array.from(configRegistry.keys());
}

// ============= Helper Functions =============

/**
 * Check if a status is valid for the current domain
 */
export function isValidStatus(status: string, domain?: string): boolean {
  const config = getDomainConfig(domain);
  return config.entityStatuses.statuses.includes(status);
}

/**
 * Check if a status is terminal
 */
export function isTerminalStatus(status: string, domain?: string): boolean {
  const config = getDomainConfig(domain);
  return config.entityStatuses.terminalStatuses.includes(status);
}

/**
 * Get default status for domain
 */
export function getDefaultStatus(domain?: string): string {
  const config = getDomainConfig(domain);
  return config.entityStatuses.defaultStatus;
}

/**
 * Check if computation type is valid
 */
export function isValidComputationType(type: string, domain?: string): boolean {
  const config = getDomainConfig(domain);
  return config.computationTypes.types.includes(type) ||
         (config.computationTypes.customTypes?.includes(type) ?? false);
}

/**
 * Get threshold value
 */
export function getThreshold(name: string, domain?: string): number {
  const config = getDomainConfig(domain);
  const threshold = config.thresholds[name];
  return threshold?.default ?? 0;
}

/**
 * Validate threshold value within bounds
 */
export function validateThreshold(name: string, value: number, domain?: string): boolean {
  const config = getDomainConfig(domain);
  const threshold = config.thresholds[name];

  if (!threshold) return true;

  if (threshold.min !== undefined && value < threshold.min) return false;
  if (threshold.max !== undefined && value > threshold.max) return false;

  return true;
}

/**
 * Load domain config from environment
 */
export function loadDomainFromEnv(): void {
  const envDomain = process.env.DOMAIN_CONFIG;

  if (envDomain) {
    try {
      const config = JSON.parse(envDomain) as DomainConfig;
      registerDomainConfig(config);
      setActiveDomain(config.name);
    } catch {
      console.warn('Failed to parse DOMAIN_CONFIG environment variable');
    }
  }

  const activeDomainEnv = process.env.ACTIVE_DOMAIN;
  if (activeDomainEnv && configRegistry.has(activeDomainEnv)) {
    setActiveDomain(activeDomainEnv);
  }
}
