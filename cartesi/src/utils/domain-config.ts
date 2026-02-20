/**
 * Domain Configuration Registry
 *
 * Provides configurable domain-specific values.
 * Register custom domain configs via registerDomainConfig() for your use case.
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

// ============= Default Configuration =============

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
