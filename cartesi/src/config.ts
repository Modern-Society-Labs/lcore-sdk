/**
 * Configuration Module
 *
 * This module provides environment-based configuration with sensible defaults.
 * All configuration is read from environment variables at runtime.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Add new configuration functions for your domain-specific settings
 * 2. Follow the pattern: read from env, parse, validate, return default if invalid
 */

// ============= Core Configuration =============

/**
 * Whether certain operations require approval before being applied.
 * Set REQUIRE_APPROVAL=true in environment to enable.
 */
export function requireApproval(): boolean {
  const envValue = process.env.REQUIRE_APPROVAL;
  return envValue === 'true' || envValue === '1';
}

/**
 * Maximum records per sync operation to prevent spam/DoS.
 * Set MAX_RECORDS_PER_SYNC in environment to customize.
 */
export function getMaxRecordsPerSync(): number {
  const envValue = process.env.MAX_RECORDS_PER_SYNC;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 500;
}

/**
 * Default threshold value for computations.
 * Set DEFAULT_THRESHOLD in environment to customize.
 */
export function getDefaultThreshold(): number {
  const envValue = process.env.DEFAULT_THRESHOLD;
  if (envValue) {
    const parsed = parseFloat(envValue);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 1.25;
}

/**
 * Number of months to look back for historical computations.
 * Set COMPUTATION_LOOKBACK_MONTHS in environment to customize.
 */
export function getComputationLookbackMonths(): number {
  const envValue = process.env.COMPUTATION_LOOKBACK_MONTHS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 60) {
      return parsed;
    }
  }
  return 12;
}

// ============= Security Configuration =============

/**
 * Secret key for proof verification.
 * REQUIRED: Set PROOF_SIGNING_KEY environment variable!
 * Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */
export function getProofSigningKey(): string {
  const key = process.env.PROOF_SIGNING_KEY;
  if (!key) {
    throw new Error('PROOF_SIGNING_KEY environment variable is required. Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }
  return key;
}

/**
 * Proof expiration time in milliseconds.
 * Set PROOF_EXPIRATION_MS in environment to customize.
 */
export function getProofExpirationMs(): number {
  const envValue = process.env.PROOF_EXPIRATION_MS;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 24 * 60 * 60 * 1000; // 24 hours default
}

// ============= Rollup Configuration =============

/**
 * Get the rollup HTTP server URL.
 * In production Cartesi environment, this is set by the Cartesi runtime.
 * For local development, set ROLLUP_HTTP_SERVER_URL environment variable.
 */
export function getRollupServerUrl(): string {
  const url = process.env.ROLLUP_HTTP_SERVER_URL;
  if (!url) {
    console.warn('[CONFIG] ROLLUP_HTTP_SERVER_URL not set - using default http://127.0.0.1:5004');
    return 'http://127.0.0.1:5004';
  }
  return url;
}

/**
 * Whether to run in development mode (less strict validation).
 */
export function isDevelopmentMode(): boolean {
  const envValue = process.env.NODE_ENV;
  return envValue !== 'production';
}

// ============= Logging Configuration =============

/**
 * Log level for the application.
 * Values: 'debug', 'info', 'warn', 'error'
 */
export function getLogLevel(): string {
  return process.env.LOG_LEVEL || 'info';
}

/**
 * Whether to enable verbose logging.
 */
export function isVerboseLogging(): boolean {
  const envValue = process.env.VERBOSE_LOGGING;
  return envValue === 'true' || envValue === '1';
}

// ============= Output Configuration =============

/**
 * Output mode for query responses.
 * Options:
 *   'encrypted' - All outputs encrypted (default, requires attestor to decrypt)
 *   'raw'       - All outputs raw (for public data use cases)
 *   'custom'    - Developer implements their own outputHandler()
 *
 * Set LCORE_OUTPUT_MODE in environment to customize.
 */
export type OutputMode = 'encrypted' | 'raw' | 'custom';

export function getOutputMode(): OutputMode {
  const envValue = process.env.LCORE_OUTPUT_MODE;
  if (envValue === 'raw' || envValue === 'custom' || envValue === 'encrypted') {
    return envValue;
  }
  return 'encrypted'; // Default to encrypted for privacy
}

// ============= Rate Limiting Configuration =============

/**
 * Maximum payload size in bytes.
 */
export function getMaxPayloadSize(): number {
  const envValue = process.env.MAX_PAYLOAD_SIZE;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 100 * 1024; // 100KB default
}

/**
 * Maximum string field length in bytes.
 */
export function getMaxStringLength(): number {
  const envValue = process.env.MAX_STRING_LENGTH;
  if (envValue) {
    const parsed = parseInt(envValue, 10);
    if (!isNaN(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return 10 * 1024; // 10KB default
}

// ============= Unified Config Object =============

export interface AppConfig {
  rollupHttpServerUrl: string;
  isDevelopment: boolean;
  logLevel: string;
  verboseLogging: boolean;
  requireApproval: boolean;
  maxRecordsPerSync: number;
  maxPayloadSize: number;
  defaultThreshold: number;
  proofExpirationMs: number;
  outputMode: OutputMode;
}

let cachedConfig: AppConfig | null = null;

/**
 * Get unified application configuration.
 */
export function getConfig(): AppConfig {
  if (cachedConfig) return cachedConfig;

  cachedConfig = {
    rollupHttpServerUrl: getRollupServerUrl(),
    isDevelopment: isDevelopmentMode(),
    logLevel: getLogLevel(),
    verboseLogging: isVerboseLogging(),
    requireApproval: requireApproval(),
    maxRecordsPerSync: getMaxRecordsPerSync(),
    maxPayloadSize: getMaxPayloadSize(),
    defaultThreshold: getDefaultThreshold(),
    proofExpirationMs: getProofExpirationMs(),
    outputMode: getOutputMode(),
  };

  return cachedConfig;
}

/**
 * Reset cached config (for testing).
 */
export function resetConfig(): void {
  cachedConfig = null;
}
