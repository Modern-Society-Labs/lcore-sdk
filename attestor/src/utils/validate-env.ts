/**
 * Environment variable validation utilities
 *
 * Validates required environment variables at startup to fail fast
 * with clear error messages rather than failing later with cryptic errors.
 */

import { getEnvVariable } from '#src/utils/env.ts'

/** Environment variable requirements */
interface EnvRequirement {
	/** Variable name */
	name: string
	/** Description for error messages */
	description: string
	/** Whether the variable is required (default: true) */
	required?: boolean
	/** Minimum length (if applicable) */
	minLength?: number
	/** Validation function (optional) */
	validate?: (value: string) => boolean
	/** Error message if validation fails */
	validationError?: string
}

/** Core environment variables required for the attestor */
const CORE_REQUIREMENTS: EnvRequirement[] = [
	{
		name: 'PRIVATE_KEY',
		description: 'Operator private key for signing',
		required: true,
	},
]

/** Database environment variables (required if using admin features) */
const DATABASE_REQUIREMENTS: EnvRequirement[] = [
	{
		name: 'SUPABASE_URL',
		description: 'Supabase project URL',
		required: false, // Only required for admin features
	},
	{
		name: 'SUPABASE_SERVICE_KEY',
		description: 'Supabase service role key',
		required: false,
	},
	{
		name: 'JWT_SECRET',
		description: 'JWT signing secret for admin sessions',
		required: false,
		minLength: 32,
		validationError: 'JWT_SECRET must be at least 32 characters for security',
	},
]

/** L{CORE} environment variables */
const LCORE_REQUIREMENTS: EnvRequirement[] = [
	{
		name: 'LCORE_NODE_URL',
		description: 'L{CORE} Cartesi node URL',
		required: false,
	},
	{
		name: 'LCORE_DAPP_ADDRESS',
		description: 'L{CORE} DApp contract address',
		required: false,
		validate: (value) => /^0x[a-fA-F0-9]{40}$/.test(value),
		validationError: 'LCORE_DAPP_ADDRESS must be a valid Ethereum address',
	},
]

/**
 * Validate environment variable against requirement
 */
function validateEnvVar(req: EnvRequirement): string | null {
	const value = getEnvVariable(req.name)

	// Check if required and missing
	if(req.required !== false && !value) {
		return `Missing required environment variable: ${req.name} (${req.description})`
	}

	// Skip further validation if not set and not required
	if(!value) {
		return null
	}

	// Check minimum length
	if(req.minLength && value.length < req.minLength) {
		return req.validationError || `${req.name} must be at least ${req.minLength} characters`
	}

	// Run custom validation
	if(req.validate && !req.validate(value)) {
		return req.validationError || `${req.name} validation failed`
	}

	return null
}

/**
 * Validate all core environment variables
 * Throws if required variables are missing
 */
export function validateCoreEnv(): void {
	const errors: string[] = []

	for(const req of CORE_REQUIREMENTS) {
		const error = validateEnvVar(req)
		if(error) {
			errors.push(error)
		}
	}

	if(errors.length > 0) {
		throw new Error(`Environment validation failed:\n  - ${errors.join('\n  - ')}`)
	}
}

/**
 * Validate database/admin environment variables
 * Returns warnings instead of throwing for optional features
 */
export function validateDatabaseEnv(): { valid: boolean, warnings: string[] } {
	const warnings: string[] = []

	// Check if any database var is set - if so, all are required
	const hasAnyDbVar = DATABASE_REQUIREMENTS.some(req => getEnvVariable(req.name))

	if(hasAnyDbVar) {
		for(const req of DATABASE_REQUIREMENTS) {
			const value = getEnvVariable(req.name)
			if(!value) {
				warnings.push(`${req.name} is missing - admin features will be disabled`)
			} else {
				const error = validateEnvVar({ ...req, required: false })
				if(error) {
					warnings.push(error)
				}
			}
		}
	}

	return {
		valid: warnings.length === 0,
		warnings,
	}
}

/**
 * Validate L{CORE} environment variables
 */
export function validateLcoreEnv(): { valid: boolean, warnings: string[] } {
	const warnings: string[] = []
	const lcoreEnabled = getEnvVariable('LCORE_ENABLED') === '1'

	if(lcoreEnabled) {
		for(const req of LCORE_REQUIREMENTS) {
			const error = validateEnvVar(req)
			if(error) {
				warnings.push(error)
			}
		}
	}

	return {
		valid: warnings.length === 0,
		warnings,
	}
}

/**
 * Run all environment validations
 * Call this at server startup
 */
export function validateAllEnv(): void {
	// Core validation - throws on failure
	validateCoreEnv()

	// Database validation - warnings only
	const dbResult = validateDatabaseEnv()
	if(dbResult.warnings.length > 0) {
		console.warn('[STARTUP] Database environment warnings:')
		for(const warning of dbResult.warnings) {
			console.warn(`  - ${warning}`)
		}
	}

	// L{CORE} validation - warnings only
	const lcoreResult = validateLcoreEnv()
	if(lcoreResult.warnings.length > 0) {
		console.warn('[STARTUP] L{CORE} environment warnings:')
		for(const warning of lcoreResult.warnings) {
			console.warn(`  - ${warning}`)
		}
	}
}
