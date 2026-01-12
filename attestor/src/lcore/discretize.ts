/**
 * L{CORE} Discretization Utility
 *
 * Converts raw attestation data values into privacy-preserving buckets.
 * Buckets allow queries like "user has balance > $10,000" without
 * revealing the exact balance.
 *
 * Each provider schema defines bucket boundaries for its data fields.
 * This utility applies those boundaries to produce bucket labels.
 */

// ============= Types =============

export interface BucketDefinition {
	boundaries: number[]
	labels: string[]
}

export interface BucketResult {
	key: string
	value: string // The bucket label
}

export interface DiscretizationSchema {
	provider: string
	flowType: string
	bucketDefinitions: Record<string, BucketDefinition>
}

// ============= Built-in Provider Schemas =============

/**
 * Pre-defined bucket schemas for common providers.
 * These can be overridden by schemas registered in the Cartesi layer.
 */
export const BUILTIN_SCHEMAS: Record<string, DiscretizationSchema> = {
	// Chase bank account balance
	'chase:web_request': {
		provider: 'chase',
		flowType: 'web_request',
		bucketDefinitions: {
			balance: {
				boundaries: [0, 1000, 5000, 10000, 25000, 50000, 100000, 500000, Infinity],
				labels: ['<1k', '1k-5k', '5k-10k', '10k-25k', '25k-50k', '50k-100k', '100k-500k', '>500k'],
			},
			account_age_days: {
				boundaries: [0, 30, 90, 180, 365, 730, Infinity],
				labels: ['<30d', '30-90d', '90-180d', '180d-1y', '1-2y', '>2y'],
			},
		},
	},

	// Gusto payroll
	'gusto:web_request': {
		provider: 'gusto',
		flowType: 'web_request',
		bucketDefinitions: {
			annual_salary: {
				boundaries: [0, 30000, 50000, 75000, 100000, 150000, 200000, 300000, Infinity],
				labels: ['<30k', '30k-50k', '50k-75k', '75k-100k', '100k-150k', '150k-200k', '200k-300k', '>300k'],
			},
			months_employed: {
				boundaries: [0, 3, 6, 12, 24, 48, Infinity],
				labels: ['<3m', '3-6m', '6-12m', '1-2y', '2-4y', '>4y'],
			},
		},
	},

	// Binance crypto exchange
	'binance:web_request': {
		provider: 'binance',
		flowType: 'web_request',
		bucketDefinitions: {
			total_balance_usd: {
				boundaries: [0, 100, 1000, 10000, 50000, 100000, 500000, Infinity],
				labels: ['<100', '100-1k', '1k-10k', '10k-50k', '50k-100k', '100k-500k', '>500k'],
			},
			trading_volume_30d: {
				boundaries: [0, 1000, 10000, 50000, 100000, 500000, Infinity],
				labels: ['<1k', '1k-10k', '10k-50k', '50k-100k', '100k-500k', '>500k'],
			},
		},
	},

	// Whoop fitness
	'whoop:web_request': {
		provider: 'whoop',
		flowType: 'web_request',
		bucketDefinitions: {
			recovery_score: {
				boundaries: [0, 33, 67, 100, Infinity],
				labels: ['red', 'yellow', 'green', 'max'],
			},
			strain: {
				boundaries: [0, 5, 10, 15, 21, Infinity],
				labels: ['rest', 'light', 'moderate', 'high', 'extreme'],
			},
			sleep_hours: {
				boundaries: [0, 4, 6, 7, 8, 9, Infinity],
				labels: ['<4h', '4-6h', '6-7h', '7-8h', '8-9h', '>9h'],
			},
		},
	},

	// Instagram social
	'instagram:web_request': {
		provider: 'instagram',
		flowType: 'web_request',
		bucketDefinitions: {
			follower_count: {
				boundaries: [0, 100, 1000, 10000, 50000, 100000, 1000000, Infinity],
				labels: ['<100', '100-1k', '1k-10k', '10k-50k', '50k-100k', '100k-1m', '>1m'],
			},
			post_count: {
				boundaries: [0, 10, 50, 100, 500, 1000, Infinity],
				labels: ['<10', '10-50', '50-100', '100-500', '500-1k', '>1k'],
			},
		},
	},

	// Generic fallback for unknown providers
	'generic:generic': {
		provider: 'generic',
		flowType: 'generic',
		bucketDefinitions: {
			numeric_value: {
				boundaries: [0, 10, 100, 1000, 10000, 100000, Infinity],
				labels: ['<10', '10-100', '100-1k', '1k-10k', '10k-100k', '>100k'],
			},
		},
	},
}

// ============= Core Functions =============

/**
 * Find the bucket label for a numeric value given boundaries.
 *
 * Example:
 *   boundaries: [0, 1000, 5000, 10000]
 *   labels: ['<1k', '1k-5k', '5k-10k', '>10k']
 *   value: 3500 -> '1k-5k'
 */
export function discretizeValue(
	value: number,
	boundaries: number[],
	labels: string[]
): string {
	// Validate boundaries/labels relationship
	if (boundaries.length !== labels.length + 1) {
		throw new Error(
			`Invalid bucket definition: boundaries.length (${boundaries.length}) must equal labels.length + 1 (${labels.length + 1})`
		)
	}

	// Find the appropriate bucket
	for (let i = 0; i < labels.length; i++) {
		if (value >= boundaries[i] && value < boundaries[i + 1]) {
			return labels[i]
		}
	}

	// Fallback to last label if value >= last boundary
	return labels[labels.length - 1]
}

/**
 * Get the schema for a provider/flowType combination.
 * Returns undefined if not found.
 */
export function getSchema(provider: string, flowType: string): DiscretizationSchema | undefined {
	const key = `${provider.toLowerCase()}:${flowType.toLowerCase()}`
	return BUILTIN_SCHEMAS[key]
}

/**
 * Extract numeric values from parsed claim parameters.
 * Returns a map of field names to numeric values.
 */
export function extractNumericValues(params: Record<string, unknown>): Record<string, number> {
	const result: Record<string, number> = {}

	function extract(obj: unknown, prefix = ''): void {
		if (obj === null || obj === undefined) return

		if (typeof obj === 'number' && isFinite(obj)) {
			if (prefix) {
				result[prefix] = obj
			}
			return
		}

		if (typeof obj === 'string') {
			// Try to parse as number
			const num = parseFloat(obj.replace(/[,$%]/g, ''))
			if (!isNaN(num) && isFinite(num)) {
				if (prefix) {
					result[prefix] = num
				}
			}
			return
		}

		if (Array.isArray(obj)) {
			obj.forEach((item, i) => extract(item, prefix ? `${prefix}[${i}]` : `[${i}]`))
			return
		}

		if (typeof obj === 'object') {
			for (const [key, value] of Object.entries(obj)) {
				extract(value, prefix ? `${prefix}.${key}` : key)
			}
		}
	}

	extract(params)
	return result
}

/**
 * Discretize claim parameters into buckets using the appropriate schema.
 *
 * @param provider - The attestation provider (e.g., 'chase', 'gusto')
 * @param flowType - The flow type (e.g., 'web_request')
 * @param params - Parsed claim parameters containing numeric values
 * @param customSchema - Optional custom schema to use instead of built-in
 * @returns Array of bucket key-value pairs
 */
export function discretizeClaimData(
	provider: string,
	flowType: string,
	params: Record<string, unknown>,
	customSchema?: DiscretizationSchema
): BucketResult[] {
	const schema = customSchema || getSchema(provider, flowType)

	if (!schema) {
		// No schema found, return empty buckets
		return []
	}

	const numericValues = extractNumericValues(params)
	const buckets: BucketResult[] = []

	// Apply bucket definitions to matching fields
	for (const [bucketKey, definition] of Object.entries(schema.bucketDefinitions)) {
		// Look for exact match or nested match
		let value: number | undefined

		// Try exact match
		if (bucketKey in numericValues) {
			value = numericValues[bucketKey]
		} else {
			// Try to find a nested match (e.g., 'balance' matches 'account.balance')
			for (const [fieldPath, fieldValue] of Object.entries(numericValues)) {
				if (fieldPath.endsWith(`.${bucketKey}`) || fieldPath === bucketKey) {
					value = fieldValue
					break
				}
			}
		}

		if (value !== undefined) {
			try {
				const label = discretizeValue(value, definition.boundaries, definition.labels)
				buckets.push({ key: bucketKey, value: label })
			} catch (err) {
				// Skip invalid bucket definitions
				console.warn(`Skipping bucket ${bucketKey}: ${err}`)
			}
		}
	}

	return buckets
}

/**
 * Register a custom schema at runtime.
 * This allows adding new providers without code changes.
 */
export function registerSchema(schema: DiscretizationSchema): void {
	const key = `${schema.provider.toLowerCase()}:${schema.flowType.toLowerCase()}`
	BUILTIN_SCHEMAS[key] = schema
}

/**
 * List all registered provider schemas.
 */
export function listSchemas(): string[] {
	return Object.keys(BUILTIN_SCHEMAS)
}
