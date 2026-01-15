/**
 * Error sanitization utilities
 *
 * Prevents sensitive information from leaking in error messages
 * and log outputs.
 */

/** Patterns that match sensitive data */
const SENSITIVE_PATTERNS: RegExp[] = [
	// JWT tokens
	/Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/gi,
	// Private keys (hex format)
	/0x[a-fA-F0-9]{64}/g,
	// API keys (lc_ prefix)
	/lc_[a-zA-Z0-9]{32,}/g,
	// Generic API keys
	/api[_-]?key[=:]\s*["']?[a-zA-Z0-9\-_]{20,}["']?/gi,
	// Passwords in URLs or configs
	/password[=:]\s*["']?[^\s"']+["']?/gi,
	// Secrets in URLs or configs
	/secret[=:]\s*["']?[^\s"']+["']?/gi,
	// Connection strings with credentials
	/(:\/\/[^:]+:)[^@]+(@)/g,
	// Base64 encoded secrets (likely keys)
	/[A-Za-z0-9+/]{40,}={0,2}/g,
]

/**
 * Redact sensitive information from a string
 *
 * @param input - The string to sanitize
 * @returns Sanitized string with sensitive data replaced by [REDACTED]
 */
export function sanitizeString(input: string): string {
	let sanitized = input

	for(const pattern of SENSITIVE_PATTERNS) {
		// Reset regex state for global patterns
		pattern.lastIndex = 0

		// Special handling for connection string pattern (preserve structure)
		if(pattern.source.includes('@')) {
			sanitized = sanitized.replace(pattern, '$1[REDACTED]$2')
		} else {
			sanitized = sanitized.replace(pattern, '[REDACTED]')
		}
	}

	return sanitized
}

/**
 * Sanitize an Error object
 *
 * @param error - The error to sanitize
 * @returns A new Error with sanitized message
 */
export function sanitizeError(error: Error): Error {
	const sanitizedMessage = sanitizeString(error.message)
	const sanitizedError = new Error(sanitizedMessage)
	sanitizedError.name = error.name

	// Sanitize stack trace if present
	if(error.stack) {
		sanitizedError.stack = sanitizeString(error.stack)
	}

	return sanitizedError
}

/**
 * Sanitize an object by recursively sanitizing string values
 *
 * @param obj - The object to sanitize
 * @returns A new object with sanitized string values
 */
export function sanitizeObject<T extends Record<string, unknown>>(obj: T): T {
	const sanitized: Record<string, unknown> = {}

	for(const [key, value] of Object.entries(obj)) {
		// Skip known safe keys
		const lowerKey = key.toLowerCase()
		if(['id', 'uuid', 'timestamp', 'date', 'created_at', 'updated_at'].includes(lowerKey)) {
			sanitized[key] = value
			continue
		}

		// Redact potentially sensitive keys entirely
		if(['password', 'secret', 'token', 'key', 'credential', 'auth'].some(s => lowerKey.includes(s))) {
			sanitized[key] = '[REDACTED]'
			continue
		}

		// Recursively handle nested objects
		if(value && typeof value === 'object' && !Array.isArray(value)) {
			sanitized[key] = sanitizeObject(value as Record<string, unknown>)
		} else if(typeof value === 'string') {
			sanitized[key] = sanitizeString(value)
		} else {
			sanitized[key] = value
		}
	}

	return sanitized as T
}

/**
 * Create a sanitized error message for client responses
 * Maps internal errors to user-friendly messages
 */
export function clientSafeError(error: unknown): string {
	if(error instanceof Error) {
		// Map known error types to safe messages
		const message = error.message.toLowerCase()

		if(message.includes('timeout')) {
			return 'Request timed out. Please try again.'
		}

		if(message.includes('connection')) {
			return 'Connection error. Please check your network.'
		}

		if(message.includes('not found')) {
			return 'Resource not found.'
		}

		if(message.includes('unauthorized') || message.includes('authentication')) {
			return 'Authentication required.'
		}

		if(message.includes('forbidden') || message.includes('permission')) {
			return 'Insufficient permissions.'
		}

		// Generic fallback - don't expose internal details
		return 'An error occurred. Please try again later.'
	}

	return 'An unexpected error occurred.'
}
