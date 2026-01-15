/**
 * Simple in-memory rate limiter for auth endpoints
 *
 * Prevents brute-force attacks on authentication endpoints.
 * For distributed deployments, consider using Supabase-based rate limiting.
 */

interface RateLimitRecord {
	count: number
	resetAt: number
}

/** In-memory store for rate limit tracking */
const attempts = new Map<string, RateLimitRecord>()

/** Default max attempts per window */
const DEFAULT_MAX_ATTEMPTS = 5

/** Default window in milliseconds (15 minutes) */
const DEFAULT_WINDOW_MS = 15 * 60 * 1000

/** Cleanup interval in milliseconds (5 minutes) */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000

/**
 * Check if a request is within rate limits
 *
 * @param identifier - Unique identifier (usually IP address or wallet)
 * @param maxAttempts - Maximum attempts allowed in the window
 * @param windowMs - Time window in milliseconds
 * @returns Object with allowed status and remaining attempts info
 */
export function checkRateLimit(
	identifier: string,
	maxAttempts: number = DEFAULT_MAX_ATTEMPTS,
	windowMs: number = DEFAULT_WINDOW_MS
): {
	allowed: boolean
	remaining: number
	resetAt: Date
} {
	const now = Date.now()
	const record = attempts.get(identifier)

	// No record or expired window - allow and create new record
	if(!record || now > record.resetAt) {
		const resetAt = now + windowMs
		attempts.set(identifier, { count: 1, resetAt })
		return {
			allowed: true,
			remaining: maxAttempts - 1,
			resetAt: new Date(resetAt),
		}
	}

	// Within window but at or over limit
	if(record.count >= maxAttempts) {
		return {
			allowed: false,
			remaining: 0,
			resetAt: new Date(record.resetAt),
		}
	}

	// Within window and under limit
	record.count++
	return {
		allowed: true,
		remaining: maxAttempts - record.count,
		resetAt: new Date(record.resetAt),
	}
}

/**
 * Reset rate limit for an identifier (e.g., after successful login)
 */
export function resetRateLimit(identifier: string): void {
	attempts.delete(identifier)
}

/**
 * Clean up expired rate limit records
 */
function cleanupExpiredRecords(): void {
	const now = Date.now()
	for(const [identifier, record] of attempts.entries()) {
		if(now > record.resetAt) {
			attempts.delete(identifier)
		}
	}
}

// Periodic cleanup to prevent memory leaks
setInterval(cleanupExpiredRecords, CLEANUP_INTERVAL_MS)

/**
 * Get rate limit headers for HTTP response
 */
export function getRateLimitHeaders(result: {
	remaining: number
	resetAt: Date
}): Record<string, string> {
	return {
		'X-RateLimit-Remaining': String(result.remaining),
		'X-RateLimit-Reset': String(Math.floor(result.resetAt.getTime() / 1000)),
	}
}
