/**
 * KYC Session Manager
 *
 * In-memory session store that tracks the mapping between
 * user DIDs, wallet signatures, and KYC provider sessions.
 *
 * Sessions have a 30-minute TTL and are cleaned up periodically.
 */

// ============= Types =============

export interface KYCSessionRecord {
	/** KYC provider session ID */
	sessionId: string
	/** Provider name */
	provider: string
	/** User's did:key identifier */
	userDid: string
	/** Wallet signature authorizing this verification */
	walletSignature: string
	/** Timestamp from the signature message */
	signatureTimestamp: number
	/** Session status */
	status: 'pending' | 'completed' | 'failed' | 'expired'
	/** When the session was created */
	createdAt: number
	/** When the session expires */
	expiresAt: number
}

// ============= Configuration =============

/** Session TTL: 30 minutes */
const SESSION_TTL_MS = 30 * 60 * 1000

/** Cleanup interval: every 5 minutes */
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000

// ============= Session Store =============

/** Session ID → session record */
const sessions = new Map<string, KYCSessionRecord>()

/** User DID → set of session IDs */
const didToSessions = new Map<string, Set<string>>()

// Periodic cleanup
let cleanupTimer: ReturnType<typeof setInterval> | null = null

function startCleanup(): void {
	if(cleanupTimer) {
		return
	}

	cleanupTimer = setInterval(() => {
		const now = Date.now()
		for(const [id, session] of sessions) {
			if(now > session.expiresAt) {
				removeSession(id)
			}
		}
	}, CLEANUP_INTERVAL_MS)

	// Don't prevent process exit
	if(cleanupTimer.unref) {
		cleanupTimer.unref()
	}
}

// ============= Public API =============

/**
 * Create a new KYC session record.
 */
export function createSession(params: {
	sessionId: string
	provider: string
	userDid: string
	walletSignature: string
	signatureTimestamp: number
}): KYCSessionRecord {
	startCleanup()

	const now = Date.now()
	const record: KYCSessionRecord = {
		sessionId: params.sessionId,
		provider: params.provider,
		userDid: params.userDid,
		walletSignature: params.walletSignature,
		signatureTimestamp: params.signatureTimestamp,
		status: 'pending',
		createdAt: now,
		expiresAt: now + SESSION_TTL_MS,
	}

	sessions.set(params.sessionId, record)

	// Index by DID
	let didSessions = didToSessions.get(params.userDid)
	if(!didSessions) {
		didSessions = new Set()
		didToSessions.set(params.userDid, didSessions)
	}
	didSessions.add(params.sessionId)

	return record
}

/**
 * Get a session by ID.
 */
export function getSession(sessionId: string): KYCSessionRecord | null {
	const session = sessions.get(sessionId)
	if(!session) {
		return null
	}

	// Check expiry
	if(Date.now() > session.expiresAt) {
		removeSession(sessionId)
		return null
	}

	return session
}

/**
 * Get sessions for a user DID.
 */
export function getSessionsByDid(userDid: string): KYCSessionRecord[] {
	const sessionIds = didToSessions.get(userDid)
	if(!sessionIds) {
		return []
	}

	const now = Date.now()
	const results: KYCSessionRecord[] = []

	for(const id of sessionIds) {
		const session = sessions.get(id)
		if(session && now <= session.expiresAt) {
			results.push(session)
		} else {
			// Clean up expired
			sessionIds.delete(id)
			sessions.delete(id)
		}
	}

	return results
}

/**
 * Update session status.
 */
export function updateSessionStatus(
	sessionId: string,
	status: 'completed' | 'failed'
): KYCSessionRecord | null {
	const session = sessions.get(sessionId)
	if(!session) {
		return null
	}

	session.status = status
	return session
}

/**
 * Find a session by provider session ID and provider name.
 */
export function findSessionByProvider(
	providerSessionId: string,
	provider: string
): KYCSessionRecord | null {
	for(const session of sessions.values()) {
		if(session.sessionId === providerSessionId && session.provider === provider) {
			if(Date.now() <= session.expiresAt) {
				return session
			}
		}
	}
	return null
}

// ============= Internal =============

function removeSession(sessionId: string): void {
	const session = sessions.get(sessionId)
	if(session) {
		const didSessions = didToSessions.get(session.userDid)
		if(didSessions) {
			didSessions.delete(sessionId)
			if(didSessions.size === 0) {
				didToSessions.delete(session.userDid)
			}
		}
		sessions.delete(sessionId)
	}
}
