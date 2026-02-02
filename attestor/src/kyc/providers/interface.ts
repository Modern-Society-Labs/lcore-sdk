/**
 * KYC Provider Interface
 *
 * Unified abstraction for KYC verification providers.
 * Providers implement this interface to integrate with the zkIdentity flow.
 *
 * PRIVACY MODEL:
 * - Raw KYC data (name, DOB, ID numbers) is verified in the TEE and DISCARDED
 * - Only boolean flags and metadata are stored on-chain
 * - No PII ever touches the blockchain
 */

// ============= Core Provider Interface =============

export interface KYCProvider {
	/** Provider identifier (e.g., 'smile_id') */
	name: string

	/** ISO 3166-1 alpha-2 country codes this provider supports */
	supportedCountries: string[]

	/** Whether this provider is running in stub/test mode */
	isStubMode: boolean

	/**
	 * Create a new verification session.
	 * Returns a URL the user should visit to complete KYC.
	 */
	createSession(
		userDid: string,
		options?: CreateSessionOptions
	): Promise<KYCSession>

	/**
	 * Check the status of an existing session.
	 */
	getStatus(sessionId: string): Promise<KYCStatus>

	/**
	 * Verify the authenticity of an incoming webhook from the provider.
	 * Returns true if the webhook signature is valid.
	 */
	verifyWebhook(payload: unknown, signature: string): boolean

	/**
	 * Parse a webhook payload into a standardized KYCResult.
	 * Raw PII data is included for verification only and MUST NOT be persisted.
	 */
	parseResult(webhookPayload: unknown): KYCResult
}

// ============= Session Types =============

export interface CreateSessionOptions {
	/** Verification level requested */
	jobType?: 'basic' | 'document' | 'biometric'
	/** Country hint for the provider */
	country?: string
}

export interface KYCSession {
	/** Unique session identifier */
	sessionId: string
	/** Provider name */
	provider: string
	/** URL for user to complete verification */
	verificationUrl: string
	/** Session expiry (unix timestamp) */
	expiresAt: number
}

export interface KYCStatus {
	/** Session identifier */
	sessionId: string
	/** Current status */
	status: 'pending' | 'completed' | 'failed' | 'expired'
	/** Result if completed */
	result?: KYCResult
}

// ============= Result Types =============

export interface KYCResult {
	/** Whether verification was successful */
	success: boolean
	/** Session identifier */
	sessionId: string
	/** ISO 3166-1 alpha-2 country code */
	country: string
	/** Verification level achieved */
	level: 'basic' | 'document' | 'biometric'
	/** Provider that performed verification */
	provider: string
	/**
	 * Raw verification data - used for TEE verification only.
	 * MUST be discarded after attestation is generated.
	 * NEVER stored on-chain or in persistent storage.
	 */
	rawData?: Record<string, unknown>
}

// ============= Provider Info =============

export interface KYCProviderInfo {
	/** Provider identifier */
	name: string
	/** Display name */
	displayName: string
	/** Supported countries */
	supportedCountries: string[]
	/** Whether running in stub mode */
	stubMode: boolean
}
