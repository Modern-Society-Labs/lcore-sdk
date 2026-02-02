/**
 * L{CORE} SDK - Identity Attestation Handler (zkIdentity)
 *
 * Privacy-preserving KYC verification attestation handler.
 *
 * PRIVACY MODEL:
 * - Only non-PII metadata is stored (provider, country, level, verified)
 * - No names, DOBs, addresses, ID numbers, or biometric data
 * - Users prove KYC completion without revealing personal information
 *
 * SECURITY MODEL:
 * - Attestor signs the claim with JWS
 * - Idempotent: duplicate session_id for same user+provider is rejected
 * - Expiry-aware: queries filter out expired attestations
 */

import {
	AdvanceRequestData,
	RequestHandlerResult,
	InspectQuery,
} from '../router';
import { getDatabase } from '../db';
import { isValidDIDKey } from '../crypto/jws';

// ============= Types =============

interface IdentityAttestationPayload {
	action: 'identity_attestation';
	user_did: string;
	provider: string;
	country_code: string;
	verification_level: string;
	verified: boolean;
	issued_at: number;
	expires_at: number;
	attestor_signature: string;
	session_id: string;
}

export interface IdentityAttestation {
	id: number;
	user_did: string;
	provider: string;
	country_code: string;
	verification_level: string;
	verified: boolean;
	issued_at: number;
	expires_at: number;
	attestor_signature: string;
	session_id: string;
	revoked: boolean;
	revoked_reason: string | null;
	input_index: number;
	created_at: string;
}

// ============= Advance Handler =============

/**
 * Handle identity attestation submission from the attestor.
 *
 * Payload contains ONLY non-PII metadata:
 * - user_did: pseudonymous identifier (did:key)
 * - provider: which KYC provider verified (e.g., 'smile_id')
 * - country_code: ISO country code (e.g., 'ET')
 * - verification_level: 'basic' | 'document' | 'biometric'
 * - verified: boolean
 * - issued_at / expires_at: timestamps
 * - attestor_signature: JWS from the attestor TEE
 * - session_id: for idempotency
 */
export const handleIdentityAttestation = async (
	requestData: AdvanceRequestData,
	payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {

	const p = payload as IdentityAttestationPayload;

	// Step 1: Validate required fields
	if (!p.user_did) {
		return {
			status: 'reject',
			response: { error: 'Missing required field: user_did' },
		};
	}

	if (!p.provider) {
		return {
			status: 'reject',
			response: { error: 'Missing required field: provider' },
		};
	}

	if (!p.country_code || typeof p.country_code !== 'string' || p.country_code.length !== 2) {
		return {
			status: 'reject',
			response: { error: 'Missing or invalid field: country_code (must be ISO 3166-1 alpha-2)' },
		};
	}

	if (!p.verification_level || !['basic', 'document', 'biometric'].includes(p.verification_level)) {
		return {
			status: 'reject',
			response: { error: 'Invalid verification_level. Must be basic, document, or biometric' },
		};
	}

	if (typeof p.verified !== 'boolean') {
		return {
			status: 'reject',
			response: { error: 'Missing required field: verified (must be boolean)' },
		};
	}

	if (typeof p.issued_at !== 'number' || typeof p.expires_at !== 'number') {
		return {
			status: 'reject',
			response: { error: 'Missing required fields: issued_at and expires_at (must be numbers)' },
		};
	}

	if (!p.attestor_signature) {
		return {
			status: 'reject',
			response: { error: 'Missing required field: attestor_signature' },
		};
	}

	if (!p.session_id) {
		return {
			status: 'reject',
			response: { error: 'Missing required field: session_id' },
		};
	}

	// Step 2: Validate DID format
	if (!isValidDIDKey(p.user_did)) {
		return {
			status: 'reject',
			response: { error: 'Invalid user_did format. Expected did:key:z... with secp256k1 key' },
		};
	}

	// Step 3: Check for duplicate (idempotency)
	try {
		const db = getDatabase();

		const existing = db.exec(
			`SELECT id FROM identity_attestations
			 WHERE user_did = ? AND provider = ? AND session_id = ?`,
			[p.user_did, p.provider, p.session_id]
		);

		if (existing[0]?.values?.length) {
			return {
				status: 'reject',
				response: {
					error: 'Duplicate attestation: session already processed',
					existing_id: existing[0]?.values?.[0]?.[0] ?? null,
				},
			};
		}

		// Step 4: Store the attestation
		db.run(
			`INSERT INTO identity_attestations
			 (user_did, provider, country_code, verification_level, verified,
			  issued_at, expires_at, attestor_signature, session_id,
			  input_index, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
			[
				p.user_did,
				p.provider,
				p.country_code.toUpperCase(),
				p.verification_level,
				p.verified ? 1 : 0,
				p.issued_at,
				p.expires_at,
				p.attestor_signature,
				p.session_id,
				requestData.metadata.input_index,
			]
		);

		const idResult = db.exec('SELECT last_insert_rowid()');
		const id = idResult[0]?.values[0]?.[0] as number ?? 0;

		return {
			status: 'accept',
			response: {
				success: true,
				type: 'identity_verified',
				id,
				user_did: p.user_did,
				provider: p.provider,
				country_code: p.country_code.toUpperCase(),
				verification_level: p.verification_level,
				verified: p.verified,
				issued_at: p.issued_at,
				expires_at: p.expires_at,
				input_index: requestData.metadata.input_index,
			},
		};
	} catch (error) {
		return {
			status: 'reject',
			response: {
				error: 'Failed to store identity attestation',
				details: error instanceof Error ? error.message : String(error),
			},
		};
	}
};

// ============= Inspect Handlers =============

/**
 * Get the latest valid identity attestation for a user.
 *
 * Query params:
 * - user_did (required)
 * - provider (optional) - filter by provider
 */
export const handleInspectIdentity = async (
	query: InspectQuery
): Promise<unknown> => {
	const { user_did, provider } = query.params;

	if (!user_did) {
		return { error: 'user_did parameter required' };
	}

	try {
		const db = getDatabase();
		const now = Math.floor(Date.now() / 1000);

		let sql = `SELECT id, user_did, provider, country_code, verification_level,
		                  verified, issued_at, expires_at, attestor_signature, session_id,
		                  revoked, revoked_reason, input_index, created_at
		           FROM identity_attestations
		           WHERE user_did = ?
		             AND verified = 1
		             AND revoked = 0
		             AND expires_at > ?`;
		const params: (string | number)[] = [user_did, now];

		if (provider) {
			sql += ' AND provider = ?';
			params.push(provider);
		}

		sql += ' ORDER BY issued_at DESC LIMIT 1';

		const result = db.exec(sql, params);
		const row = result[0]?.values[0];

		if (!row) {
			return {
				verified: false,
				user_did,
				error: 'No valid identity attestation found',
			};
		}

		return {
			verified: true,
			attestation: rowToIdentityAttestation(row),
		};
	} catch (error) {
		return {
			error: 'Failed to query identity attestation',
			details: error instanceof Error ? error.message : String(error),
		};
	}
};

/**
 * Get all identity attestations for a user.
 *
 * Query params:
 * - user_did (required)
 * - limit (optional, default: 50)
 * - offset (optional, default: 0)
 */
export const handleInspectIdentityHistory = async (
	query: InspectQuery
): Promise<unknown> => {
	const { user_did, limit, offset } = query.params;

	if (!user_did) {
		return { error: 'user_did parameter required' };
	}

	try {
		const db = getDatabase();
		const limitNum = limit ? parseInt(limit, 10) : 50;
		const offsetNum = offset ? parseInt(offset, 10) : 0;

		const result = db.exec(
			`SELECT id, user_did, provider, country_code, verification_level,
			        verified, issued_at, expires_at, attestor_signature, session_id,
			        revoked, revoked_reason, input_index, created_at
			 FROM identity_attestations
			 WHERE user_did = ?
			 ORDER BY issued_at DESC
			 LIMIT ? OFFSET ?`,
			[user_did, limitNum, offsetNum]
		);

		const rows = result[0]?.values ?? [];

		return {
			user_did,
			count: rows.length,
			attestations: rows.map(rowToIdentityAttestation),
		};
	} catch (error) {
		return {
			error: 'Failed to query identity history',
			details: error instanceof Error ? error.message : String(error),
		};
	}
};

/**
 * Aggregate identity attestation counts by country.
 *
 * Query params:
 * - provider (optional) - filter by provider
 */
export const handleInspectIdentityByCountry = async (
	query: InspectQuery
): Promise<unknown> => {
	try {
		const db = getDatabase();
		const now = Math.floor(Date.now() / 1000);

		let sql = `SELECT country_code, COUNT(*) as count
		           FROM identity_attestations
		           WHERE verified = 1
		             AND revoked = 0
		             AND expires_at > ?`;
		const params: (string | number)[] = [now];

		if (query.params.provider) {
			sql += ' AND provider = ?';
			params.push(query.params.provider);
		}

		sql += ' GROUP BY country_code ORDER BY count DESC';

		const result = db.exec(sql, params);

		return {
			countries: (result[0]?.values ?? []).map(row => ({
				country_code: row[0] as string,
				count: row[1] as number,
			})),
		};
	} catch (error) {
		return {
			error: 'Failed to query identity by country',
			details: error instanceof Error ? error.message : String(error),
		};
	}
};

/**
 * Get identity attestation statistics.
 */
export const handleInspectIdentityStats = async (
	_query: InspectQuery
): Promise<unknown> => {
	try {
		const db = getDatabase();
		const now = Math.floor(Date.now() / 1000);

		const totalResult = db.exec('SELECT COUNT(*) FROM identity_attestations');
		const total = (totalResult[0]?.values[0]?.[0] as number) ?? 0;

		const activeResult = db.exec(
			`SELECT COUNT(*) FROM identity_attestations
			 WHERE verified = 1 AND revoked = 0 AND expires_at > ?`,
			[now]
		);
		const active = (activeResult[0]?.values[0]?.[0] as number) ?? 0;

		const uniqueUsersResult = db.exec(
			'SELECT COUNT(DISTINCT user_did) FROM identity_attestations'
		);
		const uniqueUsers = (uniqueUsersResult[0]?.values[0]?.[0] as number) ?? 0;

		const byProviderResult = db.exec(
			`SELECT provider, COUNT(*) as count
			 FROM identity_attestations
			 WHERE verified = 1 AND revoked = 0 AND expires_at > ?
			 GROUP BY provider ORDER BY count DESC`,
			[now]
		);
		const byProvider: Record<string, number> = {};
		for (const row of byProviderResult[0]?.values ?? []) {
			byProvider[row[0] as string] = row[1] as number;
		}

		const byCountryResult = db.exec(
			`SELECT country_code, COUNT(*) as count
			 FROM identity_attestations
			 WHERE verified = 1 AND revoked = 0 AND expires_at > ?
			 GROUP BY country_code ORDER BY count DESC`,
			[now]
		);
		const byCountry: Record<string, number> = {};
		for (const row of byCountryResult[0]?.values ?? []) {
			byCountry[row[0] as string] = row[1] as number;
		}

		return {
			total,
			active,
			unique_users: uniqueUsers,
			by_provider: byProvider,
			by_country: byCountry,
		};
	} catch (error) {
		return {
			error: 'Failed to get identity stats',
			details: error instanceof Error ? error.message : String(error),
		};
	}
};

// ============= Helpers =============

function rowToIdentityAttestation(row: unknown[]): IdentityAttestation {
	return {
		id: row[0] as number,
		user_did: row[1] as string,
		provider: row[2] as string,
		country_code: row[3] as string,
		verification_level: row[4] as string,
		verified: Boolean(row[5]),
		issued_at: row[6] as number,
		expires_at: row[7] as number,
		attestor_signature: row[8] as string,
		session_id: row[9] as string,
		revoked: Boolean(row[10]),
		revoked_reason: row[11] as string | null,
		input_index: row[12] as number,
		created_at: row[13] as string,
	};
}
