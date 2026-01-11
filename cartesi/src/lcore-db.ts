/**
 * L{CORE} SDK Database Layer
 *
 * This module provides the attestation-focused database schema for the L{CORE} SDK.
 * It implements the hybrid schema design with:
 * - attestations (core metadata)
 * - attestation_buckets (discovery layer - public)
 * - attestation_data (private layer - encrypted)
 * - access_grants (gated access control)
 * - provider_schemas (modular schema registry)
 * - schema_admins (authorization whitelist)
 */

import { getDatabase } from './db';

// ============= Types =============

export interface Attestation {
  id: string;
  attestation_hash: string;
  owner_address: string;
  domain: string;
  provider: string;
  flow_type: string;
  attested_at_input: number;
  valid_from: number;
  valid_until: number | null;
  tee_signature: string;
  status: string;
  freshness_score: number;
  superseded_by: string | null;
  created_input: number;
}

export interface AttestationBucket {
  attestation_id: string;
  bucket_key: string;
  bucket_value: string;
}

export interface AttestationData {
  attestation_id: string;
  data_key: string;
  encrypted_value: Uint8Array;
  encryption_key_id: string;
}

export interface AccessGrant {
  id: string;
  attestation_id: string;
  grantee_address: string;
  granted_by: string;
  data_keys: string | null; // JSON array, null = all
  grant_type: string; // 'full', 'partial', 'aggregate'
  granted_at_input: number;
  expires_at_input: number | null;
  revoked_at_input: number | null;
  status: string;
}

export interface ProviderSchema {
  provider: string;
  flow_type: string;
  version: number;
  domain: string;
  registered_by: string;
  registered_at_input: number;
  bucket_definitions: string; // JSON
  data_keys: string; // JSON array
  freshness_half_life: number;
  min_freshness: number;
  status: string;
}

export interface SchemaAdmin {
  wallet_address: string;
  added_by: string;
  added_at_input: number;
  can_add_providers: boolean;
  can_add_admins: boolean;
}

// ============= Input Types =============

export interface AttestationInput {
  id: string;
  attestation_hash: string;
  owner_address: string;
  domain: string;
  provider: string;
  flow_type: string;
  attested_at_input: number;
  valid_from: number;
  valid_until?: number;
  tee_signature: string;
  created_input: number;
}

export interface BucketInput {
  bucket_key: string;
  bucket_value: string;
}

export interface DataInput {
  data_key: string;
  encrypted_value: Uint8Array;
  encryption_key_id: string;
}

export interface AccessGrantInput {
  id: string;
  attestation_id: string;
  grantee_address: string;
  granted_by: string;
  data_keys?: string[]; // null = all
  grant_type: 'full' | 'partial' | 'aggregate';
  granted_at_input: number;
  expires_at_input?: number;
}

export interface ProviderSchemaInput {
  provider: string;
  flow_type: string;
  domain: string;
  registered_by: string;
  registered_at_input: number;
  bucket_definitions: Record<string, {
    boundaries: number[];
    labels: string[];
  }>;
  data_keys: string[];
  freshness_half_life: number;
  min_freshness?: number;
}

// ============= Schema Initialization =============

/**
 * Initialize L{CORE} SDK schema tables.
 * Call this after initDatabase() from db.ts
 */
export function initLCoreSchema(): void {
  const db = getDatabase();

  db.run(`
    -- ============= L{CORE} ATTESTATIONS =============

    -- Core attestation metadata
    CREATE TABLE IF NOT EXISTS attestations (
      id TEXT PRIMARY KEY,
      attestation_hash TEXT UNIQUE NOT NULL,
      owner_address TEXT NOT NULL,

      domain TEXT NOT NULL,
      provider TEXT NOT NULL,
      flow_type TEXT NOT NULL,

      attested_at_input INTEGER NOT NULL,
      valid_from INTEGER NOT NULL,
      valid_until INTEGER,

      tee_signature TEXT NOT NULL,
      status TEXT DEFAULT 'active',
      freshness_score INTEGER DEFAULT 100,
      superseded_by TEXT,

      created_input INTEGER NOT NULL
    );

    -- Discovery layer: public bucket key-value pairs
    CREATE TABLE IF NOT EXISTS attestation_buckets (
      attestation_id TEXT NOT NULL,
      bucket_key TEXT NOT NULL,
      bucket_value TEXT NOT NULL,
      PRIMARY KEY (attestation_id, bucket_key),
      FOREIGN KEY (attestation_id) REFERENCES attestations(id) ON DELETE CASCADE
    );

    -- Private layer: encrypted data chunks
    CREATE TABLE IF NOT EXISTS attestation_data (
      attestation_id TEXT NOT NULL,
      data_key TEXT NOT NULL,
      encrypted_value BLOB NOT NULL,
      encryption_key_id TEXT NOT NULL,
      PRIMARY KEY (attestation_id, data_key),
      FOREIGN KEY (attestation_id) REFERENCES attestations(id) ON DELETE CASCADE
    );

    -- ============= ACCESS CONTROL =============

    -- Access grants for gated data access
    CREATE TABLE IF NOT EXISTS access_grants (
      id TEXT PRIMARY KEY,
      attestation_id TEXT NOT NULL,
      grantee_address TEXT NOT NULL,
      granted_by TEXT NOT NULL,

      data_keys TEXT,
      grant_type TEXT NOT NULL,

      granted_at_input INTEGER NOT NULL,
      expires_at_input INTEGER,
      revoked_at_input INTEGER,

      status TEXT DEFAULT 'active',

      FOREIGN KEY (attestation_id) REFERENCES attestations(id) ON DELETE CASCADE
    );

    -- ============= PROVIDER SCHEMA REGISTRY =============

    -- Modular schema definitions per provider/flow
    CREATE TABLE IF NOT EXISTS provider_schemas (
      provider TEXT NOT NULL,
      flow_type TEXT NOT NULL,
      version INTEGER NOT NULL,
      domain TEXT NOT NULL,

      registered_by TEXT NOT NULL,
      registered_at_input INTEGER NOT NULL,

      bucket_definitions TEXT NOT NULL,
      data_keys TEXT NOT NULL,
      freshness_half_life INTEGER NOT NULL,
      min_freshness INTEGER DEFAULT 0,

      status TEXT DEFAULT 'active',

      PRIMARY KEY (provider, flow_type, version)
    );

    -- Schema admin whitelist
    CREATE TABLE IF NOT EXISTS schema_admins (
      wallet_address TEXT PRIMARY KEY,
      added_by TEXT NOT NULL,
      added_at_input INTEGER NOT NULL,
      can_add_providers INTEGER DEFAULT 1,
      can_add_admins INTEGER DEFAULT 0
    );

    -- ============= INDEXES =============

    CREATE INDEX IF NOT EXISTS idx_att_owner ON attestations(owner_address);
    CREATE INDEX IF NOT EXISTS idx_att_domain ON attestations(domain);
    CREATE INDEX IF NOT EXISTS idx_att_provider ON attestations(provider);
    CREATE INDEX IF NOT EXISTS idx_att_domain_provider ON attestations(domain, provider);
    CREATE INDEX IF NOT EXISTS idx_att_status ON attestations(status);
    CREATE INDEX IF NOT EXISTS idx_att_freshness ON attestations(freshness_score DESC);
    CREATE INDEX IF NOT EXISTS idx_att_hash ON attestations(attestation_hash);

    CREATE INDEX IF NOT EXISTS idx_bucket_key ON attestation_buckets(bucket_key);
    CREATE INDEX IF NOT EXISTS idx_bucket_value ON attestation_buckets(bucket_key, bucket_value);

    CREATE INDEX IF NOT EXISTS idx_grant_attestation ON access_grants(attestation_id);
    CREATE INDEX IF NOT EXISTS idx_grant_grantee ON access_grants(grantee_address);
    CREATE INDEX IF NOT EXISTS idx_grant_status ON access_grants(status);

    CREATE INDEX IF NOT EXISTS idx_schema_provider ON provider_schemas(provider);
    CREATE INDEX IF NOT EXISTS idx_schema_domain ON provider_schemas(domain);
  `);

  console.log('L{CORE} SDK schema initialized');
}

// ============= Attestation Operations =============

/**
 * Create a new attestation with buckets and encrypted data
 */
export function createAttestation(
  input: AttestationInput,
  buckets: BucketInput[],
  data: DataInput[]
): Attestation {
  const db = getDatabase();

  // Insert attestation
  db.run(
    `INSERT INTO attestations
     (id, attestation_hash, owner_address, domain, provider, flow_type,
      attested_at_input, valid_from, valid_until, tee_signature, created_input)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.id,
      input.attestation_hash,
      input.owner_address,
      input.domain,
      input.provider,
      input.flow_type,
      input.attested_at_input,
      input.valid_from,
      input.valid_until ?? null,
      input.tee_signature,
      input.created_input,
    ]
  );

  // Insert buckets
  for (const bucket of buckets) {
    db.run(
      `INSERT INTO attestation_buckets (attestation_id, bucket_key, bucket_value)
       VALUES (?, ?, ?)`,
      [input.id, bucket.bucket_key, bucket.bucket_value]
    );
  }

  // Insert encrypted data
  for (const d of data) {
    db.run(
      `INSERT INTO attestation_data (attestation_id, data_key, encrypted_value, encryption_key_id)
       VALUES (?, ?, ?, ?)`,
      [input.id, d.data_key, d.encrypted_value, d.encryption_key_id]
    );
  }

  return getAttestationById(input.id)!;
}

/**
 * Get attestation by ID
 */
export function getAttestationById(id: string): Attestation | null {
  const db = getDatabase();
  const result = db.exec(
    `SELECT id, attestation_hash, owner_address, domain, provider, flow_type,
            attested_at_input, valid_from, valid_until, tee_signature, status,
            freshness_score, superseded_by, created_input
     FROM attestations WHERE id = ?`,
    [id]
  );

  const row = result[0]?.values[0];
  if (!row) return null;

  return rowToAttestation(row);
}

/**
 * Get attestation by hash
 */
export function getAttestationByHash(hash: string): Attestation | null {
  const db = getDatabase();
  const result = db.exec(
    `SELECT id, attestation_hash, owner_address, domain, provider, flow_type,
            attested_at_input, valid_from, valid_until, tee_signature, status,
            freshness_score, superseded_by, created_input
     FROM attestations WHERE attestation_hash = ?`,
    [hash]
  );

  const row = result[0]?.values[0];
  if (!row) return null;

  return rowToAttestation(row);
}

/**
 * Get attestations by owner
 */
export function getAttestationsByOwner(
  ownerAddress: string,
  options?: {
    domain?: string;
    provider?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }
): Attestation[] {
  const db = getDatabase();
  let query = `SELECT id, attestation_hash, owner_address, domain, provider, flow_type,
                      attested_at_input, valid_from, valid_until, tee_signature, status,
                      freshness_score, superseded_by, created_input
               FROM attestations WHERE owner_address = ?`;
  const params: (string | number)[] = [ownerAddress];

  if (options?.domain) {
    query += ' AND domain = ?';
    params.push(options.domain);
  }
  if (options?.provider) {
    query += ' AND provider = ?';
    params.push(options.provider);
  }
  if (options?.status) {
    query += ' AND status = ?';
    params.push(options.status);
  }

  query += ' ORDER BY created_input DESC';

  if (options?.limit) {
    query += ' LIMIT ?';
    params.push(options.limit);
  }
  if (options?.offset) {
    query += ' OFFSET ?';
    params.push(options.offset);
  }

  const result = db.exec(query, params);
  return (result[0]?.values ?? []).map(rowToAttestation);
}

/**
 * Query attestations by multiple bucket criteria (AND logic)
 * Use this for complex queries matching multiple bucket conditions
 */
export function queryAttestationsByMultipleBuckets(
  criteria: Array<{ bucket_key: string; bucket_values: string[] }>,
  options?: {
    domain?: string;
    provider?: string;
    status?: string;
    min_freshness?: number;
    limit?: number;
  }
): Attestation[] {
  const db = getDatabase();

  // Build dynamic query with bucket joins
  let query = `SELECT DISTINCT a.id, a.attestation_hash, a.owner_address, a.domain,
                      a.provider, a.flow_type, a.attested_at_input, a.valid_from,
                      a.valid_until, a.tee_signature, a.status, a.freshness_score,
                      a.superseded_by, a.created_input
               FROM attestations a`;

  const params: (string | number)[] = [];

  // Join bucket tables for each criterion
  criteria.forEach((c, i) => {
    query += ` JOIN attestation_buckets b${i} ON a.id = b${i}.attestation_id`;
  });

  query += ' WHERE 1=1';

  // Add bucket conditions
  criteria.forEach((c, i) => {
    query += ` AND b${i}.bucket_key = ? AND b${i}.bucket_value IN (${c.bucket_values.map(() => '?').join(',')})`;
    params.push(c.bucket_key, ...c.bucket_values);
  });

  if (options?.domain) {
    query += ' AND a.domain = ?';
    params.push(options.domain);
  }
  if (options?.provider) {
    query += ' AND a.provider = ?';
    params.push(options.provider);
  }
  if (options?.status) {
    query += ' AND a.status = ?';
    params.push(options.status);
  }
  if (options?.min_freshness) {
    query += ' AND a.freshness_score >= ?';
    params.push(options.min_freshness);
  }

  query += ' ORDER BY a.freshness_score DESC';

  if (options?.limit) {
    query += ' LIMIT ?';
    params.push(options.limit);
  }

  const result = db.exec(query, params);
  return (result[0]?.values ?? []).map(rowToAttestation);
}

/**
 * Update attestation status
 */
export function updateAttestationStatus(
  id: string,
  status: 'active' | 'expired' | 'revoked' | 'superseded',
  supersededBy?: string
): boolean {
  const db = getDatabase();

  if (supersededBy) {
    db.run(
      `UPDATE attestations SET status = ?, superseded_by = ? WHERE id = ?`,
      [status, supersededBy, id]
    );
  } else {
    db.run(
      `UPDATE attestations SET status = ? WHERE id = ?`,
      [status, id]
    );
  }

  const result = db.exec(`SELECT status FROM attestations WHERE id = ?`, [id]);
  return result[0]?.values[0]?.[0] === status;
}

/**
 * Update freshness scores based on decay
 */
export function updateFreshnessScores(currentInput: number): number {
  const db = getDatabase();

  // Get all active attestations with their schema's half-life
  const result = db.exec(`
    SELECT a.id, a.attested_at_input, ps.freshness_half_life, ps.min_freshness
    FROM attestations a
    JOIN provider_schemas ps ON a.provider = ps.provider
      AND a.flow_type = ps.flow_type
      AND ps.status = 'active'
    WHERE a.status = 'active'
  `);

  let updatedCount = 0;
  const rows = result[0]?.values ?? [];

  for (const row of rows) {
    const id = row[0] as string;
    const attestedAt = row[1] as number;
    const halfLife = row[2] as number;
    const minFreshness = row[3] as number;

    // Calculate age in "input units" (treating inputs as time proxy)
    const age = currentInput - attestedAt;

    // Exponential decay: freshness = 100 * 0.5^(age/halfLife)
    const freshness = Math.max(
      minFreshness,
      Math.floor(100 * Math.pow(0.5, age / halfLife))
    );

    db.run(
      `UPDATE attestations SET freshness_score = ? WHERE id = ?`,
      [freshness, id]
    );
    updatedCount++;
  }

  return updatedCount;
}

// ============= Bucket Operations =============

/**
 * Get buckets for an attestation
 */
export function getAttestationBuckets(attestationId: string): AttestationBucket[] {
  const db = getDatabase();
  const result = db.exec(
    `SELECT attestation_id, bucket_key, bucket_value
     FROM attestation_buckets WHERE attestation_id = ?`,
    [attestationId]
  );

  return (result[0]?.values ?? []).map(row => ({
    attestation_id: row[0] as string,
    bucket_key: row[1] as string,
    bucket_value: row[2] as string,
  }));
}

/**
 * Aggregate attestations by bucket
 */
export function aggregateByBucket(
  bucketKey: string,
  options?: {
    domain?: string;
    provider?: string;
    status?: string;
    min_freshness?: number;
  }
): Array<{ bucket_value: string; count: number }> {
  const db = getDatabase();

  let query = `SELECT b.bucket_value, COUNT(DISTINCT a.owner_address) as count
               FROM attestation_buckets b
               JOIN attestations a ON b.attestation_id = a.id
               WHERE b.bucket_key = ?`;
  const params: (string | number)[] = [bucketKey];

  if (options?.domain) {
    query += ' AND a.domain = ?';
    params.push(options.domain);
  }
  if (options?.provider) {
    query += ' AND a.provider = ?';
    params.push(options.provider);
  }
  if (options?.status) {
    query += ' AND a.status = ?';
    params.push(options.status);
  }
  if (options?.min_freshness) {
    query += ' AND a.freshness_score >= ?';
    params.push(options.min_freshness);
  }

  query += ' GROUP BY b.bucket_value ORDER BY count DESC';

  const result = db.exec(query, params);
  return (result[0]?.values ?? []).map(row => ({
    bucket_value: row[0] as string,
    count: row[1] as number,
  }));
}

// ============= Data Operations =============

/**
 * Get encrypted data for an attestation
 */
export function getAttestationData(
  attestationId: string,
  dataKeys?: string[]
): AttestationData[] {
  const db = getDatabase();

  let query = `SELECT attestation_id, data_key, encrypted_value, encryption_key_id
               FROM attestation_data WHERE attestation_id = ?`;
  const params: string[] = [attestationId];

  if (dataKeys && dataKeys.length > 0) {
    query += ` AND data_key IN (${dataKeys.map(() => '?').join(',')})`;
    params.push(...dataKeys);
  }

  const result = db.exec(query, params);
  return (result[0]?.values ?? []).map(row => ({
    attestation_id: row[0] as string,
    data_key: row[1] as string,
    encrypted_value: row[2] as Uint8Array,
    encryption_key_id: row[3] as string,
  }));
}

// ============= Access Grant Operations =============

/**
 * Create an access grant
 */
export function createAccessGrant(input: AccessGrantInput): AccessGrant {
  const db = getDatabase();

  db.run(
    `INSERT INTO access_grants
     (id, attestation_id, grantee_address, granted_by, data_keys, grant_type,
      granted_at_input, expires_at_input)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.id,
      input.attestation_id,
      input.grantee_address,
      input.granted_by,
      input.data_keys ? JSON.stringify(input.data_keys) : null,
      input.grant_type,
      input.granted_at_input,
      input.expires_at_input ?? null,
    ]
  );

  return getAccessGrantById(input.id)!;
}

/**
 * Get access grant by ID
 */
export function getAccessGrantById(id: string): AccessGrant | null {
  const db = getDatabase();
  const result = db.exec(
    `SELECT id, attestation_id, grantee_address, granted_by, data_keys, grant_type,
            granted_at_input, expires_at_input, revoked_at_input, status
     FROM access_grants WHERE id = ?`,
    [id]
  );

  const row = result[0]?.values[0];
  if (!row) return null;

  return rowToAccessGrant(row);
}

/**
 * Check if grantee has valid access to attestation
 */
export function checkAccess(
  attestationId: string,
  granteeAddress: string,
  currentInput: number,
  dataKey?: string
): { hasAccess: boolean; grant: AccessGrant | null } {
  const db = getDatabase();

  let query = `SELECT id, attestation_id, grantee_address, granted_by, data_keys, grant_type,
                      granted_at_input, expires_at_input, revoked_at_input, status
               FROM access_grants
               WHERE attestation_id = ?
                 AND grantee_address = ?
                 AND status = 'active'
                 AND (expires_at_input IS NULL OR expires_at_input > ?)`;
  const params: (string | number)[] = [attestationId, granteeAddress, currentInput];

  const result = db.exec(query, params);
  const rows = result[0]?.values ?? [];

  for (const row of rows) {
    const grant = rowToAccessGrant(row);

    // If no specific data_key requested, any grant works
    if (!dataKey) {
      return { hasAccess: true, grant };
    }

    // If grant has no data_keys restriction (null = all), it's valid
    if (!grant.data_keys) {
      return { hasAccess: true, grant };
    }

    // Check if requested data_key is in the grant
    const allowedKeys = JSON.parse(grant.data_keys) as string[];
    if (allowedKeys.includes(dataKey)) {
      return { hasAccess: true, grant };
    }
  }

  return { hasAccess: false, grant: null };
}

/**
 * Revoke an access grant
 */
export function revokeAccessGrant(id: string, revokedAtInput: number): boolean {
  const db = getDatabase();

  db.run(
    `UPDATE access_grants SET status = 'revoked', revoked_at_input = ? WHERE id = ?`,
    [revokedAtInput, id]
  );

  const result = db.exec(`SELECT status FROM access_grants WHERE id = ?`, [id]);
  return result[0]?.values[0]?.[0] === 'revoked';
}

/**
 * Get all grants for an attestation
 */
export function getGrantsByAttestation(attestationId: string): AccessGrant[] {
  const db = getDatabase();
  const result = db.exec(
    `SELECT id, attestation_id, grantee_address, granted_by, data_keys, grant_type,
            granted_at_input, expires_at_input, revoked_at_input, status
     FROM access_grants WHERE attestation_id = ?`,
    [attestationId]
  );

  return (result[0]?.values ?? []).map(rowToAccessGrant);
}

/**
 * Get all grants for a grantee
 */
export function getGrantsByGrantee(granteeAddress: string, activeOnly = true): AccessGrant[] {
  const db = getDatabase();
  let query = `SELECT id, attestation_id, grantee_address, granted_by, data_keys, grant_type,
                      granted_at_input, expires_at_input, revoked_at_input, status
               FROM access_grants WHERE grantee_address = ?`;

  if (activeOnly) {
    query += ` AND status = 'active'`;
  }

  const result = db.exec(query, [granteeAddress]);
  return (result[0]?.values ?? []).map(rowToAccessGrant);
}

// ============= Provider Schema Operations =============

/**
 * Register a new provider schema
 */
export function registerProviderSchema(input: ProviderSchemaInput): ProviderSchema {
  const db = getDatabase();

  // Get next version number
  const versionResult = db.exec(
    `SELECT MAX(version) FROM provider_schemas WHERE provider = ? AND flow_type = ?`,
    [input.provider, input.flow_type]
  );
  const currentVersion = (versionResult[0]?.values[0]?.[0] as number) ?? 0;
  const newVersion = currentVersion + 1;

  db.run(
    `INSERT INTO provider_schemas
     (provider, flow_type, version, domain, registered_by, registered_at_input,
      bucket_definitions, data_keys, freshness_half_life, min_freshness)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      input.provider,
      input.flow_type,
      newVersion,
      input.domain,
      input.registered_by,
      input.registered_at_input,
      JSON.stringify(input.bucket_definitions),
      JSON.stringify(input.data_keys),
      input.freshness_half_life,
      input.min_freshness ?? 0,
    ]
  );

  return getProviderSchema(input.provider, input.flow_type)!;
}

/**
 * Get active provider schema (latest version)
 */
export function getProviderSchema(provider: string, flowType: string): ProviderSchema | null {
  const db = getDatabase();
  const result = db.exec(
    `SELECT provider, flow_type, version, domain, registered_by, registered_at_input,
            bucket_definitions, data_keys, freshness_half_life, min_freshness, status
     FROM provider_schemas
     WHERE provider = ? AND flow_type = ? AND status = 'active'
     ORDER BY version DESC LIMIT 1`,
    [provider, flowType]
  );

  const row = result[0]?.values[0];
  if (!row) return null;

  return rowToProviderSchema(row);
}

/**
 * Get all provider schemas
 */
export function getAllProviderSchemas(activeOnly = true): ProviderSchema[] {
  const db = getDatabase();
  let query = `SELECT provider, flow_type, version, domain, registered_by, registered_at_input,
                      bucket_definitions, data_keys, freshness_half_life, min_freshness, status
               FROM provider_schemas`;

  if (activeOnly) {
    query += ` WHERE status = 'active'`;
  }

  query += ' ORDER BY provider, flow_type, version DESC';

  const result = db.exec(query);
  return (result[0]?.values ?? []).map(rowToProviderSchema);
}

/**
 * Deprecate a provider schema
 */
export function deprecateProviderSchema(provider: string, flowType: string, version: number): boolean {
  const db = getDatabase();

  db.run(
    `UPDATE provider_schemas SET status = 'deprecated' WHERE provider = ? AND flow_type = ? AND version = ?`,
    [provider, flowType, version]
  );

  const result = db.exec(
    `SELECT status FROM provider_schemas WHERE provider = ? AND flow_type = ? AND version = ?`,
    [provider, flowType, version]
  );
  return result[0]?.values[0]?.[0] === 'deprecated';
}

// ============= Schema Admin Operations =============

/**
 * Add a schema admin
 */
export function addSchemaAdmin(
  walletAddress: string,
  addedBy: string,
  addedAtInput: number,
  canAddProviders = true,
  canAddAdmins = false
): SchemaAdmin {
  const db = getDatabase();

  db.run(
    `INSERT INTO schema_admins (wallet_address, added_by, added_at_input, can_add_providers, can_add_admins)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(wallet_address) DO UPDATE SET
       can_add_providers = excluded.can_add_providers,
       can_add_admins = excluded.can_add_admins`,
    [walletAddress, addedBy, addedAtInput, canAddProviders ? 1 : 0, canAddAdmins ? 1 : 0]
  );

  return getSchemaAdmin(walletAddress)!;
}

/**
 * Check if wallet is schema admin
 */
export function isSchemaAdmin(walletAddress: string): boolean {
  const db = getDatabase();
  const result = db.exec(
    `SELECT 1 FROM schema_admins WHERE wallet_address = ?`,
    [walletAddress]
  );
  return (result[0]?.values?.length ?? 0) > 0;
}

/**
 * Check if wallet can add providers
 */
export function canAddProviders(walletAddress: string): boolean {
  const db = getDatabase();
  const result = db.exec(
    `SELECT can_add_providers FROM schema_admins WHERE wallet_address = ?`,
    [walletAddress]
  );
  return Boolean(result[0]?.values[0]?.[0]);
}

/**
 * Check if wallet can add admins
 */
export function canAddAdmins(walletAddress: string): boolean {
  const db = getDatabase();
  const result = db.exec(
    `SELECT can_add_admins FROM schema_admins WHERE wallet_address = ?`,
    [walletAddress]
  );
  return Boolean(result[0]?.values[0]?.[0]);
}

/**
 * Get schema admin
 */
export function getSchemaAdmin(walletAddress: string): SchemaAdmin | null {
  const db = getDatabase();
  const result = db.exec(
    `SELECT wallet_address, added_by, added_at_input, can_add_providers, can_add_admins
     FROM schema_admins WHERE wallet_address = ?`,
    [walletAddress]
  );

  const row = result[0]?.values[0];
  if (!row) return null;

  return {
    wallet_address: row[0] as string,
    added_by: row[1] as string,
    added_at_input: row[2] as number,
    can_add_providers: Boolean(row[3]),
    can_add_admins: Boolean(row[4]),
  };
}

/**
 * Get all schema admins
 */
export function getAllSchemaAdmins(): SchemaAdmin[] {
  const db = getDatabase();
  const result = db.exec(
    `SELECT wallet_address, added_by, added_at_input, can_add_providers, can_add_admins
     FROM schema_admins`
  );

  return (result[0]?.values ?? []).map(row => ({
    wallet_address: row[0] as string,
    added_by: row[1] as string,
    added_at_input: row[2] as number,
    can_add_providers: Boolean(row[3]),
    can_add_admins: Boolean(row[4]),
  }));
}

/**
 * Remove schema admin
 */
export function removeSchemaAdmin(walletAddress: string): boolean {
  const db = getDatabase();
  db.run(`DELETE FROM schema_admins WHERE wallet_address = ?`, [walletAddress]);
  return !isSchemaAdmin(walletAddress);
}

// ============= Discovery Query Operations =============

export interface AttestationWithBuckets extends Attestation {
  buckets: Array<{ key: string; value: string }>;
}

/**
 * Query attestations by bucket value (for discovery)
 */
export function queryAttestationsByBucket(options: {
  domain: string;
  provider?: string;
  bucketKey: string;
  bucketValue: string;
  minFreshness?: number;
  limit?: number;
  offset?: number;
}): AttestationWithBuckets[] {
  const db = getDatabase();

  let query = `
    SELECT DISTINCT a.id, a.attestation_hash, a.owner_address, a.domain,
           a.provider, a.flow_type, a.attested_at_input, a.valid_from,
           a.valid_until, a.tee_signature, a.status, a.freshness_score,
           a.superseded_by, a.created_input
    FROM attestations a
    JOIN attestation_buckets b ON a.id = b.attestation_id
    WHERE a.domain = ?
      AND a.status = 'active'
      AND b.bucket_key = ?
      AND b.bucket_value = ?`;

  const params: (string | number)[] = [options.domain, options.bucketKey, options.bucketValue];

  if (options.provider) {
    query += ' AND a.provider = ?';
    params.push(options.provider);
  }

  if (options.minFreshness) {
    query += ' AND a.freshness_score >= ?';
    params.push(options.minFreshness);
  }

  query += ' ORDER BY a.freshness_score DESC';

  if (options.limit) {
    query += ' LIMIT ?';
    params.push(options.limit);
  }

  if (options.offset) {
    query += ' OFFSET ?';
    params.push(options.offset);
  }

  const result = db.exec(query, params);
  const attestations = (result[0]?.values ?? []).map(rowToAttestation);

  // Fetch buckets for each attestation
  return attestations.map(att => ({
    ...att,
    buckets: getAttestationBuckets(att.id).map(b => ({ key: b.bucket_key, value: b.bucket_value })),
  }));
}

/**
 * Query attestations by domain with filters
 */
export function queryAttestationsByDomain(options: {
  domain: string;
  provider?: string;
  flowType?: string;
  status?: string;
  minFreshness?: number;
  limit?: number;
  offset?: number;
}): AttestationWithBuckets[] {
  const db = getDatabase();

  let query = `
    SELECT id, attestation_hash, owner_address, domain, provider, flow_type,
           attested_at_input, valid_from, valid_until, tee_signature, status,
           freshness_score, superseded_by, created_input
    FROM attestations
    WHERE domain = ?`;

  const params: (string | number)[] = [options.domain];

  if (options.provider) {
    query += ' AND provider = ?';
    params.push(options.provider);
  }

  if (options.flowType) {
    query += ' AND flow_type = ?';
    params.push(options.flowType);
  }

  if (options.status) {
    query += ' AND status = ?';
    params.push(options.status);
  }

  if (options.minFreshness) {
    query += ' AND freshness_score >= ?';
    params.push(options.minFreshness);
  }

  query += ' ORDER BY freshness_score DESC';

  if (options.limit) {
    query += ' LIMIT ?';
    params.push(options.limit);
  }

  if (options.offset) {
    query += ' OFFSET ?';
    params.push(options.offset);
  }

  const result = db.exec(query, params);
  const attestations = (result[0]?.values ?? []).map(rowToAttestation);

  return attestations.map(att => ({
    ...att,
    buckets: getAttestationBuckets(att.id).map(b => ({ key: b.bucket_key, value: b.bucket_value })),
  }));
}

/**
 * Count attestations by bucket value
 */
export function countByBucket(options: {
  domain: string;
  provider?: string;
  bucketKey: string;
  minFreshness?: number;
}): Array<{ bucket_value: string; count: number }> {
  const db = getDatabase();

  let query = `
    SELECT b.bucket_value, COUNT(DISTINCT a.id) as count
    FROM attestation_buckets b
    JOIN attestations a ON b.attestation_id = a.id
    WHERE a.domain = ?
      AND a.status = 'active'
      AND b.bucket_key = ?`;

  const params: (string | number)[] = [options.domain, options.bucketKey];

  if (options.provider) {
    query += ' AND a.provider = ?';
    params.push(options.provider);
  }

  if (options.minFreshness) {
    query += ' AND a.freshness_score >= ?';
    params.push(options.minFreshness);
  }

  query += ' GROUP BY b.bucket_value ORDER BY count DESC';

  const result = db.exec(query, params);
  return (result[0]?.values ?? []).map(row => ({
    bucket_value: row[0] as string,
    count: row[1] as number,
  }));
}

/**
 * Count attestations by domain
 */
export function countByDomain(): Array<{ domain: string; count: number }> {
  const db = getDatabase();

  const result = db.exec(`
    SELECT domain, COUNT(*) as count
    FROM attestations
    WHERE status = 'active'
    GROUP BY domain
    ORDER BY count DESC
  `);

  return (result[0]?.values ?? []).map(row => ({
    domain: row[0] as string,
    count: row[1] as number,
  }));
}

/**
 * Count attestations by provider within a domain
 */
export function countByProvider(domain: string): Array<{ provider: string; flow_type: string; count: number }> {
  const db = getDatabase();

  const result = db.exec(`
    SELECT provider, flow_type, COUNT(*) as count
    FROM attestations
    WHERE domain = ?
      AND status = 'active'
    GROUP BY provider, flow_type
    ORDER BY count DESC
  `, [domain]);

  return (result[0]?.values ?? []).map(row => ({
    provider: row[0] as string,
    flow_type: row[1] as string,
    count: row[2] as number,
  }));
}

/**
 * Aggregate freshness statistics
 */
export function aggregateFreshness(options: {
  domain: string;
  provider?: string;
}): { count: number; avg_freshness: number; min_freshness: number; max_freshness: number } {
  const db = getDatabase();

  let query = `
    SELECT COUNT(*) as count,
           AVG(freshness_score) as avg_freshness,
           MIN(freshness_score) as min_freshness,
           MAX(freshness_score) as max_freshness
    FROM attestations
    WHERE domain = ?
      AND status = 'active'`;

  const params: string[] = [options.domain];

  if (options.provider) {
    query += ' AND provider = ?';
    params.push(options.provider);
  }

  const result = db.exec(query, params);
  const row = result[0]?.values[0];

  if (!row) {
    return { count: 0, avg_freshness: 0, min_freshness: 0, max_freshness: 0 };
  }

  return {
    count: (row[0] as number) ?? 0,
    avg_freshness: (row[1] as number) ?? 0,
    min_freshness: (row[2] as number) ?? 0,
    max_freshness: (row[3] as number) ?? 0,
  };
}

// ============= Statistics =============

export interface LCoreStats {
  total_attestations: number;
  active_attestations: number;
  attestations_by_domain: Record<string, number>;
  attestations_by_provider: Record<string, number>;
  total_access_grants: number;
  active_access_grants: number;
  total_provider_schemas: number;
  total_schema_admins: number;
}

export function getLCoreStats(): LCoreStats {
  const db = getDatabase();

  const totalAtts = db.exec('SELECT COUNT(*) FROM attestations')[0]?.values[0]?.[0] as number ?? 0;
  const activeAtts = db.exec(`SELECT COUNT(*) FROM attestations WHERE status = 'active'`)[0]?.values[0]?.[0] as number ?? 0;
  const totalGrants = db.exec('SELECT COUNT(*) FROM access_grants')[0]?.values[0]?.[0] as number ?? 0;
  const activeGrants = db.exec(`SELECT COUNT(*) FROM access_grants WHERE status = 'active'`)[0]?.values[0]?.[0] as number ?? 0;
  const totalSchemas = db.exec('SELECT COUNT(*) FROM provider_schemas')[0]?.values[0]?.[0] as number ?? 0;
  const totalAdmins = db.exec('SELECT COUNT(*) FROM schema_admins')[0]?.values[0]?.[0] as number ?? 0;

  // By domain
  const domainResult = db.exec('SELECT domain, COUNT(*) FROM attestations GROUP BY domain');
  const byDomain: Record<string, number> = {};
  for (const row of domainResult[0]?.values ?? []) {
    byDomain[row[0] as string] = row[1] as number;
  }

  // By provider
  const providerResult = db.exec('SELECT provider, COUNT(*) FROM attestations GROUP BY provider');
  const byProvider: Record<string, number> = {};
  for (const row of providerResult[0]?.values ?? []) {
    byProvider[row[0] as string] = row[1] as number;
  }

  return {
    total_attestations: totalAtts,
    active_attestations: activeAtts,
    attestations_by_domain: byDomain,
    attestations_by_provider: byProvider,
    total_access_grants: totalGrants,
    active_access_grants: activeGrants,
    total_provider_schemas: totalSchemas,
    total_schema_admins: totalAdmins,
  };
}

// ============= Helper Functions =============

function rowToAttestation(row: unknown[]): Attestation {
  return {
    id: row[0] as string,
    attestation_hash: row[1] as string,
    owner_address: row[2] as string,
    domain: row[3] as string,
    provider: row[4] as string,
    flow_type: row[5] as string,
    attested_at_input: row[6] as number,
    valid_from: row[7] as number,
    valid_until: row[8] as number | null,
    tee_signature: row[9] as string,
    status: row[10] as string,
    freshness_score: row[11] as number,
    superseded_by: row[12] as string | null,
    created_input: row[13] as number,
  };
}

function rowToAccessGrant(row: unknown[]): AccessGrant {
  return {
    id: row[0] as string,
    attestation_id: row[1] as string,
    grantee_address: row[2] as string,
    granted_by: row[3] as string,
    data_keys: row[4] as string | null,
    grant_type: row[5] as string,
    granted_at_input: row[6] as number,
    expires_at_input: row[7] as number | null,
    revoked_at_input: row[8] as number | null,
    status: row[9] as string,
  };
}

function rowToProviderSchema(row: unknown[]): ProviderSchema {
  return {
    provider: row[0] as string,
    flow_type: row[1] as string,
    version: row[2] as number,
    domain: row[3] as string,
    registered_by: row[4] as string,
    registered_at_input: row[5] as number,
    bucket_definitions: row[6] as string,
    data_keys: row[7] as string,
    freshness_half_life: row[8] as number,
    min_freshness: row[9] as number,
    status: row[10] as string,
  };
}
