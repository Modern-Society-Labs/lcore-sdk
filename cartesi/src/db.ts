/**
 * Cartesi SQLite Database Layer
 *
 * This module provides a generalized database layer using sql.js (SQLite compiled to WebAssembly)
 * for deterministic in-rollup state persistence.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Modify the schema in initDatabase() to match your domain
 * 2. Add entity interfaces for each table
 * 3. Implement CRUD functions following the patterns below
 * 4. Use the helper functions for type-safe query results
 */

import initSqlJs, { Database, QueryExecResult } from 'sql.js';

let db: Database | null = null;

// ============= Helper Types =============

export type SqlValue = string | number | Uint8Array | null;
export type SqlRow = SqlValue[];

// ============= Query Result Helpers =============

/**
 * Helper to safely get the first result set from a query
 */
function getFirstResult(result: QueryExecResult[]): QueryExecResult | undefined {
  return result[0];
}

/**
 * Helper to safely get rows from a result set
 */
function getRows(result: QueryExecResult | undefined): SqlRow[] {
  return result?.values ?? [];
}

/**
 * Helper to safely get the first row from a result set
 */
function getFirstRow(result: QueryExecResult | undefined): SqlRow | undefined {
  return result?.values[0];
}

/**
 * Helper to safely get a scalar value from a query result
 */
function getScalar<T>(result: QueryExecResult[], defaultValue: T): T {
  const firstResult = getFirstResult(result);
  const firstRow = getFirstRow(firstResult);
  if (firstRow && firstRow[0] !== undefined && firstRow[0] !== null) {
    return firstRow[0] as T;
  }
  return defaultValue;
}

/**
 * Helper to safely extract a scalar count from a query result
 */
function getCountResult(result: QueryExecResult[]): number {
  const firstResult = result[0];
  const firstRow = firstResult?.values[0];
  return (firstRow?.[0] as number) ?? 0;
}

/**
 * Helper to safely extract a nullable number from a query result
 */
function getNullableNumberResult(result: QueryExecResult[]): number | null {
  const firstResult = result[0];
  const firstRow = firstResult?.values[0];
  const value = firstRow?.[0];
  return value === null || value === undefined ? null : (value as number);
}

// ============= Database Initialization =============

/**
 * Initialize the SQLite database with schema.
 * Uses sql.js (SQLite compiled to WebAssembly) for deterministic in-rollup persistence.
 *
 * CUSTOMIZE: Modify the CREATE TABLE statements below to match your domain schema.
 */
export async function initDatabase(): Promise<Database> {
  if (db) {
    return db;
  }

  const SQL = await initSqlJs();
  db = new SQL.Database();

  // Create schema - CUSTOMIZE THIS FOR YOUR DOMAIN
  db.run(`
    -- ============= CORE ENTITIES =============

    -- Primary entity table (users, accounts, etc.)
    -- CUSTOMIZE: Rename and add fields for your primary entity
    CREATE TABLE IF NOT EXISTS entities (
      id TEXT PRIMARY KEY,
      external_id TEXT UNIQUE,
      entity_type TEXT DEFAULT 'default',
      status TEXT DEFAULT 'active',
      metadata TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    -- ============= DATA RECORDS =============

    -- Generic data records from external sources
    -- CUSTOMIZE: Add source-specific fields or create separate tables
    CREATE TABLE IF NOT EXISTS data_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id TEXT NOT NULL,
      source_type TEXT NOT NULL,
      source_record_id TEXT,
      record_type TEXT NOT NULL,
      amount INTEGER,
      timestamp TEXT NOT NULL,
      category TEXT,
      is_pending INTEGER DEFAULT 0,
      metadata TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(source_type, source_record_id),
      FOREIGN KEY (entity_id) REFERENCES entities(id)
    );

    -- ============= SYNC STATE =============

    -- Track incremental sync cursors for each source
    CREATE TABLE IF NOT EXISTS sync_state (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id TEXT NOT NULL,
      source_type TEXT NOT NULL,
      cursor_value TEXT,
      last_sync_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(entity_id, source_type),
      FOREIGN KEY (entity_id) REFERENCES entities(id)
    );

    -- ============= COMPUTATIONS =============

    -- Store derived calculations/computations
    -- CUSTOMIZE: Add fields for your specific computation types
    CREATE TABLE IF NOT EXISTS computations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id TEXT NOT NULL,
      computation_type TEXT NOT NULL,
      result_value REAL,
      secondary_value REAL,
      input_hash TEXT,
      computed_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (entity_id) REFERENCES entities(id)
    );

    -- ============= DATA PROOFS =============

    -- Store verified proofs for data authenticity
    CREATE TABLE IF NOT EXISTS data_proofs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      proof_id TEXT UNIQUE NOT NULL,
      proof_type TEXT NOT NULL,
      entity_id TEXT NOT NULL,
      data_hash TEXT NOT NULL,
      signature TEXT NOT NULL,
      verified INTEGER DEFAULT 0,
      verified_at TEXT,
      expires_at TEXT,
      metadata TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (entity_id) REFERENCES entities(id)
    );

    -- ============= PENDING APPROVALS =============

    -- Generic approval workflow table
    CREATE TABLE IF NOT EXISTS pending_approvals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id TEXT NOT NULL,
      approval_type TEXT NOT NULL,
      current_value TEXT,
      proposed_value TEXT NOT NULL,
      reason TEXT,
      status TEXT DEFAULT 'pending',
      requested_by TEXT,
      approved_by TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      resolved_at TEXT,
      FOREIGN KEY (entity_id) REFERENCES entities(id)
    );

    -- ============= INDEXES =============

    CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type);
    CREATE INDEX IF NOT EXISTS idx_entities_status ON entities(status);
    CREATE INDEX IF NOT EXISTS idx_records_entity ON data_records(entity_id);
    CREATE INDEX IF NOT EXISTS idx_records_source ON data_records(source_type);
    CREATE INDEX IF NOT EXISTS idx_records_timestamp ON data_records(timestamp);
    CREATE INDEX IF NOT EXISTS idx_computations_entity ON computations(entity_id);
    CREATE INDEX IF NOT EXISTS idx_computations_type ON computations(computation_type);
    CREATE INDEX IF NOT EXISTS idx_proofs_entity ON data_proofs(entity_id);
    CREATE INDEX IF NOT EXISTS idx_proofs_type ON data_proofs(proof_type);
    CREATE INDEX IF NOT EXISTS idx_approvals_entity ON pending_approvals(entity_id);
    CREATE INDEX IF NOT EXISTS idx_approvals_status ON pending_approvals(status);
  `);

  console.log('Database initialized successfully');
  return db;
}

/**
 * Get the database instance. Throws if not initialized.
 */
export function getDatabase(): Database {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }
  return db;
}

/**
 * Set the database instance directly (for testing).
 */
export function setDatabase(database: Database): void {
  db = database;
}

/**
 * Close the database connection (for cleanup/testing).
 */
export function closeDatabase(): void {
  if (db) {
    db.close();
    db = null;
  }
}

/**
 * Export database as binary for state persistence/debugging.
 */
export function exportDatabase(): Uint8Array {
  if (!db) {
    throw new Error('Database not initialized');
  }
  return db.export();
}

/**
 * Import database from binary (for state restoration).
 */
export async function importDatabase(data: Uint8Array): Promise<Database> {
  const SQL = await initSqlJs();
  db = new SQL.Database(data);
  return db;
}

// ============= Entity Operations =============

export interface Entity {
  id: string;
  external_id: string | null;
  entity_type: string;
  status: string;
  metadata: string | null;
  created_at: string;
  updated_at: string;
}

export interface EntityInput {
  id: string;
  external_id?: string;
  entity_type?: string;
  metadata?: Record<string, unknown>;
}

export function createEntity(input: EntityInput): Entity {
  const database = getDatabase();
  const now = new Date().toISOString();

  database.run(
    `INSERT INTO entities (id, external_id, entity_type, metadata, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       external_id = COALESCE(excluded.external_id, external_id),
       metadata = COALESCE(excluded.metadata, metadata),
       updated_at = excluded.updated_at`,
    [
      input.id,
      input.external_id || null,
      input.entity_type || 'default',
      input.metadata ? JSON.stringify(input.metadata) : null,
      now,
      now,
    ]
  );

  return getEntityById(input.id)!;
}

export function getEntityById(id: string): Entity | null {
  const database = getDatabase();
  const result = database.exec(
    `SELECT id, external_id, entity_type, status, metadata, created_at, updated_at
     FROM entities WHERE id = ?`,
    [id]
  );

  const row = getFirstRow(getFirstResult(result));
  if (!row) {
    return null;
  }

  return {
    id: row[0] as string,
    external_id: row[1] as string | null,
    entity_type: row[2] as string,
    status: row[3] as string,
    metadata: row[4] as string | null,
    created_at: row[5] as string,
    updated_at: row[6] as string,
  };
}

export function getEntityByExternalId(externalId: string): Entity | null {
  const database = getDatabase();
  const result = database.exec(
    `SELECT id, external_id, entity_type, status, metadata, created_at, updated_at
     FROM entities WHERE external_id = ?`,
    [externalId]
  );

  const row = getFirstRow(getFirstResult(result));
  if (!row) {
    return null;
  }

  return {
    id: row[0] as string,
    external_id: row[1] as string | null,
    entity_type: row[2] as string,
    status: row[3] as string,
    metadata: row[4] as string | null,
    created_at: row[5] as string,
    updated_at: row[6] as string,
  };
}

export function updateEntityStatus(id: string, status: string): void {
  const database = getDatabase();
  database.run(`UPDATE entities SET status = ?, updated_at = ? WHERE id = ?`, [
    status,
    new Date().toISOString(),
    id,
  ]);
}

// ============= Data Record Operations =============

export interface DataRecord {
  id: number;
  entity_id: string;
  source_type: string;
  source_record_id: string | null;
  record_type: string;
  amount: number | null;
  timestamp: string;
  category: string | null;
  is_pending: boolean;
  metadata: string | null;
  created_at: string;
}

export interface DataRecordInput {
  source_record_id?: string;
  record_type: string;
  amount?: number;
  timestamp: string;
  category?: string;
  is_pending?: boolean;
  metadata?: Record<string, unknown>;
}

export function insertDataRecords(
  entityId: string,
  sourceType: string,
  records: DataRecordInput[]
): number {
  const database = getDatabase();
  const now = new Date().toISOString();
  let insertedCount = 0;

  for (const record of records) {
    try {
      database.run(
        `INSERT INTO data_records
         (entity_id, source_type, source_record_id, record_type, amount, timestamp, category, is_pending, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(source_type, source_record_id) DO UPDATE SET
           amount = excluded.amount,
           is_pending = excluded.is_pending,
           metadata = excluded.metadata`,
        [
          entityId,
          sourceType,
          record.source_record_id || null,
          record.record_type,
          record.amount ?? null,
          record.timestamp,
          record.category || null,
          record.is_pending ? 1 : 0,
          record.metadata ? JSON.stringify(record.metadata) : null,
          now,
        ]
      );
      insertedCount++;
    } catch (error) {
      console.error(`Failed to insert record: ${error}`);
    }
  }

  return insertedCount;
}

export function getDataRecordsByEntity(
  entityId: string,
  sourceType?: string,
  startDate?: string,
  endDate?: string
): DataRecord[] {
  const database = getDatabase();

  let query = `SELECT id, entity_id, source_type, source_record_id, record_type, amount, timestamp, category, is_pending, metadata, created_at
               FROM data_records WHERE entity_id = ?`;
  const params: (string | number)[] = [entityId];

  if (sourceType) {
    query += ' AND source_type = ?';
    params.push(sourceType);
  }
  if (startDate) {
    query += ' AND timestamp >= ?';
    params.push(startDate);
  }
  if (endDate) {
    query += ' AND timestamp <= ?';
    params.push(endDate);
  }

  query += ' ORDER BY timestamp DESC';

  const result = database.exec(query, params);
  const firstResult = result[0];
  if (!firstResult) {
    return [];
  }

  return firstResult.values.map((row: unknown[]) => ({
    id: row[0] as number,
    entity_id: row[1] as string,
    source_type: row[2] as string,
    source_record_id: row[3] as string | null,
    record_type: row[4] as string,
    amount: row[5] as number | null,
    timestamp: row[6] as string,
    category: row[7] as string | null,
    is_pending: Boolean(row[8]),
    metadata: row[9] as string | null,
    created_at: row[10] as string,
  }));
}

export function getDataRecordsForComputation(
  entityId: string,
  sourceType: string,
  monthsBack: number = 12
): DataRecord[] {
  const database = getDatabase();
  const startDate = new Date();
  startDate.setMonth(startDate.getMonth() - monthsBack);

  const dateStr = startDate.toISOString().split('T')[0] ?? '';
  const result = database.exec(
    `SELECT id, entity_id, source_type, source_record_id, record_type, amount, timestamp, category, is_pending, metadata, created_at
     FROM data_records
     WHERE entity_id = ? AND source_type = ? AND timestamp >= ? AND is_pending = 0
     ORDER BY timestamp ASC`,
    [entityId, sourceType, dateStr]
  );

  const firstResult = result[0];
  if (!firstResult) {
    return [];
  }

  return firstResult.values.map((row: unknown[]) => ({
    id: row[0] as number,
    entity_id: row[1] as string,
    source_type: row[2] as string,
    source_record_id: row[3] as string | null,
    record_type: row[4] as string,
    amount: row[5] as number | null,
    timestamp: row[6] as string,
    category: row[7] as string | null,
    is_pending: Boolean(row[8]),
    metadata: row[9] as string | null,
    created_at: row[10] as string,
  }));
}

// ============= Sync State Operations =============

export function updateSyncCursor(
  entityId: string,
  sourceType: string,
  cursor: string
): void {
  const database = getDatabase();
  const now = new Date().toISOString();

  database.run(
    `INSERT INTO sync_state (entity_id, source_type, cursor_value, last_sync_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(entity_id, source_type) DO UPDATE SET
       cursor_value = excluded.cursor_value,
       last_sync_at = excluded.last_sync_at`,
    [entityId, sourceType, cursor, now]
  );
}

export function getSyncCursor(entityId: string, sourceType: string): string | null {
  const database = getDatabase();
  const result = database.exec(
    `SELECT cursor_value FROM sync_state WHERE entity_id = ? AND source_type = ?`,
    [entityId, sourceType]
  );

  const firstResult = result[0];
  if (!firstResult || firstResult.values.length === 0) {
    return null;
  }

  const firstRow = firstResult.values[0];
  return (firstRow?.[0] as string | null) ?? null;
}

// ============= Computation Operations =============

export interface Computation {
  id: number;
  entity_id: string;
  computation_type: string;
  result_value: number | null;
  secondary_value: number | null;
  input_hash: string | null;
  computed_at: string;
}

export function saveComputation(
  entityId: string,
  computationType: string,
  resultValue: number,
  secondaryValue?: number,
  inputHash?: string
): Computation {
  const database = getDatabase();
  const now = new Date().toISOString();

  database.run(
    `INSERT INTO computations (entity_id, computation_type, result_value, secondary_value, input_hash, computed_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [entityId, computationType, resultValue, secondaryValue || null, inputHash || null, now]
  );

  const result = database.exec('SELECT last_insert_rowid()');
  const firstResult = result[0];
  const firstRow = firstResult?.values[0];
  const id = (firstRow?.[0] as number) ?? 0;

  return {
    id,
    entity_id: entityId,
    computation_type: computationType,
    result_value: resultValue,
    secondary_value: secondaryValue || null,
    input_hash: inputHash || null,
    computed_at: now,
  };
}

export function getComputationHistory(
  entityId: string,
  computationType?: string
): Computation[] {
  const database = getDatabase();

  let query = `SELECT id, entity_id, computation_type, result_value, secondary_value, input_hash, computed_at
               FROM computations WHERE entity_id = ?`;
  const params: string[] = [entityId];

  if (computationType) {
    query += ' AND computation_type = ?';
    params.push(computationType);
  }

  query += ' ORDER BY computed_at DESC';

  const result = database.exec(query, params);
  const firstResult = result[0];

  if (!firstResult) {
    return [];
  }

  return firstResult.values.map((row: unknown[]) => ({
    id: row[0] as number,
    entity_id: row[1] as string,
    computation_type: row[2] as string,
    result_value: row[3] as number | null,
    secondary_value: row[4] as number | null,
    input_hash: row[5] as string | null,
    computed_at: row[6] as string,
  }));
}

// ============= Data Proof Operations =============

export interface DataProof {
  id: number;
  proof_id: string;
  proof_type: string;
  entity_id: string;
  data_hash: string;
  signature: string;
  verified: boolean;
  verified_at: string | null;
  expires_at: string | null;
  metadata: string | null;
  created_at: string;
}

export interface DataProofInput {
  proof_id: string;
  proof_type: string;
  entity_id: string;
  data_hash: string;
  signature: string;
  expires_at?: string;
  metadata?: Record<string, unknown>;
}

export function saveDataProof(input: DataProofInput): DataProof {
  const database = getDatabase();
  const now = new Date().toISOString();

  database.run(
    `INSERT INTO data_proofs
     (proof_id, proof_type, entity_id, data_hash, signature, expires_at, metadata, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(proof_id) DO UPDATE SET
       data_hash = excluded.data_hash,
       signature = excluded.signature,
       metadata = excluded.metadata`,
    [
      input.proof_id,
      input.proof_type,
      input.entity_id,
      input.data_hash,
      input.signature,
      input.expires_at || null,
      input.metadata ? JSON.stringify(input.metadata) : null,
      now,
    ]
  );

  return getDataProofById(input.proof_id)!;
}

export function getDataProofById(proofId: string): DataProof | null {
  const database = getDatabase();
  const result = database.exec(
    `SELECT id, proof_id, proof_type, entity_id, data_hash, signature, verified, verified_at, expires_at, metadata, created_at
     FROM data_proofs WHERE proof_id = ?`,
    [proofId]
  );

  const firstResult = result[0];
  const firstRow = firstResult?.values[0];

  if (!firstRow) {
    return null;
  }

  return {
    id: firstRow[0] as number,
    proof_id: firstRow[1] as string,
    proof_type: firstRow[2] as string,
    entity_id: firstRow[3] as string,
    data_hash: firstRow[4] as string,
    signature: firstRow[5] as string,
    verified: Boolean(firstRow[6]),
    verified_at: firstRow[7] as string | null,
    expires_at: firstRow[8] as string | null,
    metadata: firstRow[9] as string | null,
    created_at: firstRow[10] as string,
  };
}

export function getProofsByEntity(entityId: string): DataProof[] {
  const database = getDatabase();
  const result = database.exec(
    `SELECT id, proof_id, proof_type, entity_id, data_hash, signature, verified, verified_at, expires_at, metadata, created_at
     FROM data_proofs WHERE entity_id = ? ORDER BY created_at DESC`,
    [entityId]
  );

  const firstResult = result[0];
  if (!firstResult) {
    return [];
  }

  return firstResult.values.map((row: unknown[]) => ({
    id: row[0] as number,
    proof_id: row[1] as string,
    proof_type: row[2] as string,
    entity_id: row[3] as string,
    data_hash: row[4] as string,
    signature: row[5] as string,
    verified: Boolean(row[6]),
    verified_at: row[7] as string | null,
    expires_at: row[8] as string | null,
    metadata: row[9] as string | null,
    created_at: row[10] as string,
  }));
}

export function markProofVerified(proofId: string): boolean {
  const database = getDatabase();
  const now = new Date().toISOString();

  database.run(
    `UPDATE data_proofs SET verified = 1, verified_at = ? WHERE proof_id = ?`,
    [now, proofId]
  );

  const proof = getDataProofById(proofId);
  return proof?.verified ?? false;
}

export function isProofValid(proofId: string): boolean {
  const proof = getDataProofById(proofId);
  if (!proof) {
    return false;
  }

  if (!proof.verified) {
    return false;
  }

  if (proof.expires_at) {
    const expiresAt = new Date(proof.expires_at).getTime();
    if (Date.now() > expiresAt) {
      return false;
    }
  }

  return true;
}

// ============= Pending Approval Operations =============

export interface PendingApproval {
  id: number;
  entity_id: string;
  approval_type: string;
  current_value: string | null;
  proposed_value: string;
  reason: string | null;
  status: string;
  requested_by: string | null;
  approved_by: string | null;
  created_at: string;
  resolved_at: string | null;
}

export function createPendingApproval(
  entityId: string,
  approvalType: string,
  currentValue: string | null,
  proposedValue: string,
  reason?: string,
  requestedBy?: string
): PendingApproval {
  const database = getDatabase();
  const now = new Date().toISOString();

  database.run(
    `INSERT INTO pending_approvals (entity_id, approval_type, current_value, proposed_value, reason, requested_by, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [entityId, approvalType, currentValue, proposedValue, reason || null, requestedBy || null, now]
  );

  const result = database.exec('SELECT last_insert_rowid()');
  const firstResult = result[0];
  const firstRow = firstResult?.values[0];
  const id = (firstRow?.[0] as number) ?? 0;

  return {
    id,
    entity_id: entityId,
    approval_type: approvalType,
    current_value: currentValue,
    proposed_value: proposedValue,
    reason: reason || null,
    status: 'pending',
    requested_by: requestedBy || null,
    approved_by: null,
    created_at: now,
    resolved_at: null,
  };
}

export function getPendingApprovals(
  entityId?: string,
  approvalType?: string
): PendingApproval[] {
  const database = getDatabase();

  let query = `SELECT id, entity_id, approval_type, current_value, proposed_value, reason, status,
               requested_by, approved_by, created_at, resolved_at
               FROM pending_approvals WHERE status = 'pending'`;
  const params: string[] = [];

  if (entityId) {
    query += ' AND entity_id = ?';
    params.push(entityId);
  }

  if (approvalType) {
    query += ' AND approval_type = ?';
    params.push(approvalType);
  }

  query += ' ORDER BY created_at DESC';

  const result = database.exec(query, params);
  const firstResult = result[0];

  if (!firstResult) {
    return [];
  }

  return firstResult.values.map((row: unknown[]) => ({
    id: row[0] as number,
    entity_id: row[1] as string,
    approval_type: row[2] as string,
    current_value: row[3] as string | null,
    proposed_value: row[4] as string,
    reason: row[5] as string | null,
    status: row[6] as string,
    requested_by: row[7] as string | null,
    approved_by: row[8] as string | null,
    created_at: row[9] as string,
    resolved_at: row[10] as string | null,
  }));
}

export function resolveApproval(
  id: number,
  approved: boolean,
  approvedBy: string
): boolean {
  const database = getDatabase();
  const now = new Date().toISOString();
  const newStatus = approved ? 'approved' : 'rejected';

  database.run(
    `UPDATE pending_approvals SET status = ?, approved_by = ?, resolved_at = ? WHERE id = ? AND status = 'pending'`,
    [newStatus, approvedBy, now, id]
  );

  // Check if update was successful
  const result = database.exec(
    `SELECT status FROM pending_approvals WHERE id = ?`,
    [id]
  );
  const firstRow = result[0]?.values[0];
  return firstRow?.[0] === newStatus;
}

// ============= Statistics Operations =============

export interface DatabaseStats {
  total_entities: number;
  total_records: number;
  total_computations: number;
  entities_by_status: Record<string, number>;
  records_by_source: Record<string, number>;
}

export function getDatabaseStats(): DatabaseStats {
  const database = getDatabase();

  const entityCount = getCountResult(database.exec('SELECT COUNT(*) FROM entities'));
  const recordCount = getCountResult(database.exec('SELECT COUNT(*) FROM data_records'));
  const computationCount = getCountResult(database.exec('SELECT COUNT(*) FROM computations'));

  // Entities by status
  const statusResult = database.exec('SELECT status, COUNT(*) FROM entities GROUP BY status');
  const entitiesByStatus: Record<string, number> = {};
  const statusFirstResult = statusResult[0];
  if (statusFirstResult) {
    for (const row of statusFirstResult.values) {
      const status = row[0];
      const count = row[1];
      if (typeof status === 'string' && typeof count === 'number') {
        entitiesByStatus[status] = count;
      }
    }
  }

  // Records by source
  const sourceResult = database.exec('SELECT source_type, COUNT(*) FROM data_records GROUP BY source_type');
  const recordsBySource: Record<string, number> = {};
  const sourceFirstResult = sourceResult[0];
  if (sourceFirstResult) {
    for (const row of sourceFirstResult.values) {
      const source = row[0];
      const count = row[1];
      if (typeof source === 'string' && typeof count === 'number') {
        recordsBySource[source] = count;
      }
    }
  }

  return {
    total_entities: entityCount,
    total_records: recordCount,
    total_computations: computationCount,
    entities_by_status: entitiesByStatus,
    records_by_source: recordsBySource,
  };
}
