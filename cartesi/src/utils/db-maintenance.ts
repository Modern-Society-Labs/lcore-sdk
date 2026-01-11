/**
 * Database Maintenance Utility
 *
 * Provides maintenance operations for sql.js database:
 * - VACUUM for space reclamation
 * - ANALYZE for query optimization
 * - Memory monitoring
 * - State snapshots
 */

import { getDatabase, setDatabase, exportDatabase } from '../db';
import initSqlJs from 'sql.js';

// ============= Types =============

export interface MemoryMetrics {
  heapUsed: number;
  heapTotal: number;
  external: number;
  rss: number;
  databaseSize: number;
}

export interface MaintenanceResult {
  success: boolean;
  operation: string;
  durationMs: number;
  details?: Record<string, unknown>;
  error?: string;
}

export interface StateSnapshot {
  snapshotId: string;
  blockNumber: number;
  timestamp: string;
  databaseSize: number;
  checksum: string;
  data: Uint8Array;
}

// ============= Configuration =============

export interface MaintenanceConfig {
  vacuumIntervalBlocks: number;      // Run VACUUM every N blocks
  analyzeIntervalBlocks: number;     // Run ANALYZE every N blocks
  snapshotIntervalBlocks: number;    // Create snapshot every N blocks
  memoryThresholdMb: number;         // Trigger compaction above this threshold
  databaseSizeThresholdMb: number;   // Trigger compaction above this threshold
}

const DEFAULT_CONFIG: MaintenanceConfig = {
  vacuumIntervalBlocks: 10000,
  analyzeIntervalBlocks: 1000,
  snapshotIntervalBlocks: 5000,
  memoryThresholdMb: 400,
  databaseSizeThresholdMb: 50,
};

let maintenanceConfig = { ...DEFAULT_CONFIG };
let lastVacuumBlock = 0;
let lastAnalyzeBlock = 0;
let lastSnapshotBlock = 0;

/**
 * Update maintenance configuration
 */
export function setMaintenanceConfig(config: Partial<MaintenanceConfig>): void {
  maintenanceConfig = { ...maintenanceConfig, ...config };
}

/**
 * Get current maintenance configuration
 */
export function getMaintenanceConfig(): MaintenanceConfig {
  return { ...maintenanceConfig };
}

// ============= Memory Monitoring =============

/**
 * Get current memory metrics
 */
export function getMemoryMetrics(): MemoryMetrics {
  const mem = process.memoryUsage();
  const dbExport = exportDatabase();

  return {
    heapUsed: mem.heapUsed,
    heapTotal: mem.heapTotal,
    external: mem.external,
    rss: mem.rss,
    databaseSize: dbExport?.length || 0,
  };
}

/**
 * Check if memory thresholds are exceeded
 */
export function shouldRunMaintenance(): boolean {
  const metrics = getMemoryMetrics();
  const config = maintenanceConfig;

  const heapMb = metrics.heapUsed / (1024 * 1024);
  const dbMb = metrics.databaseSize / (1024 * 1024);

  return heapMb > config.memoryThresholdMb || dbMb > config.databaseSizeThresholdMb;
}

/**
 * Format memory metrics for logging
 */
export function formatMemoryMetrics(metrics: MemoryMetrics): string {
  const mb = (bytes: number) => (bytes / 1024 / 1024).toFixed(2);
  return `Heap: ${mb(metrics.heapUsed)}/${mb(metrics.heapTotal)}MB, RSS: ${mb(metrics.rss)}MB, DB: ${mb(metrics.databaseSize)}MB`;
}

// ============= Database Operations =============

/**
 * Run VACUUM to reclaim space
 */
export function runVacuum(): MaintenanceResult {
  const start = Date.now();

  try {
    const db = getDatabase();
    const beforeSize = exportDatabase()?.length || 0;

    db.run('VACUUM;');

    const afterSize = exportDatabase()?.length || 0;

    return {
      success: true,
      operation: 'VACUUM',
      durationMs: Date.now() - start,
      details: {
        sizeBefore: beforeSize,
        sizeAfter: afterSize,
        savedBytes: beforeSize - afterSize,
      },
    };
  } catch (error) {
    return {
      success: false,
      operation: 'VACUUM',
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Run ANALYZE to update query statistics
 */
export function runAnalyze(): MaintenanceResult {
  const start = Date.now();

  try {
    const db = getDatabase();
    db.run('ANALYZE;');

    return {
      success: true,
      operation: 'ANALYZE',
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      success: false,
      operation: 'ANALYZE',
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Reindex specific indices
 */
export function runReindex(indexNames?: string[]): MaintenanceResult {
  const start = Date.now();

  try {
    const db = getDatabase();

    if (indexNames && indexNames.length > 0) {
      for (const indexName of indexNames) {
        db.run(`REINDEX ${indexName};`);
      }
    } else {
      // Reindex all
      db.run('REINDEX;');
    }

    return {
      success: true,
      operation: 'REINDEX',
      durationMs: Date.now() - start,
      details: { indices: indexNames || 'all' },
    };
  } catch (error) {
    return {
      success: false,
      operation: 'REINDEX',
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Run integrity check
 */
export function runIntegrityCheck(): MaintenanceResult {
  const start = Date.now();

  try {
    const db = getDatabase();
    const result = db.exec('PRAGMA integrity_check;');

    const status = result[0]?.values[0]?.[0] as string;
    const isOk = status === 'ok';

    return {
      success: isOk,
      operation: 'INTEGRITY_CHECK',
      durationMs: Date.now() - start,
      details: { status },
    };
  } catch (error) {
    return {
      success: false,
      operation: 'INTEGRITY_CHECK',
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Full database compaction (export, reimport, vacuum)
 */
export async function runCompaction(): Promise<MaintenanceResult> {
  const start = Date.now();

  try {
    const db = getDatabase();
    const beforeSize = exportDatabase()?.length || 0;

    // Export current state
    const data = db.export();

    // Close current database
    db.close();

    // Create new database from export
    const SQL = await initSqlJs();
    const newDb = new SQL.Database(data);

    // Run vacuum on new database
    newDb.run('VACUUM;');

    // Replace global database
    setDatabase(newDb);

    const afterSize = exportDatabase()?.length || 0;

    return {
      success: true,
      operation: 'COMPACTION',
      durationMs: Date.now() - start,
      details: {
        sizeBefore: beforeSize,
        sizeAfter: afterSize,
        savedBytes: beforeSize - afterSize,
      },
    };
  } catch (error) {
    return {
      success: false,
      operation: 'COMPACTION',
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// ============= State Snapshots =============

const snapshots: Map<string, StateSnapshot> = new Map();

/**
 * Simple checksum for snapshot verification
 */
function calculateChecksum(data: Uint8Array): string {
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    hash = ((hash << 5) - hash + data[i]!) | 0;
  }
  return hash.toString(16);
}

/**
 * Create a state snapshot
 */
export function createSnapshot(blockNumber: number): StateSnapshot {
  const data = exportDatabase();
  if (!data) {
    throw new Error('Failed to export database');
  }

  const snapshot: StateSnapshot = {
    snapshotId: `snapshot-${blockNumber}-${Date.now()}`,
    blockNumber,
    timestamp: new Date().toISOString(),
    databaseSize: data.length,
    checksum: calculateChecksum(data),
    data: data,
  };

  snapshots.set(snapshot.snapshotId, snapshot);

  // Keep only last 5 snapshots
  if (snapshots.size > 5) {
    const oldest = Array.from(snapshots.keys())[0];
    if (oldest) snapshots.delete(oldest);
  }

  return snapshot;
}

/**
 * Get a snapshot by ID
 */
export function getSnapshot(snapshotId: string): StateSnapshot | undefined {
  return snapshots.get(snapshotId);
}

/**
 * List available snapshots (without data)
 */
export function listSnapshots(): Array<Omit<StateSnapshot, 'data'>> {
  return Array.from(snapshots.values()).map(s => ({
    snapshotId: s.snapshotId,
    blockNumber: s.blockNumber,
    timestamp: s.timestamp,
    databaseSize: s.databaseSize,
    checksum: s.checksum,
  }));
}

/**
 * Restore from a snapshot
 */
export async function restoreSnapshot(snapshotId: string): Promise<MaintenanceResult> {
  const start = Date.now();

  const snapshot = snapshots.get(snapshotId);
  if (!snapshot) {
    return {
      success: false,
      operation: 'RESTORE_SNAPSHOT',
      durationMs: Date.now() - start,
      error: 'Snapshot not found',
    };
  }

  try {
    const db = getDatabase();
    db.close();

    const SQL = await initSqlJs();
    const newDb = new SQL.Database(snapshot.data);

    setDatabase(newDb);

    return {
      success: true,
      operation: 'RESTORE_SNAPSHOT',
      durationMs: Date.now() - start,
      details: {
        snapshotId,
        blockNumber: snapshot.blockNumber,
        checksum: snapshot.checksum,
      },
    };
  } catch (error) {
    return {
      success: false,
      operation: 'RESTORE_SNAPSHOT',
      durationMs: Date.now() - start,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

// ============= Periodic Maintenance =============

/**
 * Run maintenance if needed based on block number
 */
export async function maybeRunMaintenance(blockNumber: number): Promise<MaintenanceResult[]> {
  const results: MaintenanceResult[] = [];
  const config = maintenanceConfig;

  // Check memory thresholds
  if (shouldRunMaintenance()) {
    const compactResult = await runCompaction();
    results.push(compactResult);
  }

  // Periodic VACUUM
  if (blockNumber - lastVacuumBlock >= config.vacuumIntervalBlocks) {
    const vacuumResult = runVacuum();
    results.push(vacuumResult);
    if (vacuumResult.success) {
      lastVacuumBlock = blockNumber;
    }
  }

  // Periodic ANALYZE
  if (blockNumber - lastAnalyzeBlock >= config.analyzeIntervalBlocks) {
    const analyzeResult = runAnalyze();
    results.push(analyzeResult);
    if (analyzeResult.success) {
      lastAnalyzeBlock = blockNumber;
    }
  }

  // Periodic snapshots
  if (blockNumber - lastSnapshotBlock >= config.snapshotIntervalBlocks) {
    try {
      createSnapshot(blockNumber);
      results.push({
        success: true,
        operation: 'CREATE_SNAPSHOT',
        durationMs: 0,
        details: { blockNumber },
      });
      lastSnapshotBlock = blockNumber;
    } catch (error) {
      results.push({
        success: false,
        operation: 'CREATE_SNAPSHOT',
        durationMs: 0,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return results;
}

/**
 * Get database statistics
 */
export function getDatabaseStats(): Record<string, unknown> {
  const db = getDatabase();
  const metrics = getMemoryMetrics();

  // Get table counts
  const tables = db.exec(`
    SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'
  `);

  const tableCounts: Record<string, number> = {};
  if (tables.length > 0) {
    for (const row of tables[0]!.values) {
      const tableName = row[0] as string;
      const countResult = db.exec(`SELECT COUNT(*) FROM "${tableName}"`);
      tableCounts[tableName] = countResult[0]?.values[0]?.[0] as number || 0;
    }
  }

  return {
    memory: {
      heapUsedMb: (metrics.heapUsed / 1024 / 1024).toFixed(2),
      databaseSizeMb: (metrics.databaseSize / 1024 / 1024).toFixed(2),
    },
    tables: tableCounts,
    maintenance: {
      lastVacuumBlock,
      lastAnalyzeBlock,
      lastSnapshotBlock,
      snapshotCount: snapshots.size,
    },
  };
}
