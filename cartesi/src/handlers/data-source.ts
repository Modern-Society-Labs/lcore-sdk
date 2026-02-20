/**
 * Data Source Handlers
 *
 * Generic handlers for syncing external data from any source.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Add source-specific validation in validateRecordForSource()
 * 2. Add source-specific transformation in transformRecord()
 * 3. Modify MAX_RECORDS_PER_SYNC based on your needs
 */

import { AdvanceHandler, InspectHandler, InspectQuery, AdvanceRequestData } from '../router';
import {
  insertDataRecords,
  getDataRecordsByEntity,
  getEntityById,
  createEntity,
  updateSyncCursor,
  getSyncCursor,
  DataRecord,
  DataRecordInput,
} from '../db';
import { getMaxRecordsPerSync } from '../config';

// ============= Payload Types =============

interface SyncDataPayload {
  action: 'sync_data';
  entity_id: string;
  source_type: string;
  records: RawRecordInput[];
  cursor?: string;
}

interface RawRecordInput {
  source_record_id?: string;
  record_type: string;
  amount?: number;
  timestamp: string;
  category?: string;
  is_pending?: boolean;
  metadata?: Record<string, unknown>;
}

// ============= Validation =============

/**
 * Validate a record for a specific source type.
 * CUSTOMIZE: Add source-specific validation rules
 */
function validateRecordForSource(
  record: RawRecordInput,
  _sourceType: string,
  index: number
): void {
  if (!record.record_type || typeof record.record_type !== 'string') {
    throw new Error(`Record ${index}: record_type is required`);
  }

  if (!record.timestamp || typeof record.timestamp !== 'string') {
    throw new Error(`Record ${index}: timestamp is required`);
  }

  // Validate timestamp format (YYYY-MM-DD or ISO 8601)
  if (!/^\d{4}-\d{2}-\d{2}/.test(record.timestamp)) {
    throw new Error(`Record ${index}: invalid timestamp format (use YYYY-MM-DD or ISO 8601)`);
  }

  if (record.amount !== undefined && typeof record.amount !== 'number') {
    throw new Error(`Record ${index}: amount must be a number`);
  }
}

/**
 * Transform a raw record to normalized format.
 * CUSTOMIZE: Add source-specific transformations
 */
function transformRecord(record: RawRecordInput): DataRecordInput {
  return {
    source_record_id: record.source_record_id,
    record_type: record.record_type,
    amount: record.amount,
    timestamp: record.timestamp,
    category: record.category,
    is_pending: record.is_pending || false,
    metadata: record.metadata,
  };
}

// ============= Sanitization =============

/**
 * Sanitize record for public response.
 * Removes potentially sensitive information.
 */
function sanitizeRecord(record: DataRecord): Partial<DataRecord> {
  return {
    id: record.id,
    source_type: record.source_type,
    record_type: record.record_type,
    amount: record.amount,
    timestamp: record.timestamp,
    category: record.category,
    is_pending: record.is_pending,
    created_at: record.created_at,
    // Omit: source_record_id (external ID), metadata (may contain PII)
  };
}

// ============= Advance Handlers =============

/**
 * Handle data sync from external source.
 */
export const handleSyncData: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { entity_id, source_type, records, cursor } = payload as SyncDataPayload;

  // Validate entity ID
  if (!entity_id || typeof entity_id !== 'string') {
    throw new Error('Valid entity_id is required');
  }

  // Validate source type
  if (!source_type || typeof source_type !== 'string') {
    throw new Error('Valid source_type is required');
  }

  // Validate records array
  if (!Array.isArray(records)) {
    throw new Error('Records must be an array');
  }

  if (records.length === 0) {
    throw new Error('At least one record is required');
  }

  const maxRecords = getMaxRecordsPerSync();
  if (records.length > maxRecords) {
    throw new Error(`Maximum ${maxRecords} records per sync`);
  }

  // Validate and transform each record
  const validatedRecords: DataRecordInput[] = [];
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (!record) {
      throw new Error(`Record ${i}: missing record data`);
    }

    validateRecordForSource(record, source_type, i);
    validatedRecords.push(transformRecord(record));
  }

  // Get or create entity
  let entity = getEntityById(entity_id);
  if (!entity) {
    entity = createEntity({ id: entity_id });
  }

  // Insert records
  const insertedCount = insertDataRecords(entity.id, source_type, validatedRecords);

  // Update sync cursor if provided
  if (cursor) {
    updateSyncCursor(entity.id, source_type, cursor);
  }

  console.log(`Synced ${insertedCount} ${source_type} records for entity ${entity_id}`);

  return {
    status: 'accept',
    response: {
      action: 'sync_data',
      success: true,
      entity_id,
      source_type,
      records_synced: insertedCount,
      cursor_updated: !!cursor,
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Handle inspect query for data records.
 */
export const handleInspectData: InspectHandler = async (query: InspectQuery) => {
  const { params } = query;

  if (!params.entity_id) {
    return { error: 'entity_id parameter required' };
  }

  const entity = getEntityById(params.entity_id);
  if (!entity) {
    return { error: 'Entity not found', entity_id: params.entity_id };
  }

  // Get records with optional filters
  const records = getDataRecordsByEntity(
    entity.id,
    params.source_type,
    params.start_date,
    params.end_date
  );

  // Get current sync cursor if source specified
  let cursorExists = false;
  if (params.source_type) {
    const cursor = getSyncCursor(entity.id, params.source_type);
    cursorExists = !!cursor;
  }

  // Limit response size
  const maxRecords = 100;
  const limitedRecords = records.slice(0, maxRecords);

  return {
    entity_id: params.entity_id,
    source_type: params.source_type || 'all',
    record_count: records.length,
    records: limitedRecords.map(sanitizeRecord),
    has_more: records.length > maxRecords,
    sync_cursor_exists: cursorExists,
  };
};
