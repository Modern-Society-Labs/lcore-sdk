/**
 * Notice Batcher Utility
 *
 * Batches multiple notices together for improved throughput.
 * Reduces overhead of individual notice submissions.
 */

import { getConfig } from '../config';

// ============= Types =============

export interface NoticeEvent {
  type: string;
  data: unknown;
  timestamp?: string;
}

export interface NoticeBatch {
  batch_id: string;
  event_count: number;
  events: NoticeEvent[];
  created_at: string;
}

export interface NoticeBatcherConfig {
  maxBatchSize: number;      // Max events before auto-flush
  flushIntervalMs: number;   // Max time before auto-flush (0 = disabled)
  compressPayload: boolean;  // Whether to compress large payloads
}

// ============= Default Configuration =============

const DEFAULT_CONFIG: NoticeBatcherConfig = {
  maxBatchSize: 50,
  flushIntervalMs: 0,  // Disabled by default (manual flush)
  compressPayload: false,
};

// ============= Notice Batcher Class =============

export class NoticeBatcher {
  private batch: NoticeEvent[] = [];
  private config: NoticeBatcherConfig;
  private batchCounter = 0;
  private flushTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(config: Partial<NoticeBatcherConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Add an event to the batch
   */
  async add(event: NoticeEvent): Promise<void> {
    // Add timestamp if not provided
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString();
    }

    this.batch.push(event);

    // Auto-flush if batch size reached
    if (this.batch.length >= this.config.maxBatchSize) {
      await this.flush();
    }

    // Start flush timer if configured
    if (this.config.flushIntervalMs > 0 && !this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), this.config.flushIntervalMs);
    }
  }

  /**
   * Add multiple events at once
   */
  async addMany(events: NoticeEvent[]): Promise<void> {
    for (const event of events) {
      await this.add(event);
    }
  }

  /**
   * Flush the current batch
   */
  async flush(): Promise<boolean> {
    // Clear timer
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }

    if (this.batch.length === 0) {
      return true;
    }

    const batch: NoticeBatch = {
      batch_id: `batch-${++this.batchCounter}-${Date.now()}`,
      event_count: this.batch.length,
      events: this.batch,
      created_at: new Date().toISOString(),
    };

    // Clear batch before sending (in case of error, we don't lose events)
    const eventsToSend = this.batch;
    this.batch = [];

    try {
      await sendNotice(batch);
      return true;
    } catch (error) {
      // Re-add events to batch on failure
      this.batch = [...eventsToSend, ...this.batch];
      console.error('Failed to flush notice batch:', error);
      return false;
    }
  }

  /**
   * Get current batch size
   */
  get size(): number {
    return this.batch.length;
  }

  /**
   * Get pending events (read-only)
   */
  get pending(): readonly NoticeEvent[] {
    return this.batch;
  }

  /**
   * Clear the batch without sending
   */
  clear(): void {
    this.batch = [];
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }
}

// ============= Global Batcher Instance =============

let globalBatcher: NoticeBatcher | null = null;

/**
 * Get or create the global notice batcher
 */
export function getNoticeBatcher(config?: Partial<NoticeBatcherConfig>): NoticeBatcher {
  if (!globalBatcher) {
    globalBatcher = new NoticeBatcher(config);
  }
  return globalBatcher;
}

/**
 * Reset the global batcher (for testing)
 */
export function resetNoticeBatcher(): void {
  if (globalBatcher) {
    globalBatcher.clear();
  }
  globalBatcher = null;
}

// ============= Notice Sending =============

/**
 * Send a notice to the rollup server
 */
export async function sendNotice(payload: unknown): Promise<void> {
  const config = getConfig();
  const rollupServer = config.rollupHttpServerUrl || process.env.ROLLUP_HTTP_SERVER_URL;

  if (!rollupServer) {
    throw new Error('Rollup server URL not configured');
  }

  // Encode payload as hex
  const jsonStr = JSON.stringify(payload);
  const hexPayload = '0x' + Buffer.from(jsonStr, 'utf8').toString('hex');

  const response = await fetch(`${rollupServer}/notice`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ payload: hexPayload }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Notice submission failed: ${text}`);
  }
}

/**
 * Send a single notice immediately (bypasses batcher)
 */
export async function sendImmediateNotice(event: NoticeEvent): Promise<void> {
  await sendNotice(event);
}

// ============= Common Event Types =============

export function createTransferEvent(
  tokenId: string,
  from: string,
  to: string,
  amount: string
): NoticeEvent {
  return {
    type: 'token_transfer',
    data: { token_id: tokenId, from, to, amount },
  };
}

export function createMintEvent(
  tokenId: string,
  to: string,
  amount: string
): NoticeEvent {
  return {
    type: 'token_mint',
    data: { token_id: tokenId, to, amount },
  };
}

export function createBurnEvent(
  tokenId: string,
  from: string,
  amount: string
): NoticeEvent {
  return {
    type: 'token_burn',
    data: { token_id: tokenId, from, amount },
  };
}

export function createStateChangeEvent(
  entityType: string,
  entityId: string,
  oldState: string,
  newState: string
): NoticeEvent {
  return {
    type: 'state_change',
    data: { entity_type: entityType, entity_id: entityId, old_state: oldState, new_state: newState },
  };
}

export function createErrorEvent(
  operation: string,
  error: string,
  details?: unknown
): NoticeEvent {
  return {
    type: 'error',
    data: { operation, error, details },
  };
}
