/**
 * Cartesi Request Router
 *
 * This module handles routing of advance (state-changing) and inspect (read-only)
 * requests to appropriate handlers. It also manages authorization and payload validation.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Configure AUTHORIZED_SUBMITTERS via environment variable
 * 2. Adjust MAX_PAYLOAD_SIZE and MAX_STRING_LENGTH as needed
 * 3. Modify authorization logic in isAuthorizedSender() if needed
 */

import { stringToHex } from 'viem';

// ============= Types =============

export interface AdvanceMetadata {
  msg_sender: string;
  epoch_index: number;
  input_index: number;
  block_number: number;
  timestamp: number;
}

export interface AdvanceRequestData {
  metadata: AdvanceMetadata;
  payload: string;
}

export interface InspectRequestData {
  payload: string;
}

export type RequestHandlerResult = 'accept' | 'reject';

export type AdvanceHandler = (
  data: AdvanceRequestData,
  payload: unknown
) => Promise<{ status: RequestHandlerResult; response?: unknown }>;

export type InspectHandler = (query: InspectQuery) => Promise<unknown>;

export interface InspectQuery {
  type: string;
  params: Record<string, string>;
}

export interface RouteConfig {
  advance: Record<string, AdvanceHandler>;
  inspect: Record<string, InspectHandler>;
}

// ============= Configuration =============

const rollupServer = process.env.ROLLUP_HTTP_SERVER_URL;

/**
 * Maximum payload size in bytes (100KB)
 * CUSTOMIZE: Adjust based on your needs
 */
const MAX_PAYLOAD_SIZE = 100 * 1024;

/**
 * Maximum string field length (10KB)
 * CUSTOMIZE: Adjust based on your needs
 */
const MAX_STRING_LENGTH = 10 * 1024;

/**
 * Authorized submitters whitelist.
 * Only these addresses can submit advance requests.
 * Configured via AUTHORIZED_SENDERS environment variable.
 *
 * Format: comma-separated list of addresses
 * Example: AUTHORIZED_SENDERS=0x123...,0x456...
 */
const AUTHORIZED_SUBMITTERS = new Set<string>(
  (process.env.AUTHORIZED_SENDERS || '')
    .split(',')
    .map(addr => addr.trim().toLowerCase())
    .filter(addr => addr.length > 0)
);

// ============= Authorization =============

/**
 * Check if a sender is authorized to submit requests.
 * Returns true if whitelist is empty (development mode) or sender is whitelisted.
 *
 * CUSTOMIZE: Modify this function for custom authorization logic
 */
export function isAuthorizedSender(sender: string): boolean {
  // If whitelist is empty, allow all (development mode)
  if (AUTHORIZED_SUBMITTERS.size === 0) {
    console.log('Warning: Whitelist is empty, allowing all senders (development mode)');
    return true;
  }
  return AUTHORIZED_SUBMITTERS.has(sender.toLowerCase());
}

/**
 * Add an address to the whitelist.
 */
export function addAuthorizedSender(address: string): void {
  AUTHORIZED_SUBMITTERS.add(address.toLowerCase());
}

/**
 * Remove an address from the whitelist.
 */
export function removeAuthorizedSender(address: string): void {
  AUTHORIZED_SUBMITTERS.delete(address.toLowerCase());
}

/**
 * Clear all authorized senders from the whitelist.
 * Useful for testing.
 */
export function clearAuthorizedSenders(): void {
  AUTHORIZED_SUBMITTERS.clear();
}

// ============= Validation =============

/**
 * Validate string fields in payload don't exceed maximum length.
 * Throws error if any string field is too long.
 */
function validateStringLengths(obj: unknown, path = ''): void {
  if (typeof obj === 'string') {
    if (obj.length > MAX_STRING_LENGTH) {
      throw new Error(`String field ${path || 'value'} exceeds maximum length of ${MAX_STRING_LENGTH} bytes`);
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((item, index) => validateStringLengths(item, `${path}[${index}]`));
  } else if (obj !== null && typeof obj === 'object') {
    for (const [key, value] of Object.entries(obj)) {
      validateStringLengths(value, path ? `${path}.${key}` : key);
    }
  }
}

// ============= Router Class =============

/**
 * Router class for handling advance and inspect requests.
 */
export class Router {
  private advanceHandlers: Map<string, AdvanceHandler> = new Map();
  private inspectHandlers: Map<string, InspectHandler> = new Map();

  /**
   * Register an advance request handler for a specific action type.
   */
  registerAdvanceHandler(action: string, handler: AdvanceHandler): void {
    this.advanceHandlers.set(action, handler);
  }

  /**
   * Register an inspect request handler for a specific query type.
   */
  registerInspectHandler(queryType: string, handler: InspectHandler): void {
    this.inspectHandlers.set(queryType, handler);
  }

  /**
   * Handle an advance request (state-changing operation).
   */
  async handleAdvance(data: AdvanceRequestData): Promise<RequestHandlerResult> {
    try {
      // Check authorization
      const sender = data.metadata.msg_sender;
      if (!isAuthorizedSender(sender)) {
        console.log(`Rejected: unauthorized sender ${sender}`);
        await this.sendReport(`Unauthorized sender: ${sender}`);
        return 'reject';
      }

      // Decode payload
      if (!data.payload) {
        await this.sendReport('Payload is required');
        return 'reject';
      }

      // Check payload size
      const payloadHex = data.payload.slice(2);
      if (payloadHex.length / 2 > MAX_PAYLOAD_SIZE) {
        await this.sendReport(`Payload exceeds maximum size of ${MAX_PAYLOAD_SIZE} bytes`);
        return 'reject';
      }

      const payloadStr = Buffer.from(payloadHex, 'hex').toString('utf8');
      let payload: { action?: string; [key: string]: unknown };

      try {
        payload = JSON.parse(payloadStr);
      } catch (e) {
        await this.sendReport('Invalid JSON payload');
        return 'reject';
      }

      // Validate string field lengths
      try {
        validateStringLengths(payload);
      } catch (e) {
        await this.sendReport(e instanceof Error ? e.message : 'String validation failed');
        return 'reject';
      }

      // Route to appropriate handler
      const action = payload.action;
      if (!action || typeof action !== 'string') {
        await this.sendReport('Action is required in payload');
        return 'reject';
      }

      const handler = this.advanceHandlers.get(action);
      if (!handler) {
        await this.sendReport(`Unknown action: ${action}`);
        return 'reject';
      }

      // Execute handler
      const result = await handler(data, payload);

      // Send notice if response provided
      if (result.response) {
        await this.sendNotice(result.response);
      }

      return result.status;
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : String(e);
      console.error(`Advance handler error: ${errorMessage}`);
      await this.sendReport(`Error: ${errorMessage}`);
      return 'reject';
    }
  }

  /**
   * Handle an inspect request (read-only query).
   */
  async handleInspect(data: InspectRequestData): Promise<void> {
    try {
      if (!data.payload) {
        await this.sendReport('Payload is required');
        return;
      }

      const payloadStr = Buffer.from(data.payload.slice(2), 'hex').toString('utf8');
      const query = this.parseInspectQuery(payloadStr);

      const handler = this.inspectHandlers.get(query.type);
      if (!handler) {
        await this.sendReport(`Unknown query type: ${query.type}`);
        return;
      }

      const result = await handler(query);
      await this.sendReport(JSON.stringify(result));
    } catch (e) {
      const errorMessage = e instanceof Error ? e.message : String(e);
      console.error(`Inspect handler error: ${errorMessage}`);
      await this.sendReport(`Error: ${errorMessage}`);
    }
  }

  /**
   * Parse inspect query from payload string.
   * Supports two formats:
   * 1. JSON: {"type": "query_type", "params": {"key": "value"}}
   * 2. Path: type/param1/value1/param2/value2
   */
  private parseInspectQuery(payloadStr: string): InspectQuery {
    // Try JSON first
    try {
      const parsed = JSON.parse(payloadStr);
      if (parsed.type) {
        return {
          type: parsed.type,
          params: parsed.params || {},
        };
      }
    } catch {
      // Not JSON, try path format
    }

    // Parse path format: type/key1/value1/key2/value2
    const parts = payloadStr.split('/').filter(Boolean);
    if (parts.length === 0) {
      return { type: 'unknown', params: {} };
    }

    const type = parts[0] || 'unknown';
    const params: Record<string, string> = {};

    for (let i = 1; i < parts.length; i += 2) {
      const key = parts[i];
      const value = parts[i + 1];
      if (key && value !== undefined) {
        params[key] = value;
      } else if (key) {
        // Single value after type is treated as 'id'
        params['id'] = key;
      }
    }

    return { type, params };
  }

  /**
   * Send a notice to the rollup server.
   * Notices are on-chain proofs of state transitions.
   */
  private async sendNotice(data: unknown): Promise<void> {
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    await fetch(`${rollupServer}/notice`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload: stringToHex(payload) }),
    });
  }

  /**
   * Send a report to the rollup server.
   * Reports are used for query responses and error messages.
   */
  private async sendReport(data: string): Promise<void> {
    await fetch(`${rollupServer}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload: stringToHex(data) }),
    });
  }
}

// ============= Factory Function =============

/**
 * Create and configure a router with all handlers.
 *
 * @param config - Route configuration with advance and inspect handlers
 * @returns Configured Router instance
 *
 * @example
 * const router = createRouter({
 *   advance: {
 *     create_entity: handleCreateEntity,
 *     sync_data: handleSyncData,
 *   },
 *   inspect: {
 *     entity: handleInspectEntity,
 *     stats: handleInspectStats,
 *   },
 * });
 */
export function createRouter(config: RouteConfig): Router {
  const router = new Router();

  for (const [action, handler] of Object.entries(config.advance)) {
    router.registerAdvanceHandler(action, handler);
  }

  for (const [queryType, handler] of Object.entries(config.inspect)) {
    router.registerInspectHandler(queryType, handler);
  }

  return router;
}
