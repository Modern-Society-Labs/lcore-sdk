import pino from 'pino';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface LogStreamMessage {
  type: 'log';
  data: {
    source: 'cartesi';
    timestamp: string;
    level: LogLevel;
    message: string;
    context?: Record<string, unknown>;
  };
}

// WebSocket client interface (minimal for our needs)
interface WsClient {
  readyState: number;
  OPEN: number;
  send: (data: string) => void;
  close: () => void;
  on: (event: string, handler: () => void) => void;
}

// Connected log stream clients
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const logClients: Set<WsClient> = new Set();

// Recent logs buffer for new clients
const recentLogs: LogStreamMessage[] = [];
const MAX_RECENT_LOGS = 100;

/**
 * Add a WebSocket client for log streaming
 */
export function addLogClient(ws: WsClient): void {
  logClients.add(ws);

  // Send recent logs to new client
  for (const log of recentLogs) {
    sendToClient(ws, log);
  }

  ws.on('close', () => {
    removeLogClient(ws);
  });

  ws.on('error', () => {
    removeLogClient(ws);
  });
}

/**
 * Remove a WebSocket client
 */
export function removeLogClient(ws: WsClient): void {
  logClients.delete(ws);
}

/**
 * Get number of connected log clients
 */
export function getLogClientCount(): number {
  return logClients.size;
}

/**
 * Broadcast a log entry to all connected clients
 */
function broadcast(level: LogLevel, message: string, context?: Record<string, unknown>): void {
  const logMessage: LogStreamMessage = {
    type: 'log',
    data: {
      source: 'cartesi',
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
    },
  };

  // Store in recent logs buffer
  recentLogs.push(logMessage);
  if (recentLogs.length > MAX_RECENT_LOGS) {
    recentLogs.shift();
  }

  // Broadcast to all clients
  for (const client of logClients) {
    sendToClient(client, logMessage);
  }
}

/**
 * Send a message to a specific client
 */
function sendToClient(ws: WsClient, message: LogStreamMessage): void {
  if (ws.readyState === 1) { // WebSocket.OPEN = 1
    try {
      ws.send(JSON.stringify(message));
    } catch {
      // Client may have disconnected
      removeLogClient(ws);
    }
  }
}

/**
 * Create the pino logger with WebSocket broadcasting
 */
export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: {
    target: 'pino/file',
    options: { destination: 1 }, // stdout
  },
  hooks: {
    logMethod(inputArgs, method, level) {
      // Map pino level numbers to our level strings
      const levelMap: Record<number, LogLevel> = {
        10: 'debug', // trace -> debug
        20: 'debug',
        30: 'info',
        40: 'warn',
        50: 'error',
        60: 'error', // fatal -> error
      };

      const logLevel = levelMap[level] || 'info';

      // Extract message and context from pino args
      let message = '';
      let context: Record<string, unknown> | undefined;

      if (typeof inputArgs[0] === 'string') {
        message = inputArgs[0];
      } else if (typeof inputArgs[0] === 'object' && inputArgs[0] !== null) {
        context = inputArgs[0] as Record<string, unknown>;
        message = (inputArgs[1] as string) || '';
      }

      // Broadcast to WebSocket clients
      broadcast(logLevel, message, context);

      // Call original method
      return method.apply(this, inputArgs);
    },
  },
});

/**
 * Close all log client connections
 */
export function closeLogClients(): void {
  for (const client of logClients) {
    client.close();
  }
  logClients.clear();
}
