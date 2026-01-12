/**
 * L{CORE} Rollup Server
 *
 * Implementation of the Cartesi rollup server HTTP API.
 * This server:
 * 1. Accepts advance/inspect requests via HTTP endpoints
 * 2. Queues them for the DApp to process via /finish
 * 3. Collects notices, reports, and vouchers from the DApp
 * 4. Returns results to clients
 */

import http from 'http';
import { URL } from 'url';

// ============= Types =============

interface AdvanceRequest {
  type: 'advance';
  metadata: {
    msg_sender: string;
    epoch_index: number;
    input_index: number;
    block_number: number;
    timestamp: number;
  };
  payload: string; // hex-encoded
}

interface InspectRequest {
  type: 'inspect';
  payload: string; // hex-encoded
}

interface QueuedRequest {
  id: string;
  request: AdvanceRequest | InspectRequest;
  resolve: (result: RequestResult) => void;
  notices: Array<{ payload: string }>;
  reports: Array<{ payload: string }>;
  vouchers: Array<{ destination: string; payload: string }>;
}

interface RequestResult {
  status: 'accept' | 'reject';
  notices: Array<{ payload: string }>;
  reports: Array<{ payload: string }>;
  vouchers: Array<{ destination: string; payload: string }>;
}

// ============= State =============

const requestQueue: QueuedRequest[] = [];
let currentRequest: QueuedRequest | null = null;
let inputIndex = 0;
let waitingFinishResponse: ((data: unknown) => void) | null = null;

// ============= Helpers =============

function stringToHex(str: string): string {
  return '0x' + Buffer.from(str, 'utf8').toString('hex');
}

function hexToString(hex: string): string {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  return Buffer.from(cleanHex, 'hex').toString('utf8');
}

function generateId(): string {
  return Math.random().toString(36).substring(2, 15);
}

// ============= Request Handlers =============

/**
 * Handle POST /finish - DApp polls this to get next request
 */
function handleFinish(body: string, res: http.ServerResponse): void {
  const data = JSON.parse(body);
  const status = data.status as 'accept' | 'reject';

  // If there's a current request being processed, complete it
  if (currentRequest) {
    const result: RequestResult = {
      status,
      notices: currentRequest.notices,
      reports: currentRequest.reports,
      vouchers: currentRequest.vouchers,
    };
    currentRequest.resolve(result);
    currentRequest = null;
  }

  // Check if there's a queued request
  if (requestQueue.length > 0) {
    currentRequest = requestQueue.shift()!;

    const rollupRequest =
      currentRequest.request.type === 'advance'
        ? {
            request_type: 'advance_state',
            data: {
              metadata: currentRequest.request.metadata,
              payload: currentRequest.request.payload,
            },
          }
        : {
            request_type: 'inspect_state',
            data: {
              payload: currentRequest.request.payload,
            },
          };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(rollupRequest));
  } else {
    // No pending requests - respond with 202
    res.writeHead(202, { 'Content-Type': 'text/plain' });
    res.end('no pending inputs');
  }
}

/**
 * Handle POST /notice - DApp sends notices here
 */
function handleNotice(body: string, res: http.ServerResponse): void {
  if (currentRequest) {
    const data = JSON.parse(body);
    currentRequest.notices.push({ payload: data.payload });
    console.log('[Notice]', hexToString(data.payload).substring(0, 100));
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true }));
}

/**
 * Handle POST /report - DApp sends reports here
 */
function handleReport(body: string, res: http.ServerResponse): void {
  if (currentRequest) {
    const data = JSON.parse(body);
    currentRequest.reports.push({ payload: data.payload });
    console.log('[Report]', hexToString(data.payload).substring(0, 200));
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true }));
}

/**
 * Handle POST /voucher - DApp sends vouchers here
 */
function handleVoucher(body: string, res: http.ServerResponse): void {
  if (currentRequest) {
    const data = JSON.parse(body);
    currentRequest.vouchers.push({
      destination: data.destination,
      payload: data.payload,
    });
    console.log('[Voucher]', data.destination);
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true }));
}

// ============= Input API Endpoints =============

/**
 * POST /input/advance - Submit an advance request
 * Body: { sender: string, payload: object }
 * Returns: { status, notices, reports, vouchers }
 */
async function handleInputAdvance(
  body: string,
  res: http.ServerResponse
): Promise<void> {
  const data = JSON.parse(body);
  const sender = data.sender || '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266';
  const payload = data.payload;

  const request: AdvanceRequest = {
    type: 'advance',
    metadata: {
      msg_sender: sender,
      epoch_index: 0,
      input_index: inputIndex++,
      block_number: Date.now(),
      timestamp: Math.floor(Date.now() / 1000),
    },
    payload: stringToHex(JSON.stringify(payload)),
  };

  const result = await queueRequest(request);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      status: result.status,
      notices: result.notices.map(n => ({
        payload: hexToString(n.payload),
        payloadJson: safeParseJson(hexToString(n.payload)),
      })),
      reports: result.reports.map(r => ({
        payload: hexToString(r.payload),
        payloadJson: safeParseJson(hexToString(r.payload)),
      })),
      vouchers: result.vouchers,
    })
  );
}

/**
 * POST /input/inspect - Submit an inspect request
 * Body: { query: string } or { type: string, params: object }
 * Returns: { reports }
 */
async function handleInputInspect(
  body: string,
  res: http.ServerResponse
): Promise<void> {
  const data = JSON.parse(body);

  // Support both query string format and JSON format
  let payloadStr: string;
  if (data.query) {
    payloadStr = data.query;
  } else if (data.type) {
    payloadStr = JSON.stringify({ type: data.type, params: data.params || {} });
  } else {
    payloadStr = JSON.stringify(data);
  }

  const request: InspectRequest = {
    type: 'inspect',
    payload: stringToHex(payloadStr),
  };

  const result = await queueRequest(request);

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      reports: result.reports.map(r => ({
        payload: hexToString(r.payload),
        payloadJson: safeParseJson(hexToString(r.payload)),
      })),
    })
  );
}

/**
 * GET /status - Get server status
 */
function handleStatus(res: http.ServerResponse): void {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(
    JSON.stringify({
      status: 'running',
      inputIndex,
      queueLength: requestQueue.length,
      processingRequest: currentRequest !== null,
    })
  );
}

// ============= Queue Management =============

function queueRequest(
  request: AdvanceRequest | InspectRequest
): Promise<RequestResult> {
  return new Promise(resolve => {
    const queuedRequest: QueuedRequest = {
      id: generateId(),
      request,
      resolve,
      notices: [],
      reports: [],
      vouchers: [],
    };
    requestQueue.push(queuedRequest);
    console.log(
      `[Queue] Added ${request.type} request (queue length: ${requestQueue.length})`
    );
  });
}

function safeParseJson(str: string): unknown {
  try {
    return JSON.parse(str);
  } catch {
    return null;
  }
}

// ============= Server =============

const server = http.createServer((req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const path = url.pathname;

  let body = '';
  req.on('data', chunk => {
    body += chunk;
  });

  req.on('end', async () => {
    try {
      // Cartesi rollup server endpoints (for DApp)
      if (path === '/finish' && req.method === 'POST') {
        handleFinish(body, res);
      } else if (path === '/notice' && req.method === 'POST') {
        handleNotice(body, res);
      } else if (path === '/report' && req.method === 'POST') {
        handleReport(body, res);
      } else if (path === '/voucher' && req.method === 'POST') {
        handleVoucher(body, res);
      }
      // Input API endpoints (for clients)
      else if (path === '/input/advance' && req.method === 'POST') {
        await handleInputAdvance(body, res);
      } else if (path === '/input/inspect' && req.method === 'POST') {
        await handleInputInspect(body, res);
      } else if (path === '/status' && req.method === 'GET') {
        handleStatus(res);
      } else if (path === '/health' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'healthy' }));
      }
      // Legacy /test/* endpoints (for backwards compatibility)
      else if (path === '/test/advance' && req.method === 'POST') {
        await handleInputAdvance(body, res);
      } else if (path === '/test/inspect' && req.method === 'POST') {
        await handleInputInspect(body, res);
      } else if (path === '/test/status' && req.method === 'GET') {
        handleStatus(res);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    } catch (error) {
      console.error('Error handling request:', error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: String(error) }));
    }
  });
});

const PORT = parseInt(process.env.PORT || '5004', 10);

server.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║              L{CORE} Rollup Server                           ║
╠══════════════════════════════════════════════════════════════╣
║  Cartesi API (for DApp):                                     ║
║    POST /finish  - DApp polls for next request               ║
║    POST /notice  - DApp submits notices                      ║
║    POST /report  - DApp submits reports                      ║
║    POST /voucher - DApp submits vouchers                     ║
╠══════════════════════════════════════════════════════════════╣
║  Input API (for clients):                                    ║
║    POST /input/advance - Submit advance request              ║
║    POST /input/inspect - Submit inspect query                ║
║    GET  /status        - Get server status                   ║
║    GET  /health        - Health check                        ║
╠══════════════════════════════════════════════════════════════╣
║  Listening on port ${PORT}                                       ║
╚══════════════════════════════════════════════════════════════╝
  `);
});
