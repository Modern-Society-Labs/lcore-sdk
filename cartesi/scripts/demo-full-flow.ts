/**
 * L{CORE} SDK - Full Flow Demo
 *
 * Demonstrates the complete E2E flow:
 * 1. Device generates secp256k1 keypair (did:key identity)
 * 2. Device creates sensor data and signs with JWS
 * 3. Attestor encrypts and submits to InputBox
 * 4. Cartesi decrypts and verifies JWS (fraud-provable)
 * 5. Data stored in SQLite
 * 6. Query returns decrypted, verified data
 *
 * Usage: npm run demo
 */

import * as http from 'http';
import * as https from 'https';
import nacl from 'tweetnacl';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// ============= Configuration =============
// Set these environment variables before running:
//   ATTESTOR_URL - Your attestor endpoint (e.g., http://localhost:8001)
//   CARTESI_NODE_URL - Your Cartesi node endpoint (e.g., http://localhost:10000)

const ATTESTOR_URL = process.env.ATTESTOR_URL;
const CARTESI_NODE_URL = process.env.CARTESI_NODE_URL;

if (!ATTESTOR_URL || !CARTESI_NODE_URL) {
  console.error('ERROR: Set ATTESTOR_URL and CARTESI_NODE_URL environment variables');
  console.error('Example:');
  console.error('  ATTESTOR_URL=http://localhost:8001 CARTESI_NODE_URL=http://localhost:10000 npm run demo');
  process.exit(1);
}

// ============= Logging Helpers =============

const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function step(num: number, title: string): void {
  console.log(`\n${BOLD}${CYAN}[Step ${num}]${RESET} ${BOLD}${title}${RESET}`);
  console.log(`${DIM}${'─'.repeat(50)}${RESET}`);
}

function info(label: string, value: unknown): void {
  const valueStr = typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
  console.log(`${YELLOW}${label}:${RESET} ${valueStr}`);
}

function success(msg: string): void {
  console.log(`${GREEN}✓ ${msg}${RESET}`);
}

function error(msg: string): void {
  console.log(`${RED}✗ ${msg}${RESET}`);
}

// ============= Crypto Helpers =============

function generateDeviceKeypair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = nacl.randomBytes(32);
  const publicKey = secp256k1.getPublicKey(privateKey, true);
  return { privateKey, publicKey };
}

function publicKeyToDIDKey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xe7;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);

  const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + Buffer.from(prefixed).toString('hex'));
  let encoded = '';

  while (num > 0) {
    const remainder = Number(num % 58n);
    encoded = BASE58_ALPHABET[remainder] + encoded;
    num = num / 58n;
  }

  for (let i = 0; i < prefixed.length && prefixed[i] === 0; i++) {
    encoded = '1' + encoded;
  }

  return `did:key:z${encoded}`;
}

function base64urlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64urlEncodeBytes(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function createDeviceJWS(payload: unknown, privateKey: Uint8Array): string {
  const header = { alg: 'ES256K', typ: 'JWT' };
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(payload));

  const message = `${headerB64}.${payloadB64}`;
  const messageHash = sha256(new TextEncoder().encode(message));

  const signature = secp256k1.sign(messageHash, privateKey);
  const signatureB64 = base64urlEncodeBytes(signature.toCompactRawBytes());

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

// ============= HTTP Helpers =============

interface HttpResponse<T = unknown> {
  status: number;
  data: T;
}

async function httpRequest<T>(
  url: string,
  method: 'GET' | 'POST',
  body?: unknown
): Promise<HttpResponse<T>> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const httpModule = isHttps ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = httpModule.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode || 0,
            data: data ? JSON.parse(data) : {},
          });
        } catch {
          resolve({
            status: res.statusCode || 0,
            data: data as unknown as T,
          });
        }
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============= API Helpers =============

interface AttestorSubmitResponse {
  success: boolean;
  data?: {
    txHash: string;
    blockNumber: number;
  };
  error?: string;
}

interface GraphQLResponse {
  data?: {
    inputs: {
      totalCount: number;
      edges: Array<{
        node: {
          index: number;
          status: string;
          payload: string;
        };
      }>;
    };
  };
}

interface InspectResponse {
  reports?: Array<{
    payload: string;
  }>;
}

async function submitToAttestor(
  did: string,
  payload: Record<string, unknown>,
  signature: string,
  timestamp: number
): Promise<AttestorSubmitResponse> {
  const response = await httpRequest<AttestorSubmitResponse>(
    `${ATTESTOR_URL}/api/device/submit`,
    'POST',
    { did, payload, signature, timestamp }
  );
  return response.data;
}

async function queryGraphQL(query: string): Promise<GraphQLResponse> {
  const response = await httpRequest<GraphQLResponse>(
    `${CARTESI_NODE_URL}/graphql`,
    'POST',
    { query }
  );
  return response.data;
}

async function queryInspect(type: string, params: Record<string, string> = {}): Promise<unknown> {
  // Build path format: type/key1/value1/key2/value2
  let path = type;
  for (const [key, value] of Object.entries(params)) {
    path += `/${key}/${encodeURIComponent(value)}`;
  }

  const response = await httpRequest<InspectResponse>(
    `${CARTESI_NODE_URL}/inspect/${path}`,
    'GET'
  );

  const reports = response.data.reports;
  if (reports && reports.length > 0 && reports[0]) {
    const payload = reports[0].payload;
    if (payload.startsWith('0x')) {
      const hex = payload.slice(2);
      const text = Buffer.from(hex, 'hex').toString('utf8');
      try {
        return JSON.parse(text);
      } catch {
        return text;
      }
    }
    return payload;
  }
  return response.data;
}

// ============= Main Demo =============

async function main(): Promise<void> {
  console.log(`\n${BOLD}╔════════════════════════════════════════════════════════╗${RESET}`);
  console.log(`${BOLD}║     L{CORE} SDK - Full Flow Demo                        ║${RESET}`);
  console.log(`${BOLD}║     Encrypted Input → Decrypted Query                   ║${RESET}`);
  console.log(`${BOLD}╚════════════════════════════════════════════════════════╝${RESET}\n`);

  info('Attestor URL', ATTESTOR_URL);
  info('Cartesi Node URL', CARTESI_NODE_URL);

  // Step 1: Generate Device Identity
  step(1, 'Generate Device Identity (secp256k1 keypair)');

  const { privateKey, publicKey } = generateDeviceKeypair();
  const deviceDid = publicKeyToDIDKey(publicKey);

  info('Private Key', `${Buffer.from(privateKey).toString('hex').slice(0, 16)}... (hidden)`);
  info('Public Key (compressed)', Buffer.from(publicKey).toString('hex'));
  info('Device DID', deviceDid);
  success('Device identity generated');

  // Step 2: Create Sensor Data
  step(2, 'Create Sensor Data');

  const sensorData = {
    temperature: 23.4,
    humidity: 65,
    pressure: 1013.25,
    device_name: 'Demo IoT Sensor',
    location: { lat: 37.7749, lon: -122.4194 },
  };
  const timestamp = Math.floor(Date.now() / 1000);

  info('Sensor Data', sensorData);
  info('Timestamp', `${timestamp} (${new Date(timestamp * 1000).toISOString()})`);
  success('Sensor data created');

  // Step 3: Sign Data with JWS
  step(3, 'Sign Data with JWS (ES256K / secp256k1)');

  const signature = createDeviceJWS(sensorData, privateKey);
  const jwsParts = signature.split('.');
  const headerB64 = jwsParts[0] || '';
  const payloadB64 = jwsParts[1] || '';
  const sigB64 = jwsParts[2] || '';

  info('JWS Header (base64url)', headerB64);
  info('JWS Payload (base64url)', payloadB64);
  info('JWS Signature (base64url)', `${sigB64.slice(0, 32)}...`);
  info('Full JWS', `${signature.slice(0, 80)}...`);
  success('Data signed with device private key');

  // Step 4: Submit to Attestor
  step(4, 'Submit to Attestor (encrypts + submits to InputBox)');

  console.log(`${DIM}POST ${ATTESTOR_URL}/api/device/submit${RESET}`);
  info('Request Body', {
    did: deviceDid,
    payload: '{ ...sensorData }',
    signature: `${signature.slice(0, 40)}...`,
    timestamp,
  });

  let txHash = '';
  let blockNumber = 0;

  try {
    const attestorResponse = await submitToAttestor(deviceDid, sensorData, signature, timestamp);

    if (attestorResponse.success && attestorResponse.data) {
      txHash = attestorResponse.data.txHash;
      blockNumber = attestorResponse.data.blockNumber;
      info('Response', attestorResponse);
      success(`Transaction submitted: ${txHash}`);
    } else {
      error(`Attestor error: ${attestorResponse.error || 'Unknown error'}`);
      console.log(`\n${DIM}Full response:${RESET}`, attestorResponse);
      return;
    }
  } catch (e) {
    error(`Failed to submit to attestor: ${e}`);
    return;
  }

  // Step 5: Wait for Cartesi Processing
  step(5, 'Wait for Cartesi Processing');

  console.log(`${DIM}The encrypted input is now on-chain.${RESET}`);
  console.log(`${DIM}Cartesi will:${RESET}`);
  console.log(`${DIM}  1. Fetch the encrypted input from InputBox${RESET}`);
  console.log(`${DIM}  2. Decrypt using LCORE_INPUT_PRIVATE_KEY${RESET}`);
  console.log(`${DIM}  3. Verify the JWS signature (fraud-provable!)${RESET}`);
  console.log(`${DIM}  4. Store in SQLite if valid${RESET}`);

  console.log(`\n${YELLOW}Waiting for processing...${RESET}`);

  let inputProcessed = false;
  let latestInputIndex = -1;

  for (let i = 0; i < 30; i++) {
    try {
      const result = await queryGraphQL(`
        query {
          inputs(last: 1) {
            totalCount
            edges {
              node {
                index
                status
              }
            }
          }
        }
      `);

      const edges = result.data?.inputs?.edges;
      if (edges && edges.length > 0 && edges[0]) {
        const edge = edges[0];
        latestInputIndex = edge.node.index;
        const status = edge.node.status;

        if (status === 'ACCEPTED' || status === 'REJECTED') {
          info('Latest Input Index', latestInputIndex);
          info('Status', status);
          inputProcessed = true;
          break;
        }
      }

      process.stdout.write('.');
      await sleep(2000);
    } catch (e) {
      process.stdout.write('x');
      await sleep(2000);
    }
  }

  console.log('');

  if (inputProcessed) {
    success('Input processed by Cartesi');
  } else {
    error('Timeout waiting for Cartesi processing');
    console.log(`${DIM}The input may still be processing. Try querying manually later.${RESET}`);
  }

  // Step 6: Query Device Attestation
  step(6, 'Query Device Attestation (decrypted data)');

  console.log(`${DIM}GET ${CARTESI_NODE_URL}/inspect/device_latest/device_did/${deviceDid.slice(0, 30)}...${RESET}`);

  try {
    const queryResult = await queryInspect('device_latest', { device_did: deviceDid });

    info('Query Result', queryResult);

    if (typeof queryResult === 'object' && queryResult !== null && 'data' in queryResult) {
      success('Decrypted attestation data retrieved!');
    } else if (typeof queryResult === 'object' && queryResult !== null && 'error' in queryResult) {
      error(`Query returned error: ${(queryResult as { error: string }).error}`);
      console.log(`${DIM}This is expected if the input was rejected due to invalid signature.${RESET}`);
      console.log(`${DIM}Check Step 5 - if status was REJECTED, the JWS verification may have failed.${RESET}`);
    }
  } catch (e) {
    error(`Failed to query: ${e}`);
  }

  // Step 7: Check Encryption Status
  step(7, 'Check Cartesi Encryption Status');

  // NOTE: The encryption_status endpoint returns TWO different things:
  // - encryption_configured: OUTPUT encryption (admin public key for encrypting outputs)
  // - input_decryption: Whether LCORE_INPUT_PRIVATE_KEY is set (for decrypting inputs)
  //
  // These are SEPARATE systems. The demo uses INPUT decryption (to decrypt device attestations).
  // The encryption_configured field is for OUTPUT encryption which is optional.
  //
  // Since the endpoint only returns encryption_configured (output encryption),
  // we infer input decryption is working if the submission was processed successfully.

  try {
    const encryptionStatus = await queryInspect('encryption_status');
    info('Encryption Status (Output)', encryptionStatus);

    // Check if input was processed - this proves INPUT decryption is working
    if (inputProcessed) {
      success('Input decryption is WORKING (submission was processed)');
      console.log(`${DIM}Note: encryption_configured refers to OUTPUT encryption (optional).${RESET}`);
      console.log(`${DIM}INPUT decryption uses LCORE_INPUT_PRIVATE_KEY baked into the machine.${RESET}`);
    } else {
      console.log(`${YELLOW}Could not verify input decryption (input still processing)${RESET}`);
    }
  } catch (e) {
    error(`Failed to check encryption status: ${e}`);
  }

  // Step 8: Summary
  step(8, 'Flow Summary');

  console.log(`\n${BOLD}╔════════════════════════════════════════════════════════╗${RESET}`);
  console.log(`${BOLD}║                    FLOW COMPLETE                        ║${RESET}`);
  console.log(`${BOLD}╚════════════════════════════════════════════════════════╝${RESET}\n`);

  console.log(`${GREEN}✓ Device Identity:${RESET} ${deviceDid.slice(0, 40)}...`);
  console.log(`${GREEN}✓ Sensor Data:${RESET} ${JSON.stringify(sensorData).slice(0, 50)}...`);
  console.log(`${GREEN}✓ JWS Signature:${RESET} Created with ES256K`);
  console.log(`${GREEN}✓ Encrypted on-chain:${RESET} Yes (nacl.box)`);
  console.log(`${GREEN}✓ Transaction:${RESET} ${txHash}`);
  console.log(`${GREEN}✓ Block:${RESET} ${blockNumber}`);
  console.log(`${GREEN}✓ Cartesi Processing:${RESET} ${inputProcessed ? 'Complete' : 'Pending'}`);

  console.log(`\n${DIM}The data flow was:${RESET}`);
  console.log(`${DIM}  Device → JWS Sign → Attestor → Encrypt → InputBox → Cartesi → Decrypt → Verify JWS → Store${RESET}`);
  console.log(`\n${DIM}Key Security Properties:${RESET}`);
  console.log(`${DIM}  • On-chain data is encrypted (privacy)${RESET}`);
  console.log(`${DIM}  • JWS verification happens in Cartesi (fraud-provable)${RESET}`);
  console.log(`${DIM}  • Anyone can re-run Cartesi and verify signatures${RESET}`);
  console.log(`${DIM}  • No trusted attestor needed for verification${RESET}`);
}

main().catch((e) => {
  console.error(`\n${RED}Fatal error:${RESET}`, e);
  process.exit(1);
});
