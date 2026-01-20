/**
 * JWS Verification Module for Cartesi
 *
 * Provides fraud-provable signature verification for device attestations.
 * All verification happens inside Cartesi, making it deterministic and re-runnable.
 *
 * This enables:
 * - Anyone can re-run Cartesi and verify every signature was valid
 * - No trusted attestor needed for verification
 * - Cryptographic proof of device identity
 *
 * IMPORTANT: All functions in this module are DETERMINISTIC.
 * Given the same inputs, they always produce the same outputs.
 * This is critical for Cartesi's fraud-proof verification.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

// ============= Base58btc Alphabet =============

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Decode a base58btc string to bytes.
 * Note: The 'z' multibase prefix should be removed before calling this.
 */
function base58btcDecode(str: string): Uint8Array {
  if (str.length === 0) {
    return new Uint8Array(0);
  }

  // Count leading zeros (represented as '1' in base58)
  let leadingZeros = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    leadingZeros++;
  }

  // Allocate enough space for the decoded bytes
  const size = Math.ceil((str.length * 733) / 1000) + 1;
  const bytes = new Uint8Array(size);

  // Process each character
  for (let i = 0; i < str.length; i++) {
    const char = str[i]!;
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    let carry = value;
    for (let j = size - 1; j >= 0; j--) {
      carry += 58 * (bytes[j] ?? 0);
      bytes[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
  }

  // Find first non-zero byte
  let start = 0;
  while (start < size && bytes[start] === 0) {
    start++;
  }

  // Create result with leading zeros preserved
  const result = new Uint8Array(leadingZeros + (size - start));
  result.fill(0, 0, leadingZeros);
  result.set(bytes.slice(start), leadingZeros);

  return result;
}

// ============= Base64url Utilities =============

/**
 * Decode a base64url string to a UTF-8 string.
 */
export function base64urlDecode(str: string): string {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padLength);

  // Decode base64 to bytes
  const binary = Buffer.from(base64, 'base64');
  return new TextDecoder().decode(binary);
}

/**
 * Decode a base64url string to bytes.
 */
function base64urlDecodeBytes(str: string): Uint8Array {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padLength = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padLength);

  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Encode a string to base64url (no padding).
 */
export function base64urlEncode(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// ============= DID Key Parsing =============

/**
 * Parse a did:key identifier and extract the raw secp256k1 public key bytes.
 *
 * did:key format: did:key:z<multibase-encoded-multicodec-pubkey>
 * For secp256k1: multicodec prefix is 0xe7 0x01
 *
 * @param did - The did:key identifier (e.g., "did:key:zQ3sh...")
 * @returns The raw 33-byte compressed public key
 * @throws Error if the DID format is invalid
 */
export function parseDIDKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error('Invalid did:key format - must start with did:key:z');
  }

  // Remove 'did:key:' prefix and 'z' multibase prefix
  const multibaseKey = did.slice(8); // Remove 'did:key:'
  const base58Encoded = multibaseKey.slice(1); // Remove 'z' prefix

  // Decode base58btc
  const decoded = base58btcDecode(base58Encoded);

  // Check for secp256k1-pub multicodec prefix (0xe7 0x01)
  if (decoded.length < 35) {
    throw new Error(`Invalid did:key - decoded length too short: ${decoded.length}`);
  }

  if (decoded[0] !== 0xe7 || decoded[1] !== 0x01) {
    throw new Error(`Invalid did:key - not a secp256k1 key (got prefix: 0x${decoded[0]!.toString(16)} 0x${decoded[1]!.toString(16)})`);
  }

  // Return the public key bytes (skip 2-byte multicodec prefix)
  return decoded.slice(2);
}

// ============= JWS Verification =============

/**
 * Verify a JWS (JSON Web Signature) compact serialization.
 *
 * JWS format: <header>.<payload>.<signature>
 * The signature is computed over: SHA256(<header>.<payload>)
 *
 * This function is DETERMINISTIC - safe for Cartesi's fraud-proof verification.
 *
 * @param jws - The JWS compact serialization
 * @param expectedPayload - The expected payload object (must match what was signed)
 * @param did - The device's did:key identifier
 * @returns True if signature is valid
 * @throws Error if verification fails (with reason)
 */
export function verifyJWS(
  jws: string,
  expectedPayload: unknown,
  did: string
): boolean {
  // Split JWS into parts
  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWS format - expected 3 parts separated by dots');
  }

  const headerB64 = parts[0]!;
  const payloadB64 = parts[1]!;
  const signatureB64 = parts[2]!;

  // Decode and verify header
  const headerJson = base64urlDecode(headerB64);
  const header = JSON.parse(headerJson);

  if (header.alg !== 'ES256K') {
    throw new Error(`Unsupported JWS algorithm: ${header.alg} (expected ES256K)`);
  }

  // Decode and verify payload matches expected
  const payloadJson = base64urlDecode(payloadB64);
  const payload = JSON.parse(payloadJson);

  // Canonical JSON comparison
  const expectedJson = JSON.stringify(expectedPayload);
  const actualJson = JSON.stringify(payload);

  if (expectedJson !== actualJson) {
    throw new Error('JWS payload does not match expected payload');
  }

  // Parse public key from DID
  const publicKey = parseDIDKey(did);

  // Decode signature
  const signature = base64urlDecodeBytes(signatureB64);

  // Compute message hash: SHA256(header.payload)
  const message = `${headerB64}.${payloadB64}`;
  const messageBytes = new TextEncoder().encode(message);
  const messageHash = sha256(messageBytes);

  // Verify secp256k1 signature
  const isValid = secp256k1.verify(signature, messageHash, publicKey);

  if (!isValid) {
    throw new Error('Invalid JWS signature - verification failed');
  }

  return true;
}

/**
 * Verify a JWS without throwing - returns a result object instead.
 *
 * @param jws - The JWS compact serialization
 * @param expectedPayload - The expected payload object
 * @param did - The device's did:key identifier
 * @returns Object with success status and optional error message
 */
export function verifyJWSSafe(
  jws: string,
  expectedPayload: unknown,
  did: string
): { valid: boolean; error?: string } {
  try {
    verifyJWS(jws, expectedPayload, did);
    return { valid: true };
  } catch (e) {
    return {
      valid: false,
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

/**
 * Validate a did:key format without parsing (quick check).
 */
export function isValidDIDKey(did: string): boolean {
  if (!did.startsWith('did:key:z')) {
    return false;
  }

  try {
    parseDIDKey(did);
    return true;
  } catch {
    return false;
  }
}
