/**
 * L{CORE} Encryption Module
 *
 * Provides encryption utilities for protecting sensitive outputs from the Cartesi DApp.
 * Uses X25519 ECDH + XChaCha20-Poly1305 AEAD for authenticated asymmetric encryption.
 *
 * ARCHITECTURE:
 * - Admin public key is stored in the database (set at deployment)
 * - All sensitive outputs are encrypted with the admin public key
 * - Only the TEE Attestor (which holds the private key) can decrypt
 * - Aggregate statistics (counts) are NOT encrypted (no PII)
 *
 * See docs/LCORE-ARCHITECTURE.md for full privacy model documentation.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import nacl from 'tweetnacl';
import { getDatabase } from './db';

// ============= Types =============

export type CipherAlgorithm = 'nacl-box' | 'xchacha20-poly1305';

export interface EncryptedOutput {
  version: 1;
  algorithm: CipherAlgorithm;
  nonce: string;        // Base64-encoded 24-byte nonce
  ciphertext: string;   // Base64-encoded encrypted data
  publicKey: string;    // Base64-encoded ephemeral public key
}

export interface EncryptionConfig {
  key_id: string;
  public_key: string;   // Base64-encoded 32-byte public key
  algorithm: string;
  created_at: number;
  status: 'active' | 'deprecated';
}

// ============= Schema Initialization =============

/**
 * Initialize the encryption_config table.
 * Call this in initLCoreSchema() or separately.
 */
export function initEncryptionSchema(): void {
  const db = getDatabase();

  db.run(`
    -- Encryption configuration table
    CREATE TABLE IF NOT EXISTS encryption_config (
      key_id TEXT PRIMARY KEY,
      public_key TEXT NOT NULL,
      algorithm TEXT NOT NULL DEFAULT 'xchacha20-poly1305',
      created_at INTEGER NOT NULL,
      status TEXT DEFAULT 'active'
    );

    -- Index for active keys
    CREATE INDEX IF NOT EXISTS idx_encryption_status ON encryption_config(status);
  `);

  console.log('Encryption schema initialized');
}

// ============= Key Management =============

// In-memory admin public key for encryption (alternative to database)
let adminPublicKeyMemory: Uint8Array | null = null;

/**
 * Initialize output encryption with the admin public key.
 * This stores the key in memory for use during the session.
 *
 * For production, you may prefer setEncryptionKey() which persists to database.
 *
 * @param publicKeyBase64 - Base64-encoded 32-byte NaCl public key
 */
export function initEncryption(publicKeyBase64: string): void {
  try {
    adminPublicKeyMemory = base64ToUint8Array(publicKeyBase64);

    if (adminPublicKeyMemory.length !== 32) {
      throw new Error(`Invalid public key length: expected 32 bytes, got ${adminPublicKeyMemory.length}`);
    }

    console.log('[LCORE] Output encryption initialized (in-memory)');
  } catch (e) {
    console.error('[LCORE] Failed to initialize encryption:', e);
    adminPublicKeyMemory = null;
  }
}

/**
 * Set the admin encryption public key.
 * This should only be called once at deployment (or during key rotation).
 *
 * @param publicKeyBase64 - Base64-encoded 32-byte NaCl public key
 * @param inputIndex - Current input index for timestamping
 * @returns The created encryption config
 */
export function setEncryptionKey(
  publicKeyBase64: string,
  inputIndex: number,
  keyId?: string
): EncryptionConfig {
  const db = getDatabase();

  // Validate the public key is valid base64 and correct length
  try {
    const publicKeyBytes = base64ToUint8Array(publicKeyBase64);
    if (publicKeyBytes.length !== 32) {
      throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKeyBytes.length}`);
    }
  } catch (e) {
    throw new Error(`Invalid public key: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Use provided key ID or derive a deterministic one from the input index.
  // MUST NOT include wall-clock time: key_id is written to state AND emitted in
  // the set/rotate_encryption_key notice (a committed output), so a Date.now()
  // component would make both non-deterministic. input_index is unique per input.
  const resolvedKeyId = keyId ?? `key_${inputIndex}`;

  // Deprecate any existing active keys
  db.run(`UPDATE encryption_config SET status = 'deprecated' WHERE status = 'active'`);

  // Insert the new key
  db.run(
    `INSERT INTO encryption_config (key_id, public_key, algorithm, created_at, status)
     VALUES (?, ?, ?, ?, ?)`,
    [resolvedKeyId, publicKeyBase64, 'xchacha20-poly1305', inputIndex, 'active']
  );

  console.log(`Encryption key set: ${resolvedKeyId}`);
  return getActiveEncryptionConfig()!;
}

/**
 * Get the active encryption configuration.
 * Returns null if no encryption key has been set.
 */
export function getActiveEncryptionConfig(): EncryptionConfig | null {
  const db = getDatabase();

  const result = db.exec(
    `SELECT key_id, public_key, algorithm, created_at, status
     FROM encryption_config WHERE status = 'active' LIMIT 1`
  );

  const row = result[0]?.values[0];
  if (!row) return null;

  return {
    key_id: row[0] as string,
    public_key: row[1] as string,
    algorithm: row[2] as string,
    created_at: row[3] as number,
    status: row[4] as 'active' | 'deprecated',
  };
}

/**
 * Check if encryption is configured and ready.
 * Checks both in-memory key and database-stored key.
 */
export function isEncryptionConfigured(): boolean {
  return adminPublicKeyMemory !== null || getActiveEncryptionConfig() !== null;
}

/**
 * Get the admin public key (from memory or database).
 */
function getAdminPublicKey(): Uint8Array | null {
  if (adminPublicKeyMemory) {
    return adminPublicKeyMemory;
  }

  const config = getActiveEncryptionConfig();
  if (config) {
    return base64ToUint8Array(config.public_key);
  }

  return null;
}

// ============= Encryption Functions =============

/**
 * Encrypt sensitive data for output.
 *
 * Uses X25519 ECDH + XChaCha20-Poly1305 AEAD with an ephemeral keypair
 * for forward secrecy.
 *
 * @param data - Data to encrypt (will be JSON.stringified if not already a string)
 * @returns EncryptedOutput object ready for serialization
 * @throws Error if encryption is not configured
 */
export function encryptOutput(data: unknown): EncryptedOutput {
  const adminPublicKey = getAdminPublicKey();
  if (!adminPublicKey) {
    throw new Error('Encryption not configured - admin public key not set');
  }

  // Convert data to string
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // Generate ephemeral keypair for this message (forward secrecy)
  const ephemeral = nacl.box.keyPair();

  // Generate random 24-byte nonce (safe with random nonces for XChaCha20)
  const nonce = nacl.randomBytes(24);

  // X25519 ECDH shared secret
  const sharedSecret = nacl.scalarMult(ephemeral.secretKey, adminPublicKey);

  // Encrypt using XChaCha20-Poly1305 AEAD
  const ciphertext = xchacha20poly1305(sharedSecret, nonce).encrypt(plaintextBytes);

  return {
    version: 1,
    algorithm: 'xchacha20-poly1305',
    nonce: uint8ArrayToBase64(nonce),
    ciphertext: uint8ArrayToBase64(ciphertext),
    publicKey: uint8ArrayToBase64(ephemeral.publicKey),
  };
}

/**
 * Encrypt a response and wrap it in a standard envelope.
 *
 * @param data - The data to encrypt
 * @param metadata - Optional metadata to include (unencrypted)
 * @returns Object with encrypted payload and metadata
 */
export function encryptResponse<T = unknown>(
  data: T,
  metadata?: Record<string, unknown>
): {
  encrypted: true;
  payload: EncryptedOutput;
  metadata?: Record<string, unknown>;
} {
  return {
    encrypted: true,
    payload: encryptOutput(data),
    metadata,
  };
}

/**
 * Create a response that may or may not be encrypted based on sensitivity.
 *
 * @param data - The data to return
 * @param sensitive - Whether this data contains PII and should be encrypted
 * @returns Either encrypted or plaintext response
 */
export function createResponse<T = unknown>(
  data: T,
  sensitive: boolean
): { encrypted: false; data: T } | { encrypted: true; payload: EncryptedOutput } {
  if (sensitive && isEncryptionConfigured()) {
    return {
      encrypted: true,
      payload: encryptOutput(data),
    };
  }

  return {
    encrypted: false,
    data,
  };
}

// ============= Helper Functions =============

/**
 * Convert a Base64 string to Uint8Array.
 */
function base64ToUint8Array(base64: string): Uint8Array {
  // Node.js Buffer approach
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

/**
 * Convert a Uint8Array to Base64 string.
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  // Node.js Buffer approach
  return Buffer.from(bytes).toString('base64');
}

// ============= Determinism Note =============

/**
 * WARNING: encryptOutput() is NON-DETERMINISTIC. randomBytes()/nacl.box.keyPair()
 * use crypto.getRandomValues(), so the SAME plaintext yields DIFFERENT ciphertext
 * bytes on every call.
 *
 * This is SAFE ONLY for INSPECT REPORTS, which are not part of the rollup's
 * on-chain output claim. That is exactly (and only) how it is wired today:
 * processOutputSync() is applied on the inspect path (see router.ts), never to
 * advance-path outputs.
 *
 * It is NOT SAFE for anything emitted during `advance`:
 * - Notices and vouchers are hashed into the epoch's output Merkle root. Two
 *   honest validators re-executing the same input would produce different
 *   ciphertext -> different output hashes -> fraud proofs CANNOT converge.
 * - Storing random ciphertext in SQLite likewise diverges the state hash.
 *
 * DO NOT call encryptOutput/encryptResponse on an advance handler's `response`,
 * notice, voucher, or any value written to state. If encrypted advance output is
 * ever required, derive the nonce and ephemeral key DETERMINISTICALLY from the
 * input (e.g. HKDF over input_hash + a counter) — accepting the loss of forward
 * secrecy — or perform the encryption off-chain in the attestor, not in the VM.
 */

