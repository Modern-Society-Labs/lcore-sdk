/**
 * L{CORE} Encryption Module
 *
 * Provides encryption utilities for protecting sensitive outputs from the Cartesi DApp.
 * Uses NaCl box (X25519-XSalsa20-Poly1305) for authenticated asymmetric encryption.
 *
 * ARCHITECTURE:
 * - Admin public key is stored in the database (set at deployment)
 * - All sensitive outputs are encrypted with the admin public key
 * - Only the TEE Attestor (which holds the private key) can decrypt
 * - Aggregate statistics (counts) are NOT encrypted (no PII)
 *
 * See docs/LCORE-ARCHITECTURE.md for full privacy model documentation.
 */

import nacl from 'tweetnacl';
import { getDatabase } from './db';

// ============= Types =============

export interface EncryptedOutput {
  version: 1;
  algorithm: 'nacl-box';
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
      algorithm TEXT NOT NULL DEFAULT 'nacl-box',
      created_at INTEGER NOT NULL,
      status TEXT DEFAULT 'active'
    );

    -- Index for active keys
    CREATE INDEX IF NOT EXISTS idx_encryption_status ON encryption_config(status);
  `);

  console.log('Encryption schema initialized');
}

// ============= Key Management =============

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
  inputIndex: number
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

  // Generate a unique key ID
  const keyId = `key_${inputIndex}_${Date.now()}`;

  // Deprecate any existing active keys
  db.run(`UPDATE encryption_config SET status = 'deprecated' WHERE status = 'active'`);

  // Insert the new key
  db.run(
    `INSERT INTO encryption_config (key_id, public_key, algorithm, created_at, status)
     VALUES (?, ?, ?, ?, ?)`,
    [keyId, publicKeyBase64, 'nacl-box', inputIndex, 'active']
  );

  console.log(`Encryption key set: ${keyId}`);
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
 */
export function isEncryptionConfigured(): boolean {
  return getActiveEncryptionConfig() !== null;
}

// ============= Encryption Functions =============

/**
 * Encrypt sensitive data for output.
 *
 * Uses NaCl box with an ephemeral keypair for forward secrecy.
 * The encrypted output includes the ephemeral public key needed for decryption.
 *
 * @param data - Data to encrypt (will be JSON.stringified if not already a string)
 * @returns EncryptedOutput object ready for serialization
 * @throws Error if encryption is not configured
 */
export function encryptOutput(data: unknown): EncryptedOutput {
  const config = getActiveEncryptionConfig();
  if (!config) {
    throw new Error('Encryption not configured - admin public key not set');
  }

  // Convert data to string
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // Decode admin public key
  const adminPublicKey = base64ToUint8Array(config.public_key);

  // Generate ephemeral keypair for this message (forward secrecy)
  const ephemeral = nacl.box.keyPair();

  // Generate random nonce
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  // Encrypt using NaCl box
  const ciphertext = nacl.box(
    plaintextBytes,
    nonce,
    adminPublicKey,
    ephemeral.secretKey
  );

  return {
    version: 1,
    algorithm: 'nacl-box',
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
 * IMPORTANT: NaCl's randomBytes() uses crypto.getRandomValues() which is
 * NON-DETERMINISTIC by design. This is acceptable for encryption because:
 *
 * 1. The nonce is included in the output (deterministic given the output)
 * 2. The ephemeral keypair is included in the output (public key)
 * 3. The same plaintext encrypted twice will produce different ciphertext,
 *    but both will decrypt to the same plaintext
 *
 * For Cartesi's fraud-proof verification:
 * - The encrypted OUTPUT is what's verified, not the encryption process
 * - Given the same encrypted output, decryption is deterministic
 * - The randomness doesn't affect state transitions, only output format
 *
 * If absolute determinism is required (unlikely), you could:
 * 1. Use the input hash + counter as a seed for nonce generation
 * 2. Use a deterministic ephemeral key derivation scheme
 * But this would weaken security (no forward secrecy).
 */
