/**
 * Device identity management for L{CORE}
 *
 * Provides DeviceIdentity class for generating and managing device credentials
 * with did:key support for direct device attestation.
 */

import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { base58btc } from 'multiformats/bases/base58'
import { randomBytes } from '@noble/hashes/utils'

// Multicodec prefix for secp256k1-pub: 0xe7 0x01
const SECP256K1_MULTICODEC = new Uint8Array([0xe7, 0x01])

/**
 * Convert a secp256k1 compressed public key to a did:key string.
 *
 * @param publicKey - 33-byte compressed secp256k1 public key
 * @returns did:key string (e.g., "did:key:zQ3sh...")
 */
export function publicKeyToDIDKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 33) {
    throw new Error(`Public key must be 33 bytes (compressed), got ${publicKey.length}`)
  }

  // Prepend multicodec prefix
  const multicodecKey = new Uint8Array(2 + publicKey.length)
  multicodecKey.set(SECP256K1_MULTICODEC, 0)
  multicodecKey.set(publicKey, 2)

  // Base58btc encode with 'z' multibase prefix
  const encoded = base58btc.encode(multicodecKey)

  return `did:key:${encoded}`
}

/**
 * Create a JWS compact serialization (ES256K algorithm).
 *
 * @param payload - Object to sign
 * @param privateKey - 32-byte secp256k1 private key
 * @returns JWS compact serialization string
 */
export function createJWS(payload: Record<string, unknown>, privateKey: Uint8Array): string {
  // JWS header for ES256K
  const header = { alg: 'ES256K', typ: 'JWS' }

  // Base64url encode header and payload
  const headerB64 = base64urlEncode(JSON.stringify(header))
  const payloadB64 = base64urlEncode(JSON.stringify(payload))

  // Create signing input
  const signingInput = `${headerB64}.${payloadB64}`

  // SHA256 hash of signing input
  const msgHash = sha256(new TextEncoder().encode(signingInput))

  // Sign with secp256k1
  const signature = secp256k1.sign(msgHash, privateKey)

  // Get raw r||s signature (64 bytes)
  const sigBytes = new Uint8Array(64)
  sigBytes.set(signature.r.toByteArray().slice(-32), 0)
  sigBytes.set(signature.s.toByteArray().slice(-32), 32)

  // Base64url encode signature
  const sigB64 = base64urlEncode(sigBytes)

  return `${headerB64}.${payloadB64}.${sigB64}`
}

/**
 * Base64url encode without padding
 */
function base64urlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Represents a device identity with did:key and signing capabilities.
 *
 * @example
 * ```typescript
 * // Generate new identity
 * const device = DeviceIdentity.generate()
 * console.log(device.did) // did:key:zQ3sh...
 *
 * // Sign sensor data
 * const signed = device.sign({ temperature: 23.4 })
 * ```
 */
export class DeviceIdentity {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
  readonly did: string

  /**
   * Create a DeviceIdentity from an existing private key.
   *
   * @param privateKey - 32-byte secp256k1 private key
   */
  constructor(privateKey: Uint8Array) {
    if (privateKey.length !== 32) {
      throw new Error(`Private key must be 32 bytes, got ${privateKey.length}`)
    }

    this.privateKey = privateKey
    this.publicKey = secp256k1.getPublicKey(privateKey, true) // compressed
    this.did = publicKeyToDIDKey(this.publicKey)
  }

  /**
   * Generate a new random device identity.
   *
   * @returns New DeviceIdentity with random secp256k1 keypair
   */
  static generate(): DeviceIdentity {
    const privateKey = randomBytes(32)
    return new DeviceIdentity(privateKey)
  }

  /**
   * Create a DeviceIdentity from a hex-encoded private key.
   *
   * @param hexKey - 64-character hex string (with or without 0x prefix)
   */
  static fromHex(hexKey: string): DeviceIdentity {
    if (hexKey.startsWith('0x')) {
      hexKey = hexKey.slice(2)
    }
    if (hexKey.length !== 64) {
      throw new Error(`Hex key must be 64 characters, got ${hexKey.length}`)
    }
    const privateKey = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      privateKey[i] = parseInt(hexKey.slice(i * 2, i * 2 + 2), 16)
    }
    return new DeviceIdentity(privateKey)
  }

  /**
   * Sign a payload and return submission-ready data.
   *
   * @param payload - Sensor data to sign
   * @returns Object with did, payload, signature, and timestamp
   */
  sign(payload: Record<string, unknown>): {
    did: string
    payload: Record<string, unknown>
    signature: string
    timestamp: number
  } {
    const signature = createJWS(payload, this.privateKey)
    const timestamp = Math.floor(Date.now() / 1000)

    return {
      did: this.did,
      payload,
      signature,
      timestamp,
    }
  }

  /**
   * Export private key as hex string.
   *
   * @returns 64-character hex string (without 0x prefix)
   */
  toHex(): string {
    return Array.from(this.privateKey)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }
}
