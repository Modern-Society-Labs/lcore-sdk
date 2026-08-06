/**
 * Inspect Proxy Unit Tests
 *
 * Tests reEncryptForRequester(), validateNaClPublicKey(), and
 * the full decrypt → re-encrypt → decrypt round-trip.
 *
 * No server required — tests encryption helpers directly.
 *
 * Run:
 *   cd attestor && node --experimental-strip-types --test ../tests/attestor/inspect-proxy.test.ts
 */

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const require = createRequire(
	new URL('../../attestor/package.json', import.meta.url)
)
const nacl = require('tweetnacl') as typeof import('tweetnacl')
const { xchacha20poly1305 } = require('@noble/ciphers/chacha.js') as { xchacha20poly1305: typeof import('@noble/ciphers/chacha.js').xchacha20poly1305 }
const { secp256k1 } = require('@noble/curves/secp256k1') as typeof import('@noble/curves/secp256k1')
const { hkdf } = require('@noble/hashes/hkdf') as typeof import('@noble/hashes/hkdf')
const { sha256: sha256Hash } = require('@noble/hashes/sha256') as typeof import('@noble/hashes/sha256')

// Set env vars BEFORE importing the encryption module.
// generics.ts runs getOperatorPrivateKey() at import time.
const adminKeypair = nacl.box.keyPair()
const adminPrivateKeyBase64 = Buffer.from(adminKeypair.secretKey).toString('base64')
const adminPublicKeyBase64 = Buffer.from(adminKeypair.publicKey).toString('base64')

process.env.LCORE_PRIVATE_KEY = adminPrivateKeyBase64
process.env.LCORE_PUBLIC_KEY = adminPublicKeyBase64
// generics.ts requires PRIVATE_KEY or MNEMONIC at module load
process.env.PRIVATE_KEY = '0x' + Buffer.from(nacl.randomBytes(32)).toString('hex')

// V2 secp256k1 keypair for per-device ECDH tests
const v2PrivateKey = nacl.randomBytes(32)
const v2PublicKey = secp256k1.getPublicKey(v2PrivateKey, true)
process.env.LCORE_PRIVATE_KEY_V2 = Buffer.from(v2PrivateKey).toString('hex')

// Generate a test device secp256k1 keypair and DID
const devicePrivateKey = nacl.randomBytes(32)
const devicePublicKey = secp256k1.getPublicKey(devicePrivateKey, true)

function testPublicKeyToDIDKey(publicKey: Uint8Array): string {
	const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	const prefixed = new Uint8Array(2 + publicKey.length)
	prefixed[0] = 0xe7
	prefixed[1] = 0x01
	prefixed.set(publicKey, 2)

	let num = BigInt('0x' + Buffer.from(prefixed).toString('hex'))
	let encoded = ''
	while (num > 0) {
		encoded = BASE58_ALPHABET[Number(num % 58n)] + encoded
		num = num / 58n
	}
	for (let i = 0; i < prefixed.length && prefixed[i] === 0; i++) {
		encoded = '1' + encoded
	}
	return `did:key:z${encoded}`
}

const testDeviceDid = testPublicKeyToDIDKey(devicePublicKey)
const testTimestamp = 1700000000
// Per-submission salt folded into the signed data_hash (H-2). Fixed here so
// hashes are reproducible across runs; devices generate this randomly.
const testSalt = '00112233445566778899aabbccddeeff'

// Now import after env is set
const encryption = await import('../../attestor/src/lcore/encryption.ts')

// Initialize decryption and input encryption
encryption.initDecryption()
encryption.initInputEncryption()
encryption.initV2Encryption()

// ============= Helper =============

function createTestPackedBlob(data: unknown): string {
	const salt = nacl.randomBytes(16)
	const plaintext = JSON.stringify({
		data,
		salt: Buffer.from(salt).toString('base64'),
	})
	const plaintextBytes = new TextEncoder().encode(plaintext)

	const ephemeral = nacl.box.keyPair()
	const nonce = nacl.randomBytes(nacl.box.nonceLength)

	const ciphertext = nacl.box(
		plaintextBytes,
		nonce,
		adminKeypair.publicKey,
		ephemeral.secretKey
	)

	// Pack: nonce + ephemeralPubKey + ciphertext
	const blob = new Uint8Array(nonce.length + ephemeral.publicKey.length + ciphertext.length)
	blob.set(nonce, 0)
	blob.set(ephemeral.publicKey, nonce.length)
	blob.set(ciphertext, nonce.length + ephemeral.publicKey.length)

	return Buffer.from(blob).toString('base64')
}

function decryptPackedBlob(
	blob: string,
	recipientSecretKey: Uint8Array
): unknown {
	const bytes = Buffer.from(blob, 'base64')
	const nonce = new Uint8Array(bytes.subarray(0, 24))
	const ephPubKey = new Uint8Array(bytes.subarray(24, 56))
	const ciphertext = new Uint8Array(bytes.subarray(56))

	// Try XChaCha20-Poly1305 first (current cipher), fall back to NaCl box
	try {
		const sharedSecret = nacl.scalarMult(recipientSecretKey, ephPubKey)
		const decrypted = xchacha20poly1305(sharedSecret, nonce).decrypt(ciphertext)
		return JSON.parse(new TextDecoder().decode(decrypted))
	} catch {
		const decrypted = nacl.box.open(ciphertext, nonce, ephPubKey, recipientSecretKey)
		assert.ok(decrypted, 'Failed to decrypt packed blob')
		return JSON.parse(new TextDecoder().decode(decrypted))
	}
}

// ============= Tests =============

describe('validateNaClPublicKey', () => {
	it('should accept valid 32-byte base64 key', () => {
		const kp = nacl.box.keyPair()
		const key = Buffer.from(kp.publicKey).toString('base64')
		assert.equal(encryption.validateNaClPublicKey(key), true)
	})

	it('should reject too-short key', () => {
		const short = Buffer.from(nacl.randomBytes(16)).toString('base64')
		assert.equal(encryption.validateNaClPublicKey(short), false)
	})

	it('should reject too-long key', () => {
		const long = Buffer.from(nacl.randomBytes(64)).toString('base64')
		assert.equal(encryption.validateNaClPublicKey(long), false)
	})

	it('should reject invalid base64', () => {
		assert.equal(encryption.validateNaClPublicKey('!!!not-base64!!!'), false)
	})

	it('should reject empty string', () => {
		assert.equal(encryption.validateNaClPublicKey(''), false)
	})
})

describe('reEncryptForRequester', () => {
	it('should decrypt and re-encrypt for requester key', () => {
		const testData = { temperature: 23.4, humidity: 65 }
		const encryptedBlob = createTestPackedBlob(testData)

		// Requester keypair
		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		const result = encryption.reEncryptForRequester(encryptedBlob, requesterPubKey)
		assert.equal(result.success, true)
		assert.ok('encrypted_data' in result && result.encrypted_data)

		// Requester should be able to decrypt with their private key
		const decrypted = decryptPackedBlob(
			(result as { encrypted_data: string }).encrypted_data,
			requester.secretKey
		)

		// The decrypted content is { data: <original>, salt: <base64> }
		assert.ok(typeof decrypted === 'object' && decrypted !== null)
		const inner = decrypted as { data: unknown; salt: string }
		assert.deepStrictEqual(inner.data, testData)
		assert.ok(inner.salt) // salt should be present
	})

	it('should produce different ciphertext each time (ephemeral keys)', () => {
		const testData = { value: 42 }
		const encryptedBlob = createTestPackedBlob(testData)

		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		const result1 = encryption.reEncryptForRequester(encryptedBlob, requesterPubKey)
		const result2 = encryption.reEncryptForRequester(encryptedBlob, requesterPubKey)

		assert.equal(result1.success, true)
		assert.equal(result2.success, true)

		// Different ephemeral keys → different ciphertext
		assert.notEqual(
			(result1 as { encrypted_data: string }).encrypted_data,
			(result2 as { encrypted_data: string }).encrypted_data
		)
	})

	it('should fail with invalid encrypted blob', () => {
		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		const result = encryption.reEncryptForRequester('bm90LWEtdmFsaWQtYmxvYg==', requesterPubKey)
		assert.equal(result.success, false)
		assert.ok('error' in result)
	})

	it('should fail with invalid requester public key', () => {
		const testData = { value: 1 }
		const encryptedBlob = createTestPackedBlob(testData)

		const result = encryption.reEncryptForRequester(
			encryptedBlob,
			Buffer.from(nacl.randomBytes(16)).toString('base64') // wrong length
		)
		assert.equal(result.success, false)
		assert.ok('error' in result)
	})

	it('admin should NOT be able to decrypt re-encrypted blob', () => {
		const testData = { secret: 'only-for-requester' }
		const encryptedBlob = createTestPackedBlob(testData)

		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		const result = encryption.reEncryptForRequester(encryptedBlob, requesterPubKey)
		assert.equal(result.success, true)

		// Try decrypting with admin key — should fail
		const reEncrypted = (result as { encrypted_data: string }).encrypted_data
		const bytes = Buffer.from(reEncrypted, 'base64')
		const nonce = new Uint8Array(bytes.subarray(0, 24))
		const ephPubKey = new Uint8Array(bytes.subarray(24, 56))
		const ciphertext = new Uint8Array(bytes.subarray(56))

		let adminDecryptFailed = false
		try {
			const sharedSecret = nacl.scalarMult(adminKeypair.secretKey, ephPubKey)
			xchacha20poly1305(sharedSecret, nonce).decrypt(ciphertext)
		} catch {
			adminDecryptFailed = true
		}

		assert.ok(adminDecryptFailed, 'Admin should not be able to decrypt re-encrypted blob')
	})
})

describe('encryptDataForSubmission → reEncryptForRequester round-trip', () => {
	it('should round-trip through the full V1 pipeline', () => {
		// Step 1: Encrypt with encryptDataForSubmission (what the attestor does on write)
		const originalData = { sensor_id: 'test-001', temperature: 22.5, humidity: 60 }
		const submission = encryption.encryptDataForSubmission(originalData, testDeviceDid, testTimestamp, testSalt)

		assert.ok(submission.data_hash)
		assert.ok(submission.encrypted_data)
		assert.equal(submission.encryption_key_id, 'lcore_key_v1')

		// Step 2: Re-encrypt for a requester (what inspect proxy does on read)
		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		const reEncrypted = encryption.reEncryptForRequester(
			submission.encrypted_data,
			requesterPubKey
		)
		assert.equal(reEncrypted.success, true)

		// Step 3: Requester decrypts with their private key
		const decrypted = decryptPackedBlob(
			(reEncrypted as { encrypted_data: string }).encrypted_data,
			requester.secretKey
		)

		const inner = decrypted as { data: { data: unknown; salt: string }; salt: string }
		// The re-encrypted blob wraps { data: { data: originalData, salt: <inner_salt> }, salt: <outer_salt> }
		// Actually, reEncryptForRequester decrypts the submission which gives { data, salt },
		// then re-encrypts that whole object. So the requester gets { data, salt }.
		assert.deepStrictEqual(inner.data, originalData)
		assert.ok(inner.salt)
	})
})

describe('getAdminPublicKey', () => {
	it('should return the admin public key', () => {
		const pubKey = encryption.getAdminPublicKey()
		assert.ok(pubKey)
		assert.equal(pubKey, adminPublicKeyBase64)
	})
})

describe('isDecryptionConfigured', () => {
	it('should return true after initDecryption', () => {
		assert.equal(encryption.isDecryptionConfigured(), true)
	})
})

// ============= V2 Per-Device ECDH Tests =============

describe('V2 per-device ECDH encryption', () => {
	it('isV2Configured should return true after initV2Encryption', () => {
		assert.equal(encryption.isV2Configured(), true)
	})

	it('getV2PublicKey should return hex-encoded compressed secp256k1 key', () => {
		const pubKey = encryption.getV2PublicKey()
		assert.ok(pubKey)
		assert.equal(pubKey!.length, 66) // 33 bytes * 2 hex chars
		assert.ok(pubKey!.startsWith('02') || pubKey!.startsWith('03')) // compressed prefix
	})

	it('should encrypt and decrypt V2 data round-trip', () => {
		const data = { temperature: 23.4, humidity: 65 }
		const submission = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)

		assert.ok(submission.data_hash)
		assert.ok(submission.encrypted_data)
		assert.equal(submission.encryption_key_id, 'lcore_key_v2')

		// V2 blob is shorter than V1 (no 32-byte ephemeral pubkey)
		const v1Submission = encryption.encryptDataForSubmission(data, testDeviceDid, testTimestamp, testSalt)
		const v2BlobLen = Buffer.from(submission.encrypted_data, 'base64').length
		const v1BlobLen = Buffer.from(v1Submission.encrypted_data, 'base64').length
		assert.ok(v2BlobLen < v1BlobLen, `V2 blob (${v2BlobLen}) should be smaller than V1 (${v1BlobLen})`)

		// Decrypt
		const decrypted = encryption.decryptDataSubmissionV2(submission.encrypted_data, testDeviceDid)
		assert.equal(decrypted.success, true)
		assert.ok('data' in decrypted && decrypted.data)

		const inner = (decrypted as { data: { data: unknown; salt: string } }).data
		assert.deepStrictEqual(inner.data, data)
		assert.ok(inner.salt)
	})

	it('should produce different ciphertext for same data (random nonce)', () => {
		const data = { value: 42 }
		const enc1 = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)
		const enc2 = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)

		assert.notEqual(enc1.encrypted_data, enc2.encrypted_data)
		// Hash is now deterministic (no salt) — same inputs yield the same hash
		assert.equal(enc1.data_hash, enc2.data_hash)
	})

	it('should fail to decrypt V2 blob with wrong device DID', () => {
		const data = { secret: 'device-specific' }
		const submission = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)

		// Generate a different device DID
		const otherKey = nacl.randomBytes(32)
		const otherPubKey = secp256k1.getPublicKey(otherKey, true)
		const otherDid = testPublicKeyToDIDKey(otherPubKey)

		// Try to decrypt with wrong device DID — should fail
		const result = encryption.decryptDataSubmissionV2(submission.encrypted_data, otherDid)
		assert.equal(result.success, false)
	})

	it('V1 blob should NOT be decryptable as V2 (and vice versa)', () => {
		const data = { cross: 'version' }

		// V1 encrypt
		const v1 = encryption.encryptDataForSubmission(data, testDeviceDid, testTimestamp, testSalt)
		const v1AsV2 = encryption.decryptDataSubmissionV2(v1.encrypted_data, testDeviceDid)
		assert.equal(v1AsV2.success, false)

		// V2 encrypt — try V1 decrypt
		const v2 = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)
		const v2AsV1 = encryption.decryptDataSubmission(v2.encrypted_data)
		assert.equal(v2AsV1.success, false)
	})

	it('data_hash should verify against decrypted data + deviceDid + timestamp', () => {
		const data = { sensor: 'test', reading: 99 }
		const submission = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)

		// Decrypt to confirm round-trip
		const decrypted = encryption.decryptDataSubmissionV2(submission.encrypted_data, testDeviceDid)
		assert.equal(decrypted.success, true)
		const inner = (decrypted as { data: { data: unknown } }).data

		// Recompute hash using deterministic inputs (no salt)
		const recomputedHash = encryption.computeDataHash(inner.data, testDeviceDid, testTimestamp, testSalt)
		assert.equal(recomputedHash, submission.data_hash)
	})
})

describe('reEncryptForRequester with V2', () => {
	it('should re-encrypt V2 blob for requester', () => {
		const data = { temperature: 25.0 }
		const submission = encryption.encryptDataForSubmissionV2(data, testDeviceDid, testTimestamp, testSalt)

		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		const result = encryption.reEncryptForRequester(
			submission.encrypted_data,
			requesterPubKey,
			'lcore_key_v2',
			testDeviceDid
		)
		assert.equal(result.success, true)
		assert.ok('encrypted_data' in result)

		// Requester decrypts
		const decrypted = decryptPackedBlob(
			(result as { encrypted_data: string }).encrypted_data,
			requester.secretKey
		)

		const inner = decrypted as { data: unknown; salt: string }
		assert.deepStrictEqual(inner.data, data)
		assert.ok(inner.salt)
	})

	it('should still re-encrypt V1 blobs without device_did', () => {
		const data = { legacy: true }
		const submission = encryption.encryptDataForSubmission(data, testDeviceDid, testTimestamp, testSalt)

		const requester = nacl.box.keyPair()
		const requesterPubKey = Buffer.from(requester.publicKey).toString('base64')

		// No encryption_key_id or device_did — should use V1 path
		const result = encryption.reEncryptForRequester(
			submission.encrypted_data,
			requesterPubKey
		)
		assert.equal(result.success, true)

		const decrypted = decryptPackedBlob(
			(result as { encrypted_data: string }).encrypted_data,
			requester.secretKey
		)

		const inner = decrypted as { data: unknown; salt: string }
		assert.deepStrictEqual(inner.data, data)
	})
})
