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

// Set env vars BEFORE importing the encryption module.
// generics.ts runs getOperatorPrivateKey() at import time.
const adminKeypair = nacl.box.keyPair()
const adminPrivateKeyBase64 = Buffer.from(adminKeypair.secretKey).toString('base64')
const adminPublicKeyBase64 = Buffer.from(adminKeypair.publicKey).toString('base64')

process.env.LCORE_PRIVATE_KEY = adminPrivateKeyBase64
process.env.LCORE_PUBLIC_KEY = adminPublicKeyBase64
// generics.ts requires PRIVATE_KEY or MNEMONIC at module load
process.env.PRIVATE_KEY = '0x' + Buffer.from(nacl.randomBytes(32)).toString('hex')

// Now import after env is set
const encryption = await import('../../attestor/src/lcore/encryption.ts')

// Initialize decryption and input encryption
encryption.initDecryption()
encryption.initInputEncryption()

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
		const submission = encryption.encryptDataForSubmission(originalData)

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
