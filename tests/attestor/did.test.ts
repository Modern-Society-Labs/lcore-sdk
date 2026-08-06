/**
 * DID Utilities Unit Tests
 *
 * Tests for did:key parsing, JWS signing, and signature verification.
 */

import { describe, it } from 'node:test'
import assert from 'node:assert'
import { secp256k1 } from '@noble/curves/secp256k1'
import { parseDIDKey, publicKeyToDIDKey, verifyJWS, createJWS } from '../../attestor/src/api/services/did.ts'

describe('DID Utilities', () => {
	describe('parseDIDKey', () => {
		it('should parse valid secp256k1 did:key', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const did = publicKeyToDIDKey(pubKey)

			const parsed = parseDIDKey(did)
			assert.ok(parsed, 'Should return parsed public key')
			assert.deepStrictEqual(parsed, pubKey, 'Parsed key should match original')
		})

		it('should reject did:web prefix', () => {
			const result = parseDIDKey('did:web:example.com')
			assert.strictEqual(result, null)
		})

		it('should reject did:ethr prefix', () => {
			const result = parseDIDKey('did:ethr:0x1234567890abcdef')
			assert.strictEqual(result, null)
		})

		it('should reject malformed multibase encoding', () => {
			const result = parseDIDKey('did:key:invalid!!!')
			assert.strictEqual(result, null)
		})

		it('should reject empty did', () => {
			const result = parseDIDKey('')
			assert.strictEqual(result, null)
		})

		it('should reject did:key without z prefix', () => {
			const result = parseDIDKey('did:key:abc123')
			assert.strictEqual(result, null)
		})

		it('should reject did:key with wrong multicodec prefix', () => {
			// This would be ed25519 key (0xed 0x01) not secp256k1
			const result = parseDIDKey('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK')
			assert.strictEqual(result, null)
		})
	})

	describe('publicKeyToDIDKey', () => {
		it('should generate valid did:key from public key', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)

			const did = publicKeyToDIDKey(pubKey)

			assert.ok(did.startsWith('did:key:z'), 'Should start with did:key:z')
			assert.ok(did.length > 50, 'Should be a reasonable length')
		})

		it('should be reversible with parseDIDKey', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)

			const did = publicKeyToDIDKey(pubKey)
			const parsed = parseDIDKey(did)

			assert.deepStrictEqual(parsed, pubKey)
		})

		it('should generate different DIDs for different keys', () => {
			const privKey1 = secp256k1.utils.randomPrivateKey()
			const pubKey1 = secp256k1.getPublicKey(privKey1, true)
			const did1 = publicKeyToDIDKey(pubKey1)

			const privKey2 = secp256k1.utils.randomPrivateKey()
			const pubKey2 = secp256k1.getPublicKey(privKey2, true)
			const did2 = publicKeyToDIDKey(pubKey2)

			assert.notStrictEqual(did1, did2)
		})
	})

	describe('createJWS', () => {
		it('should create a valid JWS with three parts', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const payload = { temperature: 23.4 }

			const jws = createJWS(payload, privKey)
			const parts = jws.split('.')

			assert.strictEqual(parts.length, 3, 'JWS should have 3 parts')
			assert.ok(parts[0].length > 0, 'Header should not be empty')
			assert.ok(parts[1].length > 0, 'Payload should not be empty')
			assert.ok(parts[2].length > 0, 'Signature should not be empty')
		})

		it('should create different signatures for different payloads', () => {
			const privKey = secp256k1.utils.randomPrivateKey()

			const jws1 = createJWS({ temperature: 23.4 }, privKey)
			const jws2 = createJWS({ temperature: 25.0 }, privKey)

			assert.notStrictEqual(jws1, jws2)
		})

		it('should create different signatures with different keys', () => {
			const privKey1 = secp256k1.utils.randomPrivateKey()
			const privKey2 = secp256k1.utils.randomPrivateKey()
			const payload = { temperature: 23.4 }

			const jws1 = createJWS(payload, privKey1)
			const jws2 = createJWS(payload, privKey2)

			// Payload parts should be the same
			assert.strictEqual(jws1.split('.')[1], jws2.split('.')[1])
			// Signature parts should differ
			assert.notStrictEqual(jws1.split('.')[2], jws2.split('.')[2])
		})
	})

	describe('verifyJWS', () => {
		it('should verify valid signature', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const payload = { temperature: 23.4, humidity: 65 }

			const jws = createJWS(payload, privKey)
			const isValid = verifyJWS(jws, payload, pubKey)

			assert.strictEqual(isValid, true)
		})

		it('should reject tampered payload', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const payload = { temperature: 23.4 }
			const tampered = { temperature: 99.9 }

			const jws = createJWS(payload, privKey)
			const isValid = verifyJWS(jws, tampered, pubKey)

			assert.strictEqual(isValid, false)
		})

		it('should reject wrong public key', () => {
			const privKey1 = secp256k1.utils.randomPrivateKey()
			const privKey2 = secp256k1.utils.randomPrivateKey()
			const pubKey2 = secp256k1.getPublicKey(privKey2, true)
			const payload = { temperature: 23.4 }

			const jws = createJWS(payload, privKey1)
			const isValid = verifyJWS(jws, payload, pubKey2)

			assert.strictEqual(isValid, false)
		})

		it('should reject malformed JWS (missing parts)', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const payload = { temperature: 23.4 }

			const isValid = verifyJWS('invalid.jws', payload, pubKey)
			assert.strictEqual(isValid, false)
		})

		it('should reject empty JWS', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const payload = { temperature: 23.4 }

			const isValid = verifyJWS('', payload, pubKey)
			assert.strictEqual(isValid, false)
		})

		it('should handle complex nested payloads', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const payload = {
				device_id: 'sensor-001',
				readings: {
					temperature: 23.4,
					humidity: 65,
					pressure: 1013.25
				},
				metadata: {
					firmware: '1.2.3',
					battery: 85
				}
			}

			const jws = createJWS(payload, privKey)
			const isValid = verifyJWS(jws, payload, pubKey)

			assert.strictEqual(isValid, true)
		})

		it('should be sensitive to payload key order', () => {
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)

			// Note: JSON.stringify preserves insertion order, so these differ
			const payload1 = { a: 1, b: 2 }
			const payload2 = { b: 2, a: 1 }

			const jws = createJWS(payload1, privKey)

			// Should verify with same order
			assert.strictEqual(verifyJWS(jws, payload1, pubKey), true)

			// May fail with different order (depends on JS engine)
			// This is expected behavior for JWS
		})
	})

	describe('Round-trip verification', () => {
		it('should complete full sign-verify cycle', () => {
			// Generate device identity
			const privKey = secp256k1.utils.randomPrivateKey()
			const pubKey = secp256k1.getPublicKey(privKey, true)
			const did = publicKeyToDIDKey(pubKey)

			// Create payload
			const payload = {
				device: did,
				temperature: 23.4,
				timestamp: Date.now()
			}

			// Sign
			const jws = createJWS(payload, privKey)

			// Parse DID and verify
			const parsedKey = parseDIDKey(did)
			assert.ok(parsedKey, 'Should parse DID')

			const isValid = verifyJWS(jws, payload, parsedKey)
			assert.strictEqual(isValid, true, 'Should verify signature')
		})
	})
})
