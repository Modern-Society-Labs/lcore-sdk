/**
 * Device Endpoint Tests — POST /api/device/submit
 *
 * Drives the REAL attestor router in-process (no external server required), so
 * this runs in CI. Submissions use the salted-hash protocol: the device signs
 * data_hash = sha256(JCS(payload) + did + timestamp + salt) and sends the salt
 * alongside, so the attestor can recompute the hash. See LICENSING/H-2 notes.
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert'
import http from 'node:http'
import { secp256k1 } from '@noble/curves/secp256k1'
import { bytesToHex, randomBytes } from '@noble/hashes/utils'
import { createJWSOverHash, publicKeyToDIDKey } from '../../attestor/src/api/services/did.ts'

process.env.MNEMONIC ??= 'test test test test test test test test test test test junk'
process.env.LCORE_ENABLED ??= '0'

const { handleApiRequest } = await import('../../attestor/src/api/routes/index.ts')
const { computeDataHash } = await import('../../attestor/src/lcore/encryption.ts')

/** Fixed salt for reproducible hashes; real devices generate this randomly. */
const TEST_SALT = '00112233445566778899aabbccddeeff'

let server: http.Server
let BASE_URL = ''

before(async () => {
	server = http.createServer(async (req, res) => {
		if (!(await handleApiRequest(req, res))) { res.writeHead(404); res.end('{}') }
	})
	await new Promise<void>(r => server.listen(0, r))
	BASE_URL = `http://127.0.0.1:${(server.address() as { port: number }).port}`
})

after(async () => {
	await new Promise<void>(r => server.close(() => r()))
})

/** Sign a submission the way a conforming device does. */
function signSubmission(
	device: { privKey: Uint8Array; did: string },
	payload: Record<string, unknown>,
	timestamp: number,
	salt: string = TEST_SALT
) {
	const hash = computeDataHash(payload, device.did, timestamp, salt)
	return createJWSOverHash(hash, device.privKey)
}

interface TestResponse {
	status: number
	body: Record<string, unknown>
}

function generateDeviceIdentity() {
	const privKey = secp256k1.utils.randomPrivateKey()
	const pubKey = secp256k1.getPublicKey(privKey, true)
	const did = publicKeyToDIDKey(pubKey)
	return { privKey, pubKey, did }
}

async function submitDeviceData(body: unknown): Promise<TestResponse> {
	return new Promise((resolve, reject) => {
		const url = new URL('/api/device/submit', BASE_URL)
		const req = http.request(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' }
		}, res => {
			let data = ''
			res.on('data', chunk => data += chunk)
			res.on('end', () => {
				try {
					resolve({
						status: res.statusCode!,
						body: JSON.parse(data)
					})
				} catch {
					resolve({
						status: res.statusCode!,
						body: { raw: data }
					})
				}
			})
		})
		req.on('error', reject)
		req.write(JSON.stringify(body))
		req.end()
	})
}

describe('POST /api/device/submit', () => {
	describe('Valid submissions', () => {
		it('should accept valid signed device data (may fail at Cartesi step)', async () => {
			const device = generateDeviceIdentity()
			const payload = { temperature: 23.4, humidity: 65 }
			const timestamp = Math.floor(Date.now() / 1000)
			const signature = signSubmission(device, payload, timestamp)

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				timestamp,
				salt: TEST_SALT
			})

			// Signature verification should pass
			// 500 means we reached Cartesi submission (which may fail if node not available)
			// 201 means full success
			assert.ok(
				status === 500 || status === 201,
				`Expected 500 or 201, got ${status}: ${JSON.stringify(body)}`
			)
		})

		it('should pass signature verification before Cartesi check', async () => {
			const device = generateDeviceIdentity()
			const payload = { sensor_id: 'test-001', value: 42 }
			const timestamp = Math.floor(Date.now() / 1000)
			const signature = signSubmission(device, payload, timestamp)

			const { status } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				timestamp,
				salt: TEST_SALT
			})

			// 500 or 201 means we passed validation
			// 400/401 would mean validation failed
			assert.ok(status === 500 || status === 201, `Expected 500 or 201, got ${status}`)
		})
	})

	describe('Missing required fields', () => {
		it('should reject missing did', async () => {
			const { status, body } = await submitDeviceData({
				payload: { temperature: 23.4 },
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('did'))
		})

		it('should reject missing payload', async () => {
			const device = generateDeviceIdentity()
			const { status, body } = await submitDeviceData({
				did: device.did,
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('payload'))
		})

		it('should reject missing signature', async () => {
			const device = generateDeviceIdentity()
			const { status, body } = await submitDeviceData({
				did: device.did,
				payload: { temperature: 23.4 },
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('signature'))
		})

		it('should reject missing timestamp', async () => {
			const device = generateDeviceIdentity()
			const payload = { temperature: 23.4 }
			const signature = signSubmission(device, payload, Math.floor(Date.now() / 1000))

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('timestamp'))
		})
	})

	describe('Invalid DID format', () => {
		it('should reject did:web format', async () => {
			const { status, body } = await submitDeviceData({
				did: 'did:web:example.com',
				payload: { temperature: 23.4 },
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('did:key'))
		})

		it('should reject did:ethr format', async () => {
			const { status, body } = await submitDeviceData({
				did: 'did:ethr:0x1234567890abcdef1234567890abcdef12345678',
				payload: { temperature: 23.4 },
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('did:key'))
		})

		it('should reject malformed did:key', async () => {
			const { status, body } = await submitDeviceData({
				did: 'did:key:invalid!!!',
				payload: { temperature: 23.4 },
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('did:key'))
		})

		it('should reject ed25519 did:key (wrong multicodec)', async () => {
			// This is a valid ed25519 did:key, but we only support secp256k1
			const { status, body } = await submitDeviceData({
				did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
				payload: { temperature: 23.4 },
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('did:key'))
		})
	})

	describe('Signature verification', () => {
		it('should reject signature from different device', async () => {
			const device1 = generateDeviceIdentity()
			const device2 = generateDeviceIdentity()
			const payload = { temperature: 23.4 }
			// Hash is for device1's DID, but signed with device2's key
			const timestamp = Math.floor(Date.now() / 1000)
			const signature = createJWSOverHash(
				computeDataHash(payload, device1.did, timestamp, TEST_SALT),
				device2.privKey
			)

			const { status, body } = await submitDeviceData({
				did: device1.did,
				payload,
				signature,
				timestamp,
				salt: TEST_SALT
			})

			assert.strictEqual(status, 401)
			assert.ok(body.error && String(body.error).toLowerCase().includes('signature'))
		})

		it('should reject tampered payload', async () => {
			const device = generateDeviceIdentity()
			const originalPayload = { temperature: 23.4 }
			const timestamp = Math.floor(Date.now() / 1000)
			const signature = signSubmission(device, originalPayload, timestamp)
			const tamperedPayload = { temperature: 99.9 }

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload: tamperedPayload,
				signature,
				timestamp,
				salt: TEST_SALT
			})

			assert.strictEqual(status, 401)
			assert.ok(body.error && String(body.error).toLowerCase().includes('signature'))
		})

		it('should reject completely invalid signature string', async () => {
			const device = generateDeviceIdentity()

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload: { temperature: 23.4 },
				signature: 'not-a-valid-jws',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 401)
			assert.ok(body.error && String(body.error).toLowerCase().includes('signature'))
		})
	})

	describe('Timestamp validation', () => {
		it('should reject timestamp more than 5 minutes old', async () => {
			const device = generateDeviceIdentity()
			const payload = { temperature: 23.4 }
			const oldTimestamp = Math.floor(Date.now() / 1000) - 600 // 10 minutes ago
			const signature = signSubmission(device, payload, oldTimestamp)

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				timestamp: oldTimestamp,
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('timestamp'))
		})

		it('should reject timestamp more than 5 minutes in the future', async () => {
			const device = generateDeviceIdentity()
			const payload = { temperature: 23.4 }
			const futureTimestamp = Math.floor(Date.now() / 1000) + 600 // 10 minutes from now
			const signature = signSubmission(device, payload, futureTimestamp)

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				timestamp: futureTimestamp,
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('timestamp'))
		})

		it('should accept timestamp within valid window', async () => {
			const device = generateDeviceIdentity()
			const payload = { temperature: 23.4 }
			// 2 minutes ago - within the 5 minute window
			const recentTimestamp = Math.floor(Date.now() / 1000) - 120
			const signature = signSubmission(device, payload, recentTimestamp)

			const { status } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				timestamp: recentTimestamp,
				salt: TEST_SALT
			})

			// 500 or 201 means validation passed
			assert.ok(status === 500 || status === 201, `Expected 500 or 201, got ${status}`)
		})

		it('should reject non-numeric timestamp', async () => {
			const device = generateDeviceIdentity()
			const payload = { temperature: 23.4 }
			const signature = signSubmission(device, payload, Math.floor(Date.now() / 1000))

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload,
				signature,
				timestamp: 'not-a-number',
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('timestamp'))
		})
	})

	describe('Payload validation', () => {
		it('should reject non-object payload (string)', async () => {
			const device = generateDeviceIdentity()

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload: 'not-an-object',
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('payload'))
		})

		it('should reject non-object payload (array)', async () => {
			const device = generateDeviceIdentity()

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload: [1, 2, 3],
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('payload'))
		})

		it('should reject null payload', async () => {
			const device = generateDeviceIdentity()

			const { status, body } = await submitDeviceData({
				did: device.did,
				payload: null,
				signature: 'dummy',
				timestamp: Math.floor(Date.now() / 1000),
				salt: TEST_SALT
			})

			assert.strictEqual(status, 400)
			assert.ok(body.error && String(body.error).toLowerCase().includes('payload'))
		})
	})

	describe('Request body validation', () => {
		it('should reject invalid JSON', async () => {
			const url = new URL('/api/device/submit', BASE_URL)
			const response = await new Promise<TestResponse>((resolve, reject) => {
				const req = http.request(url, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' }
				}, res => {
					let data = ''
					res.on('data', chunk => data += chunk)
					res.on('end', () => {
						try {
							resolve({ status: res.statusCode!, body: JSON.parse(data) })
						} catch {
							resolve({ status: res.statusCode!, body: { raw: data } })
						}
					})
				})
				req.on('error', reject)
				req.write('{ invalid json }')
				req.end()
			})

			assert.strictEqual(response.status, 400)
		})

		it('should reject empty body', async () => {
			const url = new URL('/api/device/submit', BASE_URL)
			const response = await new Promise<TestResponse>((resolve, reject) => {
				const req = http.request(url, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' }
				}, res => {
					let data = ''
					res.on('data', chunk => data += chunk)
					res.on('end', () => {
						try {
							resolve({ status: res.statusCode!, body: JSON.parse(data) })
						} catch {
							resolve({ status: res.statusCode!, body: { raw: data } })
						}
					})
				})
				req.on('error', reject)
				req.end()
			})

			assert.strictEqual(response.status, 400)
		})
	})
})
