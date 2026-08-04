/**
 * H-2 regression tests: the device data_hash is salted so low-entropy sensor
 * data cannot be brute-forced from the on-chain hash, and the attestor verifies
 * the device JWS over that salted hash.
 *
 * Run: npm run test:h2   (from packages/.../attestor)
 *
 * Self-contained: sets a throwaway MNEMONIC (only needed so the encryption
 * module loads) and uses dynamic import so no external setup is required.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { secp256k1 } from '@noble/curves/secp256k1'
import { bytesToHex, randomBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'

process.env.MNEMONIC ??= 'test test test test test test test test test test test junk'
process.env.LCORE_ENABLED ??= '0'

// Real attestor code under test
const { computeDataHash } = await import('#src/lcore/encryption.ts')
const { parseDIDKey, verifyJWSOverHash, createJWSOverHash } = await import('#src/api/services/did.ts')
const { handleApiRequest } = await import('#src/api/routes/index.ts')

function didOf(pk: Uint8Array): string {
	const mc = new Uint8Array(2 + pk.length)
	mc[0] = 0xe7; mc[1] = 0x01; mc.set(pk, 2)
	return 'did:key:' + base58btc.encode(mc)
}

function newDevice() {
	const priv = secp256k1.utils.randomPrivateKey()
	const did = didOf(secp256k1.getPublicKey(priv, true))
	return { priv, did }
}

const payload = { humidity: 65, location: 'office-1', temperature: 23.4 }
const ts = 1730000000

test('valid salted submission verifies against the attestor', () => {
	const { priv, did } = newDevice()
	const salt = bytesToHex(randomBytes(16))
	const jws = createJWSOverHash(computeDataHash(payload, did, ts, salt), priv)
	assert.equal(verifyJWSOverHash(jws, computeDataHash(payload, did, ts, salt), parseDIDKey(did)!), true)
})

test('wrong salt is rejected (attacker without the salt cannot match)', () => {
	const { priv, did } = newDevice()
	const salt = bytesToHex(randomBytes(16))
	const jws = createJWSOverHash(computeDataHash(payload, did, ts, salt), priv)
	const wrong = bytesToHex(randomBytes(16))
	assert.equal(verifyJWSOverHash(jws, computeDataHash(payload, did, ts, wrong), parseDIDKey(did)!), false)
})

test('tampered payload or timestamp is rejected', () => {
	const { priv, did } = newDevice()
	const salt = bytesToHex(randomBytes(16))
	const jws = createJWSOverHash(computeDataHash(payload, did, ts, salt), priv)
	const pk = parseDIDKey(did)!
	assert.equal(verifyJWSOverHash(jws, computeDataHash({ ...payload, temperature: 99 }, did, ts, salt), pk), false)
	assert.equal(verifyJWSOverHash(jws, computeDataHash(payload, did, ts + 1, salt), pk), false)
})

test('salt is bound into the hash (salted != unsalted)', () => {
	const { did } = newDevice()
	const salt = bytesToHex(randomBytes(16))
	assert.notEqual(computeDataHash(payload, did, ts, salt), computeDataHash(payload, did, ts, ''))
})

test('low-entropy payload is NOT recoverable from the hash without the salt', () => {
	const { did } = newDevice()
	const salt = bytesToHex(randomBytes(16))
	const observed = computeDataHash(payload, did, ts, salt) // what an observer sees on-chain
	let recovered = false
	for (let t = 150; t <= 350; t++) { // brute-force 15.0..35.0
		const guess = { humidity: 65, location: 'office-1', temperature: t / 10 }
		if (computeDataHash(guess, did, ts, '') === observed) { recovered = true; break }
	}
	assert.equal(recovered, false, 'salted hash must not be brute-forceable without the salt')
})

test('/api/device/submit enforces the salt and verifies the signature', async () => {
	const { priv, did } = newDevice()
	const now = Math.floor(Date.now() / 1000)
	const salt = bytesToHex(randomBytes(16))
	const jws = createJWSOverHash(computeDataHash(payload, did, now, salt), priv)

	const server = http.createServer(async (req, res) => {
		if (!(await handleApiRequest(req, res))) { res.writeHead(404); res.end('{}') }
	})
	await new Promise<void>(r => server.listen(0, r))
	const port = (server.address() as { port: number }).port
	const post = async (body: unknown) => {
		const r = await fetch(`http://127.0.0.1:${port}/api/device/submit`, {
			method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
		})
		return r.status
	}
	try {
		// Valid submission passes verification (only fails later at the disabled submit step)
		assert.notEqual(await post({ did, payload, signature: jws, timestamp: now, salt }), 400)
		assert.notEqual(await post({ did, payload, signature: jws, timestamp: now, salt }), 401)
		// Missing / malformed salt -> 400
		assert.equal(await post({ did, payload, signature: jws, timestamp: now }), 400)
		assert.equal(await post({ did, payload, signature: jws, timestamp: now, salt: 'nothex' }), 400)
		// Wrong salt / tampered payload -> 401
		assert.equal(await post({ did, payload, signature: jws, timestamp: now, salt: bytesToHex(randomBytes(16)) }), 401)
		assert.equal(await post({ did, payload: { humidity: 1 }, signature: jws, timestamp: now, salt }), 401)
	} finally {
		await new Promise<void>(r => server.close(() => r()))
	}
})
