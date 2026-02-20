/**
 * Post-cleanup smoke tests
 *
 * Validates that the attestor HTTP API is functional after removing
 * the EigenLayer AVS infrastructure (mechain, indexer, operator routes,
 * stats, subgraph sync, governance/task ABIs).
 *
 * Requirements:
 *   - Attestor server running on ATTESTOR_URL (default: http://localhost:8001)
 *   - No Supabase or blockchain connection needed
 *
 * Run:
 *   node --experimental-strip-types --test tests/attestor/smoke.test.ts
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

const BASE_URL = process.env.ATTESTOR_URL || 'http://localhost:8001'

async function request(
	path: string,
	opts: { method?: string; body?: unknown; headers?: Record<string, string> } = {}
) {
	const res = await fetch(`${BASE_URL}${path}`, {
		method: opts.method || 'GET',
		headers: {
			'Content-Type': 'application/json',
			...opts.headers,
		},
		body: opts.body ? JSON.stringify(opts.body) : undefined,
	})
	const text = await res.text()
	let json: any = null
	try {
		json = JSON.parse(text)
	} catch {}
	return { status: res.status, json, text }
}

describe('Server health', () => {
	it('GET /api/health returns 200 with status ok', async () => {
		const { status, json } = await request('/api/health')
		assert.equal(status, 200)
		assert.equal(json.status, 'ok')
		assert.ok(json.timestamp)
		assert.ok(json.version)
	})
})

describe('Active routes respond correctly', () => {
	it('POST /api/auth/nonce gracefully handles no-database', async () => {
		const { status, json } = await request('/api/auth/nonce', {
			method: 'POST',
			body: { walletAddress: '0x1234567890123456789012345678901234567890' },
		})
		// 400 = database not configured (graceful), not 500 crash
		assert.equal(status, 400)
		assert.ok(json.error)
	})

	it('GET /api/lcore/status returns disabled when LCORE_ENABLED=0', async () => {
		const { status, json } = await request('/api/lcore/status')
		assert.equal(status, 200)
		assert.equal(json.enabled, false)
	})

	it('POST /api/device/submit validates required fields', async () => {
		const { status, json } = await request('/api/device/submit', {
			method: 'POST',
			body: {},
		})
		assert.equal(status, 400)
		assert.ok(json.error.includes('did'))
	})

	it('POST /api/device/submit validates DID format', async () => {
		const { status, json } = await request('/api/device/submit', {
			method: 'POST',
			body: {
				did: 'did:web:example.com',
				payload: { test: true },
				signature: 'fakesig',
				timestamp: Math.floor(Date.now() / 1000),
			},
		})
		assert.equal(status, 400)
		assert.ok(json.error.toLowerCase().includes('did:key'))
	})

	it('POST /api/device/submit validates timestamp freshness', async () => {
		const { status } = await request('/api/device/submit', {
			method: 'POST',
			body: {
				did: 'did:key:zQ3shunBKsXmCvEPknRg3EAXX2gQHfEjPbkD3JhU4GoqbLEq6',
				payload: { test: true },
				signature: 'fakesig',
				timestamp: 1000000,
			},
		})
		assert.equal(status, 400)
	})
})

describe('Removed AVS routes return 404', () => {
	it('GET /api/operators returns 404', async () => {
		const { status } = await request('/api/operators')
		assert.equal(status, 404)
	})

	it('GET /api/operators/stats returns 404', async () => {
		const { status } = await request('/api/operators/stats')
		assert.equal(status, 404)
	})

	it('GET /api/stats returns 404', async () => {
		const { status } = await request('/api/stats')
		assert.equal(status, 404)
	})

	it('GET /api/stats/tasks returns 404', async () => {
		const { status } = await request('/api/stats/tasks')
		assert.equal(status, 404)
	})

	it('GET /api/stats/operators returns 404', async () => {
		const { status } = await request('/api/stats/operators')
		assert.equal(status, 404)
	})
})

describe('General routing', () => {
	it('unknown API route returns 404', async () => {
		const { status, json } = await request('/api/nonexistent')
		assert.equal(status, 404)
		assert.equal(json.error, 'Not found')
	})

	it('OPTIONS preflight returns 204', async () => {
		const res = await fetch(`${BASE_URL}/api/health`, {
			method: 'OPTIONS',
			headers: { Origin: 'http://localhost:3000' },
		})
		assert.equal(res.status, 204)
	})

	it('CORS headers are present', async () => {
		const res = await fetch(`${BASE_URL}/api/health`)
		const cors = res.headers.get('access-control-allow-origin')
		assert.ok(cors)
	})

	it('security headers are present', async () => {
		const res = await fetch(`${BASE_URL}/api/health`)
		assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
		assert.equal(res.headers.get('x-frame-options'), 'DENY')
	})
})
