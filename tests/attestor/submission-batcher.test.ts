import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { SubmissionBatcher, type BatchableSubmission, type BatchFlushResult } from '../../attestor/src/submission-batcher.ts'

function makeSub(i: number): BatchableSubmission {
	return {
		action: 'device_attestation',
		data_hash: 'a'.repeat(64),
		jws: `header.payload.sig${i}`,
		encrypted_data: Buffer.from(`data-${i}`).toString('base64'),
		device_did: `did:key:zDevice${i}`,
		timestamp: Math.floor(Date.now() / 1000),
		encryption_key_id: 'lcore_key_v1',
		source: 'relay',
	}
}

describe('SubmissionBatcher', () => {
	let flushedBatches: BatchableSubmission[][]
	let flushFn: (subs: BatchableSubmission[]) => Promise<BatchFlushResult>

	beforeEach(() => {
		flushedBatches = []
		flushFn = async (subs) => {
			flushedBatches.push([...subs])
			return { success: true, count: subs.length, txHash: '0xabc', blockNumber: 42 }
		}
	})

	it('should buffer submissions until flush', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 10 })

		await batcher.add(makeSub(1))
		await batcher.add(makeSub(2))

		assert.equal(batcher.size, 2)
		assert.equal(flushedBatches.length, 0)

		const result = await batcher.flush()
		assert.equal(result.success, true)
		assert.equal(result.count, 2)
		assert.equal(batcher.size, 0)
		assert.equal(flushedBatches.length, 1)
		assert.equal(flushedBatches[0].length, 2)
	})

	it('should auto-flush when maxSize is reached', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 3 })

		await batcher.add(makeSub(1))
		await batcher.add(makeSub(2))
		assert.equal(flushedBatches.length, 0)

		const result = await batcher.add(makeSub(3))
		assert.equal(flushedBatches.length, 1)
		assert.equal(flushedBatches[0].length, 3)
		assert.equal(batcher.size, 0)
		assert.ok(result !== null)
		assert.equal(result!.success, true)
	})

	it('should return empty result when flushing empty buffer', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 10 })
		const result = await batcher.flush()
		assert.equal(result.success, true)
		assert.equal(result.count, 0)
		assert.equal(flushedBatches.length, 0)
	})

	it('should put submissions back on flush failure', async () => {
		const failFlush: typeof flushFn = async () => {
			throw new Error('network error')
		}
		const batcher = new SubmissionBatcher(failFlush, { flushInterval: 60000, maxSize: 10 })

		await batcher.add(makeSub(1))
		await batcher.add(makeSub(2))

		const result = await batcher.flush()
		assert.equal(result.success, false)
		assert.equal(result.error, 'network error')
		// Submissions should be back in the buffer
		assert.equal(batcher.size, 2)
	})

	it('should stop timer and flush remaining on stop()', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 100 })
		batcher.start()

		await batcher.add(makeSub(1))
		await batcher.add(makeSub(2))

		const result = await batcher.stop()
		assert.ok(result !== null)
		assert.equal(result!.success, true)
		assert.equal(result!.count, 2)
		assert.equal(batcher.size, 0)
	})

	it('should return null from stop() when buffer is empty', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 100 })
		batcher.start()

		const result = await batcher.stop()
		assert.equal(result, null)
	})

	it('should return null from add() when below maxSize', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 10 })
		const result = await batcher.add(makeSub(1))
		assert.equal(result, null)
	})

	it('should expose pending submissions as read-only snapshot', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 10 })
		await batcher.add(makeSub(1))
		await batcher.add(makeSub(2))

		const pending = batcher.pending
		assert.equal(pending.length, 2)
		assert.equal(pending[0].device_did, 'did:key:zDevice1')
		assert.equal(pending[1].device_did, 'did:key:zDevice2')
	})

	it('should handle sequential flushes correctly', async () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 10 })

		await batcher.add(makeSub(1))
		await batcher.flush()
		assert.equal(flushedBatches.length, 1)

		await batcher.add(makeSub(2))
		await batcher.add(makeSub(3))
		await batcher.flush()
		assert.equal(flushedBatches.length, 2)
		assert.equal(flushedBatches[1].length, 2)
	})

	it('should not double-start the timer', () => {
		const batcher = new SubmissionBatcher(flushFn, { flushInterval: 60000, maxSize: 10 })
		batcher.start()
		batcher.start() // Should be a no-op
		// No assertion needed - just verifying no error
		void batcher.stop()
	})
})

describe('SubmissionBatcher byte budget', () => {
	/**
	 * The InputBox caps input size, and in rollups-contracts v2 that cap drops to
	 * 64 KB with the transaction REVERTING rather than the input being rejected.
	 * Batching on count alone could exceed it, so the batcher budgets bytes too.
	 */
	function makeBigSub(i: number, payloadBytes: number): BatchableSubmission {
		return { ...makeSub(i), encrypted_data: 'x'.repeat(payloadBytes) }
	}

	let batches: BatchableSubmission[][]
	let flush: (subs: BatchableSubmission[]) => Promise<BatchFlushResult>

	beforeEach(() => {
		batches = []
		flush = async (subs) => {
			batches.push([...subs])
			return { success: true, count: subs.length, txHash: '0xabc', blockNumber: 1 }
		}
	})

	it('flushes on the byte budget before the count limit is reached', async () => {
		// maxSize 100 would never trigger; the byte budget must be what flushes.
		const b = new SubmissionBatcher(flush, { maxSize: 100, maxBytes: 4096 })
		for (let i = 0; i < 6; i++) await b.add(makeBigSub(i, 1000))

		assert.ok(batches.length >= 1, 'expected at least one byte-triggered flush')
		for (const batch of batches) {
			const bytes = Buffer.byteLength(JSON.stringify(batch), 'utf8')
			assert.ok(bytes <= 4096 * 1.5, `batch of ${bytes}B exceeded the budget`)
		}
	})

	it('keeps every submission across byte-triggered flushes', async () => {
		const b = new SubmissionBatcher(flush, { maxSize: 100, maxBytes: 4096 })
		for (let i = 0; i < 10; i++) await b.add(makeBigSub(i, 1000))
		await b.stop()

		const delivered = batches.flat().length
		assert.equal(delivered, 10, 'submissions were dropped by the byte budget')
	})

	it('still honours the count limit when payloads are small', async () => {
		const b = new SubmissionBatcher(flush, { maxSize: 3, maxBytes: 1024 * 1024 })
		for (let i = 0; i < 3; i++) await b.add(makeSub(i))

		assert.equal(batches.length, 1)
		assert.equal(batches[0].length, 3)
	})
})
