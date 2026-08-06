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
