/**
 * Submission Batcher
 *
 * Buffers device attestation submissions and flushes them as a single
 * `batch_device_attestation` InputBox transaction. Mitigates metadata
 * activity pattern leaks (timing, cadence) by decoupling individual
 * device submissions from on-chain transactions.
 *
 * Configurable via environment variables:
 * - LCORE_BATCH_FLUSH_INTERVAL: Flush interval in ms (default: 30000)
 * - LCORE_BATCH_MAX_SIZE: Max submissions before forced flush (default: 50)
 */

export interface BatchableSubmission {
	action: 'device_attestation'
	data_hash: string
	jws: string
	encrypted_data: string
	device_did: string
	timestamp: number
	encryption_key_id: string
	source?: string
}

export interface BatchFlushResult {
	success: boolean
	count: number
	txHash?: string
	blockNumber?: number
	error?: string
}

export type FlushFn = (submissions: BatchableSubmission[]) => Promise<BatchFlushResult>

export class SubmissionBatcher {
	private buffer: BatchableSubmission[] = []
	private flushInterval: number
	private maxSize: number
	private flushFn: FlushFn
	private timer: ReturnType<typeof setInterval> | null = null
	private flushing = false

	constructor(flushFn: FlushFn, options?: { flushInterval?: number; maxSize?: number }) {
		this.flushFn = flushFn
		this.flushInterval = options?.flushInterval ??
			parseInt(process.env.LCORE_BATCH_FLUSH_INTERVAL || '30000', 10)
		this.maxSize = options?.maxSize ??
			parseInt(process.env.LCORE_BATCH_MAX_SIZE || '50', 10)
	}

	/**
	 * Start the periodic flush timer.
	 */
	start(): void {
		if (this.timer) return
		this.timer = setInterval(() => {
			void this.flush()
		}, this.flushInterval)
	}

	/**
	 * Stop the periodic flush timer and flush remaining items.
	 */
	async stop(): Promise<BatchFlushResult | null> {
		if (this.timer) {
			clearInterval(this.timer)
			this.timer = null
		}
		if (this.buffer.length > 0) {
			return this.flush()
		}
		return null
	}

	/**
	 * Add a submission to the batch buffer.
	 * If the buffer reaches maxSize, triggers an immediate flush.
	 * Returns a promise that resolves when the submission is accepted into the buffer.
	 * If maxSize is reached, returns the flush result.
	 */
	async add(submission: BatchableSubmission): Promise<BatchFlushResult | null> {
		this.buffer.push(submission)

		if (this.buffer.length >= this.maxSize) {
			return this.flush()
		}

		return null
	}

	/**
	 * Flush the current buffer to the InputBox as a batch.
	 * No-op if buffer is empty or a flush is already in progress.
	 */
	async flush(): Promise<BatchFlushResult> {
		if (this.buffer.length === 0) {
			return { success: true, count: 0 }
		}

		if (this.flushing) {
			return { success: false, count: 0, error: 'Flush already in progress' }
		}

		this.flushing = true
		const batch = this.buffer.splice(0)

		try {
			const result = await this.flushFn(batch)
			return result
		} catch (error) {
			// Put submissions back at the front of the buffer for retry
			this.buffer.unshift(...batch)
			return {
				success: false,
				count: batch.length,
				error: error instanceof Error ? error.message : String(error),
			}
		} finally {
			this.flushing = false
		}
	}

	/**
	 * Get the current buffer size.
	 */
	get size(): number {
		return this.buffer.length
	}

	/**
	 * Get the current buffer contents (read-only snapshot).
	 */
	get pending(): ReadonlyArray<BatchableSubmission> {
		return [...this.buffer]
	}
}
