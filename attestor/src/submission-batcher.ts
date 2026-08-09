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

/**
 * Byte budget for a single batch.
 *
 * The Cartesi InputBox caps the size of an input. On the rollups-contracts line
 * this repo currently targets that cap is ~2 MB, but in contracts v2 it drops to
 * 64 KB (CanonicalMachine.INPUT_MAX_SIZE, 1<<16) and InputBox REVERTS the
 * transaction rather than rejecting the input — so an oversized batch fails as a
 * failed tx, after gas, with no rollup-level error to inspect.
 *
 * Batching previously flushed on count and time only, with no byte awareness, so
 * a batch of large payloads could exceed the cap. We budget against the v2 limit
 * now: it is well within the current cap, costs only slightly more frequent
 * flushes, and means the upgrade does not silently break ingestion.
 *
 * The margin covers ABI encoding overhead — the on-chain check measures the full
 * encoded EvmAdvance call, not the JSON payload.
 */
const DEFAULT_MAX_BATCH_BYTES = 56 * 1024

export class SubmissionBatcher {
	private buffer: BatchableSubmission[] = []
	private bufferBytes = 0
	private flushInterval: number
	private maxSize: number
	private maxBytes: number
	private flushFn: FlushFn
	private timer: ReturnType<typeof setInterval> | null = null
	private flushing = false

	constructor(
		flushFn: FlushFn,
		options?: { flushInterval?: number; maxSize?: number; maxBytes?: number }
	) {
		this.flushFn = flushFn
		this.flushInterval = options?.flushInterval ??
			parseInt(process.env.LCORE_BATCH_FLUSH_INTERVAL || '30000', 10)
		this.maxSize = options?.maxSize ??
			parseInt(process.env.LCORE_BATCH_MAX_SIZE || '50', 10)
		this.maxBytes = options?.maxBytes ??
			parseInt(process.env.LCORE_BATCH_MAX_BYTES || String(DEFAULT_MAX_BATCH_BYTES), 10)
	}

	/** Encoded size of one submission, as it will appear in the batch payload. */
	private sizeOf(submission: BatchableSubmission): number {
		return Buffer.byteLength(JSON.stringify(submission), 'utf8')
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
		const size = this.sizeOf(submission)

		// Flush BEFORE adding if this submission would push the batch over the byte
		// budget, so the batch we send stays under the InputBox limit.
		let pendingResult: BatchFlushResult | null = null
		if (this.buffer.length > 0 && this.bufferBytes + size > this.maxBytes) {
			pendingResult = await this.flush()
		}

		this.buffer.push(submission)
		this.bufferBytes += size

		if (this.buffer.length >= this.maxSize || this.bufferBytes >= this.maxBytes) {
			return this.flush()
		}

		return pendingResult
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
		this.bufferBytes = 0

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
