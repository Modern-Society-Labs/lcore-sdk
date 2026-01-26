import type { WebSocket } from 'ws'
import type { LogLevel } from '#src/types/index.ts'

export interface LogStreamMessage {
	type: 'log'
	data: {
		source: 'attestor'
		timestamp: string
		level: LogLevel
		message: string
		context?: Record<string, unknown>
	}
}

/**
 * Manages WebSocket connections for real-time log streaming.
 * Clients can connect to receive logs as they're generated.
 */
class LogStreamManager {
	private clients: Set<WebSocket> = new Set()
	private recentLogs: LogStreamMessage[] = []
	private maxRecentLogs = 100

	/**
	 * Add a new client connection for log streaming
	 */
	addClient(ws: WebSocket): void {
		this.clients.add(ws)

		// Send recent logs to new client
		for(const log of this.recentLogs) {
			this.sendToClient(ws, log)
		}

		ws.on('close', () => {
			this.removeClient(ws)
		})

		ws.on('error', () => {
			this.removeClient(ws)
		})
	}

	/**
	 * Remove a client connection
	 */
	removeClient(ws: WebSocket): void {
		this.clients.delete(ws)
	}

	/**
	 * Broadcast a log entry to all connected clients
	 */
	broadcast(level: LogLevel, log: Record<string, unknown>): void {
		const message: LogStreamMessage = {
			type: 'log',
			data: {
				source: 'attestor',
				timestamp: new Date().toISOString(),
				level,
				message: (log.msg as string) || (log.message as string) || JSON.stringify(log),
				context: this.extractContext(log),
			},
		}

		// Store in recent logs buffer
		this.recentLogs.push(message)
		if(this.recentLogs.length > this.maxRecentLogs) {
			this.recentLogs.shift()
		}

		// Broadcast to all clients
		for(const client of this.clients) {
			this.sendToClient(client, message)
		}
	}

	/**
	 * Extract context from log object (excluding standard pino fields)
	 */
	private extractContext(log: Record<string, unknown>): Record<string, unknown> | undefined {
		const standardFields = ['level', 'time', 'pid', 'hostname', 'msg', 'message']
		const context: Record<string, unknown> = {}

		for(const [key, value] of Object.entries(log)) {
			if(!standardFields.includes(key)) {
				context[key] = value
			}
		}

		return Object.keys(context).length > 0 ? context : undefined
	}

	/**
	 * Send a message to a specific client
	 */
	private sendToClient(ws: WebSocket, message: LogStreamMessage): void {
		if(ws.readyState === ws.OPEN) {
			try {
				ws.send(JSON.stringify(message))
			} catch {
				// Client may have disconnected, remove it
				this.removeClient(ws)
			}
		}
	}

	/**
	 * Get the number of connected clients
	 */
	getClientCount(): number {
		return this.clients.size
	}

	/**
	 * Clear all connections (for shutdown)
	 */
	close(): void {
		for(const client of this.clients) {
			client.close()
		}
		this.clients.clear()
	}
}

// Singleton instance for global log streaming
export const logStreamManager = new LogStreamManager()
