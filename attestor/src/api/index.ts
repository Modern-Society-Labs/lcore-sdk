/**
 * Admin API module
 *
 * Provides REST API endpoints for the admin dashboard.
 */

// Main router
export { handleApiRequest, handleHealthCheck } from './routes/index.ts'

// Auth module
export * from './auth/index.ts'

// Operators module
export * from './operators/index.ts'

// HTTP utilities
export {
	parseJsonBody,
	sendJson,
	sendError,
	getClientInfo,
	parseQuery,
	setCorsHeaders,
	handleCorsPrelight,
} from './utils/http.ts'
