/**
 * Admin authentication module
 *
 * Provides wallet-based authentication with JWT session tokens for the admin dashboard.
 */

// JWT utilities
export {
	createJWT,
	verifyJWT,
	refreshJWT,
	shouldRefreshToken,
	hashSessionToken,
	generateSessionId,
} from './jwt.ts'
export type { JWTPayload, SessionToken } from './jwt.ts'

// Wallet authentication
export {
	generateNonce,
	verifyWalletSignature,
	getSignMessage,
	isValidAddress,
	normalizeAddress,
} from './wallet.ts'

// Middleware
export {
	createAuthMiddleware,
	hasRequiredRole,
	requireSuperAdmin,
	requireAdmin,
	requireViewer,
	requireAuthWithApiKey,
} from './middleware.ts'
export type { AuthenticatedRequest, AuthMiddlewareOptions } from './middleware.ts'

// Admin service
export {
	requestLoginNonce,
	loginWithWallet,
	getAdminById,
	registerAdmin,
	updateAdminRole,
	revokeSession,
	revokeAllSessions,
	listAdmins,
	deleteAdmin,
} from './admin-service.ts'
export type { AdminInfo, LoginResult, NonceResult } from './admin-service.ts'

// Audit logging
export {
	createAuditLog,
	auditFromRequest,
	queryAuditLogs,
	getRecentActivity,
	getActivitySummary,
} from './audit.ts'
export type { AuditAction, AuditLogEntry } from './audit.ts'

// API keys
export {
	createApiKey,
	listApiKeys,
	revokeApiKey,
	updateApiKeyPermissions,
	API_KEY_PERMISSIONS,
} from './api-keys.ts'
export type { ApiKeyInfo, CreateApiKeyResult, ApiKeyPermission } from './api-keys.ts'
