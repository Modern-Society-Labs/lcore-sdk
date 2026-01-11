/**
 * Operators module
 *
 * Provides operator application workflow and profile management.
 */

// Application service
export {
	submitApplication,
	getApplicationById,
	getApplicationByWallet,
	listApplications,
	startReview,
	reviewApplication,
	withdrawApplication,
	getApplicationStats,
} from './application-service.ts'
export type {
	ApplicationInfo,
	SubmitApplicationParams,
	ReviewApplicationParams,
} from './application-service.ts'

// Profile service
export {
	getOperatorProfile,
	updateOperatorProfile,
	listOperators,
	getOperatorStats,
} from './profile-service.ts'
export type {
	OperatorInfo,
	UpdateProfileParams,
} from './profile-service.ts'
