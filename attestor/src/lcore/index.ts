/**
 * L{CORE} SDK Integration
 *
 * Exports for integrating with the L{CORE} Cartesi rollup layer.
 */

export {
	submitAttestationToLCore,
	queryAttestationFromLCore,
	checkLCoreHealth,
	getLCoreStatus,
} from './client.ts'

export {
	discretizeClaimData,
	discretizeValue,
	extractNumericValues,
	getSchema,
	registerSchema,
	listSchemas,
	BUILTIN_SCHEMAS,
	type BucketDefinition,
	type BucketResult,
	type DiscretizationSchema,
} from './discretize.ts'

export {
	initDecryption,
	isDecryptionConfigured,
	getAdminPublicKey,
	decryptOutput,
	processLCoreResponse,
	processLCoreResponseSync,
	verifyDecryptionProof,
	isEncryptedOutput,
	// Input encryption (for device attestation privacy)
	initInputEncryption,
	isInputEncryptionConfigured,
	encryptInput,
	encryptInputEnvelope,
	// V1 data encryption
	encryptDataForSubmission,
	computeDataHash,
	decryptDataSubmission,
	// V2 per-device ECDH encryption
	initV2Encryption,
	isV2Configured,
	getV2PublicKey,
	encryptDataForSubmissionV2,
	decryptDataSubmissionV2,
	type EncryptedOutput,
	type DecryptionResult,
	type DecryptionError,
	type DecryptionProof,
	type LCoreResponseWithProof,
} from './encryption.ts'

export {
	type LCoreQueryResult,
	type LCoreQueryError,
} from './client.ts'
