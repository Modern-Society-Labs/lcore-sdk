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
