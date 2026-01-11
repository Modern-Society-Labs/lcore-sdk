// eslint-disable-next-line simple-import-sort/imports
import '#src/server/utils/config-env.ts'
import { ethers } from 'ethers'

import { SELECTED_CHAIN_ID } from '#src/avs/config.ts'
import { getContracts } from '#src/avs/utils/contracts.ts'
import { logger as LOGGER } from '#src/utils/index.ts'

type RegisterTEEWalletOpts = {
	logger?: typeof LOGGER
	/**
	 * Chain ID to register on
	 * @default -- env variable CHAIN_ID
	 */
	chainId?: string
	/**
	 * The TEE-derived wallet address to register
	 */
	teeWalletAddress: string
	/**
	 * The Docker image hash for attestation
	 * Use bytes32(0) for testing or the actual image digest
	 */
	dockerImageHash?: string
}

/**
 * Registers a TEE wallet for the operator on the LocaleServiceManager
 */
export async function registerTEEWallet({
	logger = LOGGER,
	chainId = SELECTED_CHAIN_ID,
	teeWalletAddress,
	dockerImageHash = ethers.constants.HashZero, // Default to zero hash for initial registration
}: RegisterTEEWalletOpts) {
	if(!chainId) {
		throw new Error('CHAIN_ID environment variable is required')
	}

	const contracts = getContracts(chainId)
	const wallet = contracts.wallet

	if(!wallet) {
		throw new Error('PRIVATE_KEY environment variable is required to sign the transaction')
	}

	const contract = contracts.contract.connect(wallet)
	const operatorAddress = await wallet.getAddress()

	logger.info({ operatorAddress, chainId }, 'Registering TEE wallet')

	// Check if the operator is registered
	const isRegistered = await contracts.registryContract.operatorRegistered(operatorAddress)
	if(!isRegistered) {
		throw new Error(`Operator ${operatorAddress} is not registered on the AVS. Please register first using: npm run register:avs-operator`)
	}

	// Check if this TEE wallet is already registered
	// Use getOperatorForTEEWallet which is a proper getter that returns address(0) if not found
	try {
		const existingOperator = await contract.getOperatorForTEEWallet(teeWalletAddress)
		if(existingOperator !== ethers.constants.AddressZero) {
			if(existingOperator.toLowerCase() === operatorAddress.toLowerCase()) {
				logger.info({ teeWalletAddress }, 'TEE wallet already registered for this operator')
				return
			}
			throw new Error(`TEE wallet ${teeWalletAddress} is already registered to operator ${existingOperator}`)
		}
	} catch(err) {
		// If the function doesn't exist or fails, proceed with registration
		logger.debug({ error: err.message }, 'Could not check existing TEE wallet registration')
	}

	// Check if operator already has a different TEE wallet registered
	try {
		const existingTEEWallet = await contract.operatorToTEEWallet(operatorAddress)
		if(existingTEEWallet !== ethers.constants.AddressZero) {
			logger.warn(
				{ existingTEEWallet, newTEEWallet: teeWalletAddress },
				'Operator already has a TEE wallet registered. It will be replaced.'
			)
		}
	} catch(err) {
		// If the function doesn't exist or fails, proceed
		logger.debug({ error: err.message }, 'Could not check existing operator TEE wallet')
	}

	// Register the TEE wallet
	logger.info(
		{
			teeWalletAddress,
			dockerImageHash,
		},
		'Submitting registerTEEWallet transaction'
	)

	const tx = await contract.registerTEEWallet(teeWalletAddress, dockerImageHash)
	logger.info({ txHash: tx.hash }, 'Transaction submitted, waiting for confirmation')

	const receipt = await tx.wait()
	logger.info(
		{
			txHash: receipt.transactionHash,
			blockNumber: receipt.blockNumber,
			gasUsed: receipt.gasUsed.toString(),
		},
		'TEE wallet registered successfully!'
	)

	// Verify registration
	try {
		const verifyOperator = await contract.getOperatorForTEEWallet(teeWalletAddress)
		const isValid = await contract.isTEEWalletValid(teeWalletAddress)

		logger.info(
			{
				teeWalletAddress,
				mappedOperator: verifyOperator,
				isValid,
			},
			'Registration verified'
		)
	} catch(err) {
		logger.info({ teeWalletAddress }, 'Registration complete (verification unavailable)')
	}
}

// Main execution
const TEE_WALLET_ADDRESS = process.env.TEE_WALLET_ADDRESS
const DOCKER_IMAGE_HASH = process.env.DOCKER_IMAGE_HASH || ethers.constants.HashZero

if(!TEE_WALLET_ADDRESS) {
	console.error('Error: TEE_WALLET_ADDRESS environment variable is required')
	console.error('Usage: TEE_WALLET_ADDRESS=0x... npm run register:tee-wallet')
	console.error('')
	console.error('If running on EigenCompute, the TEE wallet address is derived from MNEMONIC.')
	console.error('You can get it by running the attestor and checking the startup logs.')
	process.exit(1)
}

void registerTEEWallet({
	teeWalletAddress: TEE_WALLET_ADDRESS,
	dockerImageHash: DOCKER_IMAGE_HASH,
})
