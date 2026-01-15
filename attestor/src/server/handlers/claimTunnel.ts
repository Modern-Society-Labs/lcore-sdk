import { MAX_CLAIM_TIMESTAMP_DIFF_S } from '#src/config/index.ts'
import { discretizeClaimData, submitAttestationToLCore } from '#src/lcore/index.ts'
import { ClaimTunnelResponse } from '#src/proto/api.ts'
import { getApm } from '#src/server/utils/apm.ts'
import { assertTranscriptsMatch, assertValidClaimRequest } from '#src/server/utils/assert-valid-claim-request.ts'
import { getAttestorAddress, signAsAttestor } from '#src/server/utils/generics.ts'
import type { RPCHandler } from '#src/types/index.ts'
import { getEnvVariable } from '#src/utils/env.ts'
import { AttestorError, createSignDataForClaim, getIdentifierFromClaimInfo, unixTimestampSeconds } from '#src/utils/index.ts'

// Enable/disable L{CORE} integration (enabled by default)
const LCORE_ENABLED = getEnvVariable('LCORE_ENABLED') !== '0'

export const claimTunnel: RPCHandler<'claimTunnel'> = async(
	claimRequest,
	{ tx, logger, client }
) => {
	const {
		request,
		data: { timestampS } = {},
	} = claimRequest
	const tunnel = client.getTunnel(request?.id!)
	try {
		await tunnel.close()
	} catch(err) {
		logger.debug({ err }, 'error closing tunnel')
	}

	if(tx) {
		const transcriptBytes = tunnel.transcript.reduce(
			(acc, { message }) => acc + message.length,
			0
		)
		tx?.setLabel('transcriptBytes', transcriptBytes.toString())
	}

	// we throw an error for cases where the attestor cannot prove
	// the user's request is faulty. For eg. if the user sends a
	// "createRequest" that does not match the tunnel's actual
	// create request -- the attestor cannot prove that the user
	// is lying. In such cases, we throw a bad request error.
	// Same goes for matching the transcript.
	if(
		tunnel.createRequest?.host !== request?.host
		|| tunnel.createRequest?.port !== request?.port
		|| tunnel.createRequest?.geoLocation !== request?.geoLocation
		|| tunnel.createRequest?.proxySessionId !== request?.proxySessionId
	) {
		throw AttestorError.badRequest('Tunnel request does not match')
	}

	assertTranscriptsMatch(claimRequest.transcript, tunnel.transcript)

	const res = ClaimTunnelResponse.create({ request: claimRequest })
	try {
		const now = unixTimestampSeconds()
		if(Math.floor(timestampS! - now) > MAX_CLAIM_TIMESTAMP_DIFF_S) {
			throw new AttestorError(
				'ERROR_INVALID_CLAIM',
				`Timestamp provided ${timestampS} is too far off. Current time is ${now}`
			)
		}

		const assertTx = getApm()
			?.startTransaction('assertValidClaimRequest', { childOf: tx })

		try {
			const claim = await assertValidClaimRequest(
				claimRequest,
				client.metadata,
				logger
			)
			res.claim = {
				...claim,
				identifier: getIdentifierFromClaimInfo(claim),
				// hardcode for compatibility with V1 claims
				epoch: 1
			}
		} catch(err) {
			assertTx?.setOutcome('failure')
			throw err
		} finally {
			assertTx?.end()
		}
	} catch(err) {
		logger.error({ err }, 'invalid claim request')
		const attestorErr = AttestorError.fromError(err, 'ERROR_INVALID_CLAIM')
		res.error = attestorErr.toProto()
	}

	res.signatures = {
		attestorAddress: getAttestorAddress(
			client.metadata.signatureType
		),
		claimSignature: res.claim
			? await signAsAttestor(
				createSignDataForClaim(res.claim),
				client.metadata.signatureType
			)
			: new Uint8Array(),
		resultSignature: await signAsAttestor(
			ClaimTunnelResponse.encode(res).finish(),
			client.metadata.signatureType
		)
	}

	// Submit successful claim to L{CORE} Cartesi layer
	if(LCORE_ENABLED && res.claim && !res.error) {
		try {
			const lcoreTx = getApm()
				?.startTransaction('submitToLCore', { childOf: tx })

			// Parse parameters to extract bucket data
			let parsedParams: Record<string, unknown> = {}
			try {
				parsedParams = JSON.parse(res.claim.parameters || '{}')
			} catch{
				// Parameters not JSON, skip bucket extraction
			}

			// Determine flow type from parameters
			const flowType = parsedParams.url ? 'web_request' : 'generic'

			// Discretize claim data into privacy-preserving buckets
			const buckets = discretizeClaimData(
				res.claim.provider,
				flowType,
				parsedParams
			)

			// Convert claim signature to base64 for storage
			const signatureBase64 = Buffer.from(res.signatures.claimSignature).toString('base64')

			const lcoreResult = await submitAttestationToLCore({
				id: res.claim.identifier,
				attestationHash: res.claim.identifier,
				ownerAddress: res.claim.owner,
				provider: res.claim.provider,
				flowType,
				validFrom: res.claim.timestampS,
				teeSignature: signatureBase64,
				buckets,
				data: [{
					key: 'parameters',
					value: Buffer.from(res.claim.parameters || '').toString('base64'),
					encryptionKeyId: 'none', // Not encrypted for now
				}, {
					key: 'context',
					value: Buffer.from(res.claim.context || '').toString('base64'),
					encryptionKeyId: 'none',
				}],
			}, res.signatures.attestorAddress)

			if(lcoreResult.success) {
				logger.info(
					{ attestationId: lcoreResult.attestationId },
					'Claim submitted to L{CORE}'
				)
			} else {
				logger.warn(
					{ error: lcoreResult.error, details: lcoreResult.details },
					'Failed to submit claim to L{CORE}'
				)
			}

			lcoreTx?.end()
		} catch(err) {
			// L{CORE} submission failure should not fail the claim
			logger.error({ err }, 'Error submitting to L{CORE}')
		}
	}

	// remove tunnel from client -- to free up our mem
	client.removeTunnel(request.id)

	return res
}