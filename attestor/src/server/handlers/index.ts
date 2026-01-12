import { claimTeeBundle } from '#src/server/handlers/claimTeeBundle.ts'
import { claimTunnel } from '#src/server/handlers/claimTunnel.ts'
import { createTaskOnMechain } from '#src/server/handlers/createTaskOnMechain.ts'
import { createTunnel } from '#src/server/handlers/createTunnel.ts'
import { disconnectTunnel } from '#src/server/handlers/disconnectTunnel.ts'
import { fetchCertificateBytes } from '#src/server/handlers/fetchCertificateBytes.ts'
import { init } from '#src/server/handlers/init.ts'
import { toprf } from '#src/server/handlers/toprf.ts'
import type { RPCHandler, RPCType } from '#src/types/index.ts'
import { AttestorError } from '#src/utils/index.ts'

// Deprecated AVS handlers - throw error if called
const createClaimOnChain: RPCHandler<'createClaimOnChain'> = async() => {
	throw AttestorError.badRequest('createClaimOnChain is deprecated. Use createTaskOnMechain instead.')
}

const completeClaimOnChain: RPCHandler<'completeClaimOnChain'> = async() => {
	throw AttestorError.badRequest('completeClaimOnChain is deprecated. Use createTaskOnMechain instead.')
}

export const HANDLERS: { [T in RPCType]: RPCHandler<T> } = {
	createTunnel,
	disconnectTunnel,
	claimTunnel,
	claimTeeBundle,
	init,
	createClaimOnChain,
	completeClaimOnChain,
	toprf,
	createTaskOnMechain,
	fetchCertificateBytes
}
