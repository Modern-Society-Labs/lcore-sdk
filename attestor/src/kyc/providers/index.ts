/**
 * KYC Provider Registry
 *
 * Central registry for all KYC providers.
 * Add new providers here to make them available in the zkIdentity flow.
 */

import type { KYCProvider, KYCProviderInfo } from './interface.ts'
import { smileIdProvider } from './smile-id.ts'
import { plaidProvider } from './plaid.ts'

// ============= Registry =============

const providers = new Map<string, KYCProvider>()

// Register built-in providers
providers.set('smile_id', smileIdProvider)
providers.set('plaid', plaidProvider)

// ============= Public API =============

/**
 * Get a KYC provider by name.
 * Throws if provider not found.
 */
export function getProvider(name: string): KYCProvider {
	const provider = providers.get(name)
	if(!provider) {
		throw new Error(`Unknown KYC provider: ${name}. Available: ${[...providers.keys()].join(', ')}`)
	}

	return provider
}

/**
 * List all available KYC providers with their metadata.
 */
export function getAvailableProviders(): KYCProviderInfo[] {
	return [...providers.values()].map(p => ({
		name: p.name,
		displayName: formatDisplayName(p.name),
		supportedCountries: p.supportedCountries,
		stubMode: p.isStubMode,
	}))
}

/**
 * Check if a provider exists.
 */
export function hasProvider(name: string): boolean {
	return providers.has(name)
}

// ============= Helpers =============

function formatDisplayName(name: string): string {
	const names: Record<string, string> = {
		smile_id: 'Smile ID',
		vove_id: 'Vove ID',
		persona: 'Persona',
		plaid: 'Plaid',
	}
	return names[name] || name
}

// Re-export types
export type { KYCProvider, KYCProviderInfo, KYCSession, KYCStatus, KYCResult, CreateSessionOptions } from './interface.ts'
