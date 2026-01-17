/**
 * L{CORE} SDK Utilities
 */

/**
 * Encode a JavaScript object to hex string for Cartesi
 */
export function hexEncode(data: unknown): string {
  const jsonStr = JSON.stringify(data)
  return '0x' + Buffer.from(jsonStr, 'utf-8').toString('hex')
}

/**
 * Decode a hex string from Cartesi to JavaScript object
 */
export function hexDecode<T = unknown>(hex: string): T {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex
  const str = Buffer.from(cleanHex, 'hex').toString('utf-8')
  return JSON.parse(str) as T
}

/**
 * URL-encode a query object for Cartesi inspect endpoint
 */
export function encodeInspectQuery(query: Record<string, unknown>): string {
  return encodeURIComponent(JSON.stringify(query))
}

/**
 * Build full inspect URL
 */
export function buildInspectUrl(baseUrl: string, query: Record<string, unknown>): string {
  const encoded = encodeInspectQuery(query)
  return `${baseUrl}/inspect/${encoded}`
}

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

/**
 * Retry a function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: {
    maxRetries?: number
    initialDelay?: number
    maxDelay?: number
    factor?: number
  } = {}
): Promise<T> {
  const {
    maxRetries = 3,
    initialDelay = 1000,
    maxDelay = 10000,
    factor = 2,
  } = options

  let lastError: Error | undefined
  let delay = initialDelay

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))

      if (attempt < maxRetries) {
        await sleep(delay)
        delay = Math.min(delay * factor, maxDelay)
      }
    }
  }

  throw lastError
}

/**
 * Validate L{CORE} configuration
 */
export function validateConfig(config: {
  attestorUrl?: string
  cartesiUrl?: string
  dappAddress?: string
}): string[] {
  const errors: string[] = []

  if (!config.attestorUrl) {
    errors.push('attestorUrl is required')
  } else if (!isValidUrl(config.attestorUrl)) {
    errors.push('attestorUrl must be a valid URL')
  }

  if (!config.cartesiUrl) {
    errors.push('cartesiUrl is required')
  } else if (!isValidUrl(config.cartesiUrl)) {
    errors.push('cartesiUrl must be a valid URL')
  }

  if (!config.dappAddress) {
    errors.push('dappAddress is required')
  } else if (!isValidAddress(config.dappAddress)) {
    errors.push('dappAddress must be a valid Ethereum address')
  }

  return errors
}

/**
 * Check if string is valid URL
 */
function isValidUrl(str: string): boolean {
  try {
    new URL(str)
    return true
  } catch {
    return false
  }
}

/**
 * Check if string is valid Ethereum address
 */
function isValidAddress(str: string): boolean {
  return /^0x[a-fA-F0-9]{40}$/.test(str)
}
