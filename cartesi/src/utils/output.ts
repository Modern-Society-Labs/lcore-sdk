/**
 * Output Processing Utility
 *
 * Handles output processing based on configured OUTPUT_MODE.
 * This provides a unified interface for all handlers to process their outputs.
 */

import { getConfig } from '../config';
import { encryptOutput, isEncryptionConfigured } from '../encryption';
import { customOutputHandler } from '../custom/output-handler';
import type { AdvanceRequestData, InspectRequestData } from '../router';

/**
 * Check if data is already wrapped by createResponse().
 * Handlers that call createResponse() return { encrypted: boolean, ... }.
 * processOutput/processOutputSync must not re-encrypt these.
 */
function isAlreadyWrapped(data: unknown): boolean {
  return (
    typeof data === 'object' &&
    data !== null &&
    'encrypted' in data &&
    typeof (data as Record<string, unknown>).encrypted === 'boolean'
  );
}

/**
 * Process output based on configured OUTPUT_MODE.
 *
 * @param data - The raw data to be returned
 * @param request - The original request (optional, used for custom mode)
 * @returns Processed output according to OUTPUT_MODE setting
 */
export async function processOutput(
  data: unknown,
  request?: AdvanceRequestData | InspectRequestData
): Promise<unknown> {
  // Handler already called createResponse() — don't re-encrypt
  if (isAlreadyWrapped(data)) {
    return data;
  }

  const config = getConfig();

  switch (config.outputMode) {
    case 'encrypted':
      // Default: Encrypt all outputs for privacy
      if (!isEncryptionConfigured()) {
        console.warn('[LCORE] Output encryption not configured, returning raw data');
        return data;
      }
      return encryptOutput(data);

    case 'raw':
      // Return raw data (for public data use cases)
      return data;

    case 'custom':
      // Developer-defined access control
      if (!request) {
        // If no request context, fall back to encrypted
        console.warn('[LCORE] Custom output mode requires request context, falling back to encrypted');
        if (isEncryptionConfigured()) {
          return encryptOutput(data);
        }
        return data;
      }
      return customOutputHandler(data, request);

    default:
      // Fallback to encrypted for safety
      if (isEncryptionConfigured()) {
        return encryptOutput(data);
      }
      return data;
  }
}

/**
 * Synchronous version for simple cases (only for encrypted/raw modes).
 * For custom mode, use processOutput() instead.
 */
export function processOutputSync(data: unknown): unknown {
  // Handler already called createResponse() — don't re-encrypt
  if (isAlreadyWrapped(data)) {
    return data;
  }

  const config = getConfig();

  switch (config.outputMode) {
    case 'raw':
      return data;

    case 'encrypted':
    case 'custom':
    default:
      if (isEncryptionConfigured()) {
        return encryptOutput(data);
      }
      return data;
  }
}
