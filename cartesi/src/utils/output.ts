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
