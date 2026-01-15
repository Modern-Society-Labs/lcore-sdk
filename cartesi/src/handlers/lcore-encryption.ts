/**
 * L{CORE} Encryption Handlers
 *
 * Handlers for encryption key management.
 *
 * ADVANCE HANDLERS:
 * - set_encryption_key: Set the admin encryption public key (admin only)
 *
 * INSPECT HANDLERS:
 * - encryption_config: Get current encryption configuration
 */

import type { AdvanceRequestData, InspectQuery } from '../router';
import {
  setEncryptionKey,
  getActiveEncryptionConfig,
  isEncryptionConfigured,
} from '../encryption';
import { isSchemaAdmin, getAllSchemaAdmins } from '../lcore-db';

// ============= Advance Handlers =============

/**
 * Set the encryption public key.
 *
 * This is a privileged operation that can only be performed by:
 * 1. The first caller (bootstrap - when no admins exist)
 * 2. A schema admin with full permissions
 *
 * @param data - Advance request with payload containing:
 *   - public_key: Base64-encoded 32-byte NaCl public key
 */
export async function handleSetEncryptionKey(
  data: AdvanceRequestData,
  payload: unknown
): Promise<{ status: 'accept' | 'reject'; response?: unknown }> {
  const p = payload as {
    action: string;
    public_key: string;
  };

  // Validate payload
  if (!p.public_key || typeof p.public_key !== 'string') {
    return {
      status: 'reject',
      response: { error: 'public_key is required' },
    };
  }

  // Check authorization
  const sender = data.metadata.msg_sender.toLowerCase();
  const existingAdmins = getAllSchemaAdmins();

  // Allow bootstrap if no admins exist
  const isBootstrap = existingAdmins.length === 0;

  if (!isBootstrap && !isSchemaAdmin(sender)) {
    return {
      status: 'reject',
      response: {
        error: 'Not authorized to set encryption key',
        sender,
      },
    };
  }

  try {
    const config = setEncryptionKey(p.public_key, data.metadata.input_index);

    return {
      status: 'accept',
      response: {
        success: true,
        key_id: config.key_id,
        algorithm: config.algorithm,
        message: isBootstrap
          ? 'Encryption key set during bootstrap'
          : 'Encryption key updated',
      },
    };
  } catch (error) {
    return {
      status: 'reject',
      response: {
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

// ============= Inspect Handlers =============

/**
 * Get the current encryption configuration.
 *
 * Returns:
 * - configured: boolean
 * - config: { key_id, algorithm, created_at } (if configured)
 *
 * Note: The public_key is intentionally not returned to avoid confusion.
 * The public key should be retrieved through admin channels if needed.
 */
export async function handleInspectEncryptionConfig(
  query: InspectQuery
): Promise<unknown> {
  const config = getActiveEncryptionConfig();

  if (!config) {
    return {
      configured: false,
      message: 'No encryption key has been set',
    };
  }

  return {
    configured: true,
    config: {
      key_id: config.key_id,
      algorithm: config.algorithm,
      created_at: config.created_at,
      status: config.status,
    },
  };
}

/**
 * Check if encryption is configured.
 *
 * Simple boolean check for quick health checks.
 */
export async function handleInspectEncryptionStatus(
  query: InspectQuery
): Promise<unknown> {
  return {
    encryption_configured: isEncryptionConfigured(),
  };
}
