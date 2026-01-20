/**
 * Custom Output Handler - DEVELOPERS OVERRIDE THIS FILE
 *
 * This is called when OUTPUT_MODE='custom'. Implement your own
 * access control, monetization, or data filtering logic here.
 *
 * Examples:
 *   - Micropayments: Verify payment proof before returning data
 *   - Role-based: Check viewer permissions in database
 *   - Tiered access: Return redacted vs full based on subscription
 *   - Public aggregates: Return only aggregated/anonymized data
 *
 * SECURITY NOTE:
 * This function runs inside Cartesi (deterministic, fraud-provable).
 * Any access control you implement here can be verified by anyone.
 */

import { encryptOutput, isEncryptionConfigured } from '../encryption';
import type { AdvanceRequestData, InspectRequestData } from '../router';

/**
 * Custom output processing function.
 *
 * @param data - The raw data to be returned
 * @param request - The original request (contains sender address, metadata)
 * @returns Processed output (encrypted, filtered, or raw)
 */
export async function customOutputHandler(
  data: unknown,
  request: AdvanceRequestData | InspectRequestData
): Promise<unknown> {
  // ============================================
  // DEFAULT IMPLEMENTATION: Same as 'encrypted' mode
  // Replace this with your custom logic
  // ============================================
  if (isEncryptionConfigured()) {
    return encryptOutput(data);
  }
  return data;

  // ============================================
  // EXAMPLE: Micropayment verification
  // ============================================
  // const paymentProof = (request as any).payload?.paymentProof;
  // if (!paymentProof) {
  //   return { error: 'Payment required', price: '0.001 ETH' };
  // }
  // const isValid = await verifyPayment(paymentProof, request.metadata.msg_sender);
  // if (!isValid) {
  //   return { error: 'Invalid payment proof' };
  // }
  // return data;  // Return raw data after payment verified

  // ============================================
  // EXAMPLE: Role-based access control
  // ============================================
  // import { getDatabase } from '../db';
  // const db = getDatabase();
  // const viewer = request.metadata.msg_sender;
  // const result = db.exec(
  //   `SELECT level FROM permissions WHERE address = ?`,
  //   [viewer]
  // );
  // const permission = result[0]?.values[0]?.[0] as string | undefined;
  //
  // if (!permission) {
  //   return { error: 'Not authorized' };
  // }
  // if (permission === 'full') return data;
  // if (permission === 'redacted') return redactPII(data);
  // return { error: 'Insufficient permissions' };

  // ============================================
  // EXAMPLE: Time-based access
  // ============================================
  // const timestamp = request.metadata.timestamp;
  // const dataTimestamp = (data as any)?.timestamp;
  // const ONE_HOUR = 3600;
  //
  // // Only allow access to data older than 1 hour for non-premium users
  // if (timestamp - dataTimestamp < ONE_HOUR) {
  //   const isPremium = await checkPremiumStatus(request.metadata.msg_sender);
  //   if (!isPremium) {
  //     return { error: 'Real-time data requires premium subscription' };
  //   }
  // }
  // return data;
}

/**
 * Optional: Redact PII from data.
 * Implement based on your data schema.
 */
export function redactPII(data: unknown): unknown {
  if (typeof data === 'object' && data !== null) {
    const clone = { ...data } as Record<string, unknown>;
    // Remove common PII fields
    delete clone.email;
    delete clone.phone;
    delete clone.ssn;
    delete clone.address;
    delete clone.ip;
    return clone;
  }
  return data;
}

/**
 * Optional: Check if sender has specific permission.
 * Implement based on your permission system.
 */
export async function hasPermission(
  _sender: string,
  _permission: string
): Promise<boolean> {
  // TODO: Implement your permission checking logic
  // Example: Query database for sender's permissions
  return true;
}
