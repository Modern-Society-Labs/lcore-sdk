/**
 * Voucher Generator Utility
 *
 * Generates vouchers for L1 contract interactions from the Cartesi rollup.
 * Vouchers are used to trigger state changes on L1 (withdrawals, governance execution, etc.)
 */

import { getConfig } from '../config';

// ============= Types =============

export interface VoucherRequest {
  destination: string;      // L1 contract address
  payload: string;          // Hex-encoded calldata
}

export interface VoucherResult {
  success: boolean;
  voucherIndex?: number;
  error?: string;
}

// Pending vouchers for batch submission
const pendingVouchers: VoucherRequest[] = [];

// ============= ABI Encoding Helpers =============

/**
 * Encode a uint256 value as 32-byte hex
 */
export function encodeUint256(value: bigint): string {
  return value.toString(16).padStart(64, '0');
}

/**
 * Encode an address as 32-byte hex (left-padded)
 */
export function encodeAddress(address: string): string {
  const clean = address.toLowerCase().replace('0x', '');
  return clean.padStart(64, '0');
}

/**
 * Encode a bytes32 value
 */
export function encodeBytes32(value: string): string {
  const clean = value.replace('0x', '');
  return clean.padEnd(64, '0');
}

/**
 * Calculate function selector (first 4 bytes of keccak256)
 */
export function functionSelector(signature: string): string {
  // Simple hash implementation for common functions
  // In production, use proper keccak256
  const common: Record<string, string> = {
    'transfer(address,uint256)': 'a9059cbb',
    'approve(address,uint256)': '095ea7b3',
    'transferFrom(address,address,uint256)': '23b872dd',
    'mint(address,uint256)': '40c10f19',
    'burn(address,uint256)': '9dc29fac',
    'withdraw(address,uint256)': 'f3fef3a3',
    'execute(bytes32)': '4b64e492',
    'executeProposal(uint256)': '0d61b519',
  };

  return common[signature] || '00000000';
}

/**
 * Encode a function call with parameters
 */
export function encodeFunctionCall(
  signature: string,
  params: Array<{ type: 'address' | 'uint256' | 'bytes32'; value: string | bigint }>
): string {
  let encoded = '0x' + functionSelector(signature);

  for (const param of params) {
    switch (param.type) {
      case 'address':
        encoded += encodeAddress(param.value as string);
        break;
      case 'uint256':
        encoded += encodeUint256(BigInt(param.value));
        break;
      case 'bytes32':
        encoded += encodeBytes32(param.value as string);
        break;
    }
  }

  return encoded;
}

// ============= Voucher Generation =============

/**
 * Send a voucher to the rollup server
 */
export async function sendVoucher(request: VoucherRequest): Promise<VoucherResult> {
  const config = getConfig();
  const rollupServer = config.rollupHttpServerUrl || process.env.ROLLUP_HTTP_SERVER_URL;

  if (!rollupServer) {
    return { success: false, error: 'Rollup server URL not configured' };
  }

  try {
    const response = await fetch(`${rollupServer}/voucher`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        destination: request.destination,
        payload: request.payload,
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      return { success: false, error: `Voucher submission failed: ${text}` };
    }

    const result = await response.json() as { index?: number };
    return { success: true, voucherIndex: result.index };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Queue a voucher for batch submission
 */
export function queueVoucher(request: VoucherRequest): void {
  pendingVouchers.push(request);
}

/**
 * Send all queued vouchers
 */
export async function flushVouchers(): Promise<VoucherResult[]> {
  const results: VoucherResult[] = [];

  while (pendingVouchers.length > 0) {
    const voucher = pendingVouchers.shift()!;
    const result = await sendVoucher(voucher);
    results.push(result);
  }

  return results;
}

/**
 * Get count of pending vouchers
 */
export function getPendingVoucherCount(): number {
  return pendingVouchers.length;
}

// ============= Common Voucher Patterns =============

/**
 * Generate voucher for ERC-20 transfer on L1
 */
export async function generateTokenTransferVoucher(
  tokenContract: string,
  recipient: string,
  amount: bigint
): Promise<VoucherResult> {
  const payload = encodeFunctionCall('transfer(address,uint256)', [
    { type: 'address', value: recipient },
    { type: 'uint256', value: amount },
  ]);

  return sendVoucher({ destination: tokenContract, payload });
}

/**
 * Generate voucher for withdrawal from rollup portal
 */
export async function generateWithdrawVoucher(
  portalContract: string,
  recipient: string,
  tokenContract: string,
  amount: bigint
): Promise<VoucherResult> {
  const payload = encodeFunctionCall('withdraw(address,uint256)', [
    { type: 'address', value: recipient },
    { type: 'uint256', value: amount },
  ]);

  return sendVoucher({ destination: portalContract, payload });
}

/**
 * Generate voucher for governance proposal execution
 */
export async function generateExecuteProposalVoucher(
  governanceContract: string,
  proposalId: bigint
): Promise<VoucherResult> {
  const payload = encodeFunctionCall('executeProposal(uint256)', [
    { type: 'uint256', value: proposalId },
  ]);

  return sendVoucher({ destination: governanceContract, payload });
}

// ============= Voucher Verification =============

export interface VoucherMetadata {
  destination: string;
  payload: string;
  createdAtInput: number;
  status: 'pending' | 'executed' | 'failed';
}

const voucherHistory: VoucherMetadata[] = [];

/**
 * Record voucher for tracking
 */
export function recordVoucher(
  destination: string,
  payload: string,
  inputIndex: number
): void {
  voucherHistory.push({
    destination,
    payload,
    createdAtInput: inputIndex,
    status: 'pending',
  });
}

/**
 * Get voucher history
 */
export function getVoucherHistory(limit = 100): VoucherMetadata[] {
  return voucherHistory.slice(-limit);
}
