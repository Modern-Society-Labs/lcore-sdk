/**
 * Computation Handlers
 *
 * Handlers for derived calculations based on stored data.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Implement your computation logic in performComputation()
 * 2. Add new computation types as needed
 * 3. Customize threshold checks for your domain
 */

import { createHash } from 'crypto';
import { AdvanceHandler, InspectHandler, InspectQuery, AdvanceRequestData } from '../router';
import {
  getEntityById,
  getDataRecordsForComputation,
  saveComputation,
  getComputationHistory,
  updateEntityStatus,
  createPendingApproval,
  DataRecord,
} from '../db';
import { getDefaultThreshold, requireApproval, getComputationLookbackMonths } from '../config';

// ============= Payload Types =============

interface ComputePayload {
  action: 'compute';
  entity_id: string;
  computation_type: string;
  source_type: string;
  params?: {
    threshold?: number;
    lookback_months?: number;
  };
}

// ============= Computation Types =============

/**
 * Supported computation types.
 * CUSTOMIZE: Add your computation types here
 */
const COMPUTATION_TYPES = ['aggregate', 'average', 'trend', 'ratio', 'custom'];

// ============= Computation Logic =============

/**
 * Perform computation on data records.
 * CUSTOMIZE: Implement your computation logic here
 */
function performComputation(
  records: DataRecord[],
  computationType: string,
  params: { threshold?: number; lookback_months?: number }
): {
  resultValue: number;
  secondaryValue?: number;
  meetsThreshold: boolean;
} {
  const threshold = params.threshold || getDefaultThreshold();

  switch (computationType) {
    case 'aggregate': {
      // Sum all amounts
      const total = records.reduce((sum, r) => sum + (r.amount || 0), 0);
      return {
        resultValue: total,
        meetsThreshold: total >= threshold,
      };
    }

    case 'average': {
      // Average of amounts
      const total = records.reduce((sum, r) => sum + (r.amount || 0), 0);
      const avg = records.length > 0 ? total / records.length : 0;
      return {
        resultValue: avg,
        secondaryValue: records.length,
        meetsThreshold: avg >= threshold,
      };
    }

    case 'trend': {
      // Calculate trend (simplified: last half vs first half)
      if (records.length < 2) {
        return { resultValue: 0, meetsThreshold: false };
      }

      const midpoint = Math.floor(records.length / 2);
      const firstHalf = records.slice(0, midpoint);
      const secondHalf = records.slice(midpoint);

      const firstSum = firstHalf.reduce((sum, r) => sum + (r.amount || 0), 0);
      const secondSum = secondHalf.reduce((sum, r) => sum + (r.amount || 0), 0);

      const firstAvg = firstHalf.length > 0 ? firstSum / firstHalf.length : 0;
      const secondAvg = secondHalf.length > 0 ? secondSum / secondHalf.length : 0;

      const trend = firstAvg !== 0 ? (secondAvg - firstAvg) / firstAvg : 0;

      return {
        resultValue: trend,
        secondaryValue: secondAvg - firstAvg,
        meetsThreshold: trend >= 0, // Positive trend
      };
    }

    case 'ratio': {
      // Calculate ratio (e.g., income to expense)
      // Group by record_type and calculate ratio
      const byType: Record<string, number> = {};
      for (const r of records) {
        byType[r.record_type] = (byType[r.record_type] || 0) + (r.amount || 0);
      }

      // Assume 'income' and 'expense' types
      const income = byType['income'] || 0;
      const expense = Math.abs(byType['expense'] || 0);

      const ratio = expense !== 0 ? income / expense : income > 0 ? Infinity : 0;

      return {
        resultValue: ratio,
        secondaryValue: income - expense,
        meetsThreshold: ratio >= threshold,
      };
    }

    case 'custom':
    default: {
      // Default: simple count
      return {
        resultValue: records.length,
        meetsThreshold: records.length >= threshold,
      };
    }
  }
}

/**
 * Create hash of inputs for verification.
 */
function hashInputs(records: DataRecord[], entityId: string): string {
  const data = JSON.stringify({
    entityId,
    records: records.map(r => ({
      id: r.id,
      amount: r.amount,
      timestamp: r.timestamp,
    })),
  });
  return createHash('sha256').update(data).digest('hex');
}

// ============= Advance Handlers =============

/**
 * Handle computation request.
 */
export const handleCompute: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { entity_id, computation_type, source_type, params = {} } = payload as ComputePayload;

  // Validate entity ID
  if (!entity_id || typeof entity_id !== 'string') {
    throw new Error('Valid entity_id is required');
  }

  // Validate computation type
  if (!computation_type || typeof computation_type !== 'string') {
    throw new Error('Valid computation_type is required');
  }

  if (!COMPUTATION_TYPES.includes(computation_type)) {
    throw new Error(`Unknown computation_type. Must be one of: ${COMPUTATION_TYPES.join(', ')}`);
  }

  // Validate source type
  if (!source_type || typeof source_type !== 'string') {
    throw new Error('Valid source_type is required');
  }

  // Get entity
  const entity = getEntityById(entity_id);
  if (!entity) {
    throw new Error(`Entity not found: ${entity_id}`);
  }

  // Get records for computation
  const lookbackMonths = params.lookback_months || getComputationLookbackMonths();
  const records = getDataRecordsForComputation(entity_id, source_type, lookbackMonths);

  if (records.length === 0) {
    throw new Error(`No ${source_type} records available for computation`);
  }

  // Perform computation
  const result = performComputation(records, computation_type, params);
  const threshold = params.threshold || getDefaultThreshold();

  // Create input hash for verification
  const inputHash = hashInputs(records, entity_id);

  // Save computation result
  const computation = saveComputation(
    entity_id,
    computation_type,
    result.resultValue,
    result.secondaryValue,
    inputHash
  );

  // Determine if status change requires approval
  const needsApproval = requireApproval();
  let pendingApprovalId: number | null = null;

  if (needsApproval && result.meetsThreshold) {
    // Create pending approval for status change
    const approval = createPendingApproval(
      entity_id,
      'status_change',
      entity.status,
      'approved',
      `${computation_type}: ${result.resultValue.toFixed(4)}`,
      'system'
    );
    pendingApprovalId = approval.id;

    // Update entity to pending approval state
    updateEntityStatus(entity_id, 'pending_approval');

    console.log(
      `Computation completed for ${entity_id}: ${result.resultValue.toFixed(4)}, awaiting approval`
    );
  } else {
    // Apply status change immediately
    const newStatus = result.meetsThreshold ? 'approved' : 'pending';
    updateEntityStatus(entity_id, newStatus);

    console.log(
      `Computation completed for ${entity_id}: ${result.resultValue.toFixed(4)}, status: ${newStatus}`
    );
  }

  return {
    status: 'accept',
    response: {
      action: 'compute',
      success: true,
      entity_id,
      computation_type,
      result_value: result.resultValue.toFixed(4),
      secondary_value: result.secondaryValue?.toFixed(4) || null,
      threshold,
      meets_threshold: result.meetsThreshold,
      records_used: records.length,
      input_hash: inputHash,
      pending_approval_id: pendingApprovalId,
      requires_approval: needsApproval && result.meetsThreshold,
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Handle inspect query for computation history.
 */
export const handleInspectComputation: InspectHandler = async (query: InspectQuery) => {
  const { params } = query;

  if (!params.entity_id) {
    return { error: 'entity_id parameter required' };
  }

  const entity = getEntityById(params.entity_id);
  if (!entity) {
    return { error: 'Entity not found', entity_id: params.entity_id };
  }

  // Get computation history
  const history = getComputationHistory(params.entity_id, params.computation_type);

  return {
    entity_id: params.entity_id,
    entity_status: entity.status,
    computation_count: history.length,
    computations: history.map(c => ({
      id: c.id,
      computation_type: c.computation_type,
      result_value: c.result_value?.toFixed(4) || null,
      secondary_value: c.secondary_value?.toFixed(4) || null,
      input_hash: c.input_hash,
      computed_at: c.computed_at,
    })),
  };
};
