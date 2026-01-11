/**
 * Approval Handlers
 *
 * Handlers for the approval workflow (approve/reject pending changes).
 *
 * CUSTOMIZATION GUIDE:
 * 1. Add approval type-specific logic in handleApprove/handleReject
 * 2. Implement side effects when approvals are processed
 * 3. Add authorization checks for who can approve
 */

import { AdvanceHandler, InspectHandler, InspectQuery, AdvanceRequestData } from '../router';
import {
  getPendingApprovals,
  resolveApproval,
  getEntityById,
  updateEntityStatus,
  PendingApproval,
} from '../db';

// ============= Payload Types =============

interface ApprovalPayload {
  action: 'approve' | 'reject';
  approval_id: number;
  approved_by: string;
  reason?: string;
}

// ============= Side Effects =============

/**
 * Apply side effects when an approval is processed.
 * CUSTOMIZE: Add logic for different approval types
 */
function applyApprovalSideEffects(
  approval: PendingApproval,
  approved: boolean
): void {
  switch (approval.approval_type) {
    case 'status_change':
      if (approved) {
        // Apply the proposed status change
        updateEntityStatus(approval.entity_id, approval.proposed_value);
      } else {
        // Revert to original status or set to rejected
        const originalStatus = approval.current_value || 'pending';
        updateEntityStatus(approval.entity_id, originalStatus);
      }
      break;

    case 'rate_change':
      if (approved) {
        // Apply rate change - implement specific logic
        console.log(`Rate change approved for ${approval.entity_id}: ${approval.proposed_value}`);
      }
      break;

    case 'custom':
      // Custom approval types - implement specific logic
      break;

    default:
      console.log(`Unknown approval type: ${approval.approval_type}`);
  }
}

// ============= Advance Handlers =============

/**
 * Handle approval of a pending change.
 */
export const handleApprove: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { approval_id, approved_by, reason } = payload as ApprovalPayload;

  // Validate approval ID
  if (!approval_id || typeof approval_id !== 'number') {
    throw new Error('Valid approval_id is required');
  }

  // Validate approver
  if (!approved_by || typeof approved_by !== 'string') {
    throw new Error('approved_by is required');
  }

  // Get pending approvals to find the one we're approving
  const allPending = getPendingApprovals();
  const pendingApproval = allPending.find(a => a.id === approval_id);

  if (!pendingApproval) {
    throw new Error(`Approval ${approval_id} not found or already resolved`);
  }

  // Resolve the approval
  const success = resolveApproval(approval_id, true, approved_by);

  if (!success) {
    throw new Error(`Failed to approve ${approval_id}`);
  }

  // Apply side effects
  applyApprovalSideEffects(pendingApproval, true);

  console.log(`Approval ${approval_id} approved by ${approved_by}`);

  return {
    status: 'accept',
    response: {
      action: 'approve',
      success: true,
      approval_id,
      approved_by,
      entity_id: pendingApproval.entity_id,
      approval_type: pendingApproval.approval_type,
      applied_value: pendingApproval.proposed_value,
    },
  };
};

/**
 * Handle rejection of a pending change.
 */
export const handleReject: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { approval_id, approved_by, reason } = payload as ApprovalPayload;

  // Validate approval ID
  if (!approval_id || typeof approval_id !== 'number') {
    throw new Error('Valid approval_id is required');
  }

  // Validate rejector
  if (!approved_by || typeof approved_by !== 'string') {
    throw new Error('approved_by (rejector) is required');
  }

  // Get pending approvals to find the one we're rejecting
  const allPending = getPendingApprovals();
  const pendingApproval = allPending.find(a => a.id === approval_id);

  if (!pendingApproval) {
    throw new Error(`Approval ${approval_id} not found or already resolved`);
  }

  // Resolve the approval (rejected)
  const success = resolveApproval(approval_id, false, approved_by);

  if (!success) {
    throw new Error(`Failed to reject ${approval_id}`);
  }

  // Apply side effects (revert)
  applyApprovalSideEffects(pendingApproval, false);

  console.log(`Approval ${approval_id} rejected by ${approved_by}`);

  return {
    status: 'accept',
    response: {
      action: 'reject',
      success: true,
      approval_id,
      rejected_by: approved_by,
      entity_id: pendingApproval.entity_id,
      approval_type: pendingApproval.approval_type,
      reason,
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Handle inspect query for pending approvals.
 */
export const handleInspectApprovals: InspectHandler = async (query: InspectQuery) => {
  const { params } = query;

  // Get pending approvals, optionally filtered
  const pendingApprovals = getPendingApprovals(
    params.entity_id,
    params.approval_type
  );

  return {
    filter: {
      entity_id: params.entity_id || 'all',
      approval_type: params.approval_type || 'all',
    },
    pending_count: pendingApprovals.length,
    approvals: pendingApprovals.map(a => ({
      id: a.id,
      entity_id: a.entity_id,
      approval_type: a.approval_type,
      current_value: a.current_value,
      proposed_value: a.proposed_value,
      reason: a.reason,
      requested_by: a.requested_by,
      created_at: a.created_at,
    })),
  };
};
