/**
 * Handler Exports
 *
 * This module aggregates all handler exports for clean imports.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Add new handler files for each domain area
 * 2. Export all handlers from this file
 * 3. Keep related handlers grouped together
 */

// Entity handlers - Core entity management
export {
  handleCreateEntity,
  handleUpdateEntity,
  handleInspectEntity,
} from './entity';

// Data handlers - External data sync
export {
  handleSyncData,
  handleInspectData,
} from './data-source';

// Computation handlers - Derived calculations
export {
  handleCompute,
  handleInspectComputation,
} from './computation';

// Proof handlers - Data verification
export {
  handleSubmitProof,
  handleInspectProof,
} from './proof';

// Approval handlers - Approval workflow
export {
  handleApprove,
  handleReject,
  handleInspectApprovals,
} from './approval';

// Stats handlers - Aggregation and statistics
export { handleInspectStats } from './stats';
