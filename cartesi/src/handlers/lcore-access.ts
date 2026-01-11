/**
 * L{CORE} SDK - Access Grant Handlers
 *
 * Handles access grant creation, revocation, and verification.
 * This is the gated access layer that dApps use to control who can
 * decrypt private attestation data.
 */

import {
  AdvanceRequestData,
  RequestHandlerResult,
  InspectQuery,
} from '../router';
import {
  createAccessGrant,
  getAccessGrantById,
  checkAccess,
  revokeAccessGrant,
  getGrantsByAttestation,
  getGrantsByGrantee,
  getAttestationById,
  getAttestationData,
  AccessGrantInput,
} from '../lcore-db';

// ============= Advance Handlers =============

interface GrantAccessPayload {
  action: 'grant_access';
  grant_id: string;
  attestation_id: string;
  grantee_address: string;
  data_keys?: string[]; // null/undefined = all data
  grant_type: 'full' | 'partial' | 'aggregate';
  expires_at_input?: number;
}

/**
 * Grant access to attestation data
 * Only the attestation owner can grant access
 */
export const handleGrantAccess = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as GrantAccessPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  // Validate required fields
  if (!p.grant_id || !p.attestation_id || !p.grantee_address || !p.grant_type) {
    return {
      status: 'reject',
      response: { error: 'Missing required fields: grant_id, attestation_id, grantee_address, grant_type' },
    };
  }

  // Check attestation exists
  const attestation = getAttestationById(p.attestation_id);
  if (!attestation) {
    return {
      status: 'reject',
      response: { error: 'Attestation not found', attestation_id: p.attestation_id },
    };
  }

  // Only owner can grant access
  if (attestation.owner_address.toLowerCase() !== sender) {
    return {
      status: 'reject',
      response: { error: 'Only attestation owner can grant access' },
    };
  }

  // Check attestation is active
  if (attestation.status !== 'active') {
    return {
      status: 'reject',
      response: {
        error: 'Cannot grant access to non-active attestation',
        current_status: attestation.status,
      },
    };
  }

  // Check grant doesn't already exist
  const existingGrant = getAccessGrantById(p.grant_id);
  if (existingGrant) {
    return {
      status: 'reject',
      response: { error: 'Grant ID already exists', grant_id: p.grant_id },
    };
  }

  // Validate grant type
  if (!['full', 'partial', 'aggregate'].includes(p.grant_type)) {
    return {
      status: 'reject',
      response: { error: 'Invalid grant_type. Must be: full, partial, or aggregate' },
    };
  }

  // For partial grants, data_keys must be specified
  if (p.grant_type === 'partial' && (!p.data_keys || p.data_keys.length === 0)) {
    return {
      status: 'reject',
      response: { error: 'data_keys required for partial grant' },
    };
  }

  const grantInput: AccessGrantInput = {
    id: p.grant_id,
    attestation_id: p.attestation_id,
    grantee_address: p.grantee_address.toLowerCase(),
    granted_by: sender,
    data_keys: p.data_keys,
    grant_type: p.grant_type,
    granted_at_input: requestData.metadata.input_index,
    expires_at_input: p.expires_at_input,
  };

  try {
    const grant = createAccessGrant(grantInput);

    return {
      status: 'accept',
      response: {
        success: true,
        grant_id: grant.id,
        attestation_id: grant.attestation_id,
        grantee_address: grant.grantee_address,
        grant_type: grant.grant_type,
        data_keys: grant.data_keys ? JSON.parse(grant.data_keys) : null,
        expires_at_input: grant.expires_at_input,
      },
    };
  } catch (error) {
    return {
      status: 'reject',
      response: {
        error: 'Failed to create access grant',
        details: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

interface RevokeAccessPayload {
  action: 'revoke_access';
  grant_id: string;
}

/**
 * Revoke an access grant
 * Only the attestation owner (who granted) can revoke
 */
export const handleRevokeAccess = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as RevokeAccessPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  if (!p.grant_id) {
    return {
      status: 'reject',
      response: { error: 'grant_id required' },
    };
  }

  const grant = getAccessGrantById(p.grant_id);
  if (!grant) {
    return {
      status: 'reject',
      response: { error: 'Grant not found', grant_id: p.grant_id },
    };
  }

  // Only the grantor can revoke
  if (grant.granted_by.toLowerCase() !== sender) {
    return {
      status: 'reject',
      response: { error: 'Only grantor can revoke access' },
    };
  }

  if (grant.status !== 'active') {
    return {
      status: 'reject',
      response: {
        error: 'Grant is not active',
        current_status: grant.status,
      },
    };
  }

  const success = revokeAccessGrant(p.grant_id, requestData.metadata.input_index);

  return {
    status: success ? 'accept' : 'reject',
    response: {
      success,
      grant_id: p.grant_id,
      new_status: 'revoked',
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Check if address has access to attestation
 */
export const handleInspectCheckAccess = async (
  query: InspectQuery
): Promise<unknown> => {
  const { attestation_id, grantee, current_input, data_key } = query.params;

  if (!attestation_id || !grantee) {
    return { error: 'attestation_id and grantee parameters required' };
  }

  // Use provided current_input or default to 0 (for testing)
  const inputIndex = current_input ? parseInt(current_input, 10) : 0;

  const { hasAccess, grant } = checkAccess(
    attestation_id,
    grantee.toLowerCase(),
    inputIndex,
    data_key
  );

  return {
    attestation_id,
    grantee,
    has_access: hasAccess,
    grant: grant
      ? {
          id: grant.id,
          grant_type: grant.grant_type,
          data_keys: grant.data_keys ? JSON.parse(grant.data_keys) : null,
          expires_at_input: grant.expires_at_input,
        }
      : null,
  };
};

/**
 * Get access grant by ID
 */
export const handleInspectGrant = async (
  query: InspectQuery
): Promise<unknown> => {
  const { id } = query.params;

  if (!id) {
    return { error: 'id parameter required' };
  }

  const grant = getAccessGrantById(id);
  if (!grant) {
    return { error: 'Grant not found', grant_id: id };
  }

  return {
    grant: {
      id: grant.id,
      attestation_id: grant.attestation_id,
      grantee_address: grant.grantee_address,
      granted_by: grant.granted_by,
      grant_type: grant.grant_type,
      data_keys: grant.data_keys ? JSON.parse(grant.data_keys) : null,
      granted_at_input: grant.granted_at_input,
      expires_at_input: grant.expires_at_input,
      revoked_at_input: grant.revoked_at_input,
      status: grant.status,
    },
  };
};

/**
 * Get all grants for an attestation
 */
export const handleInspectGrantsByAttestation = async (
  query: InspectQuery
): Promise<unknown> => {
  const { attestation_id } = query.params;

  if (!attestation_id) {
    return { error: 'attestation_id parameter required' };
  }

  const grants = getGrantsByAttestation(attestation_id);

  return {
    attestation_id,
    count: grants.length,
    grants: grants.map(g => ({
      id: g.id,
      grantee_address: g.grantee_address,
      grant_type: g.grant_type,
      data_keys: g.data_keys ? JSON.parse(g.data_keys) : null,
      status: g.status,
      granted_at_input: g.granted_at_input,
      expires_at_input: g.expires_at_input,
    })),
  };
};

/**
 * Get all grants for a grantee
 */
export const handleInspectGrantsByGrantee = async (
  query: InspectQuery
): Promise<unknown> => {
  const { grantee, active_only } = query.params;

  if (!grantee) {
    return { error: 'grantee parameter required' };
  }

  const activeOnly = active_only !== 'false';
  const grants = getGrantsByGrantee(grantee.toLowerCase(), activeOnly);

  return {
    grantee,
    active_only: activeOnly,
    count: grants.length,
    grants: grants.map(g => ({
      id: g.id,
      attestation_id: g.attestation_id,
      granted_by: g.granted_by,
      grant_type: g.grant_type,
      data_keys: g.data_keys ? JSON.parse(g.data_keys) : null,
      status: g.status,
      granted_at_input: g.granted_at_input,
      expires_at_input: g.expires_at_input,
    })),
  };
};

/**
 * Get encrypted data with access verification
 * This is the gated endpoint - requires valid access grant
 */
export const handleInspectAttestationData = async (
  query: InspectQuery
): Promise<unknown> => {
  const { attestation_id, grantee, current_input, data_key } = query.params;

  if (!attestation_id || !grantee) {
    return { error: 'attestation_id and grantee parameters required' };
  }

  // Check attestation exists
  const attestation = getAttestationById(attestation_id);
  if (!attestation) {
    return { error: 'Attestation not found', attestation_id };
  }

  // Check access
  const inputIndex = current_input ? parseInt(current_input, 10) : 0;
  const { hasAccess, grant } = checkAccess(
    attestation_id,
    grantee.toLowerCase(),
    inputIndex,
    data_key
  );

  if (!hasAccess) {
    return {
      error: 'Access denied',
      attestation_id,
      grantee,
      reason: 'No valid access grant found',
    };
  }

  // Determine which data keys to return
  let allowedKeys: string[] | undefined;
  if (grant?.data_keys) {
    allowedKeys = JSON.parse(grant.data_keys) as string[];
  }

  // Get the encrypted data
  const data = getAttestationData(
    attestation_id,
    data_key ? [data_key] : allowedKeys
  );

  // Convert encrypted values to base64 for transport
  const dataForTransport = data.map(d => ({
    data_key: d.data_key,
    encrypted_value: uint8ArrayToBase64(d.encrypted_value),
    encryption_key_id: d.encryption_key_id,
  }));

  return {
    attestation_id,
    grantee,
    grant_id: grant?.id,
    grant_type: grant?.grant_type,
    data_count: dataForTransport.length,
    data: dataForTransport,
  };
};

// ============= Helpers =============

function uint8ArrayToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  // Fallback for browser
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}
