/**
 * L{CORE} SDK - Provider Schema Handlers
 *
 * Handles provider schema registration and admin management.
 * This is the modular extension system that allows authorized wallets
 * to add new data types without schema migrations.
 */

import {
  AdvanceRequestData,
  RequestHandlerResult,
  InspectQuery,
} from '../router';
import {
  registerProviderSchema,
  getProviderSchema,
  getAllProviderSchemas,
  deprecateProviderSchema,
  addSchemaAdmin,
  removeSchemaAdmin,
  isSchemaAdmin,
  canAddProviders,
  canAddAdmins,
  getAllSchemaAdmins,
  getSchemaAdmin,
  ProviderSchemaInput,
} from '../lcore-db';

// ============= Advance Handlers =============

interface RegisterProviderSchemaPayload {
  action: 'register_provider_schema';
  provider: string;
  flow_type: string;
  domain: string;
  bucket_definitions: Record<string, {
    boundaries: number[];
    labels: string[];
  }>;
  data_keys: string[];
  freshness_half_life: number;
  min_freshness?: number;
}

/**
 * Register a new provider schema
 * Only schema admins with can_add_providers permission
 */
export const handleRegisterProviderSchema = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as RegisterProviderSchemaPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  // Validate required fields
  if (!p.provider || !p.flow_type || !p.domain || !p.bucket_definitions || !p.data_keys || !p.freshness_half_life) {
    return {
      status: 'reject',
      response: {
        error: 'Missing required fields: provider, flow_type, domain, bucket_definitions, data_keys, freshness_half_life',
      },
    };
  }

  // Check authorization
  if (!isSchemaAdmin(sender)) {
    return {
      status: 'reject',
      response: { error: 'Not authorized. Must be schema admin.' },
    };
  }

  if (!canAddProviders(sender)) {
    return {
      status: 'reject',
      response: { error: 'Admin does not have permission to add providers' },
    };
  }

  // Validate bucket definitions
  for (const [key, def] of Object.entries(p.bucket_definitions)) {
    if (!def.boundaries || !def.labels) {
      return {
        status: 'reject',
        response: {
          error: `Invalid bucket definition for key '${key}': must have boundaries and labels`,
        },
      };
    }
    if (def.boundaries.length !== def.labels.length + 1) {
      return {
        status: 'reject',
        response: {
          error: `Invalid bucket definition for key '${key}': boundaries length must be labels length + 1`,
        },
      };
    }
  }

  // Validate data_keys
  if (!Array.isArray(p.data_keys) || p.data_keys.length === 0) {
    return {
      status: 'reject',
      response: { error: 'data_keys must be a non-empty array' },
    };
  }

  // Validate freshness_half_life
  if (p.freshness_half_life <= 0) {
    return {
      status: 'reject',
      response: { error: 'freshness_half_life must be positive' },
    };
  }

  const schemaInput: ProviderSchemaInput = {
    provider: p.provider.toLowerCase(),
    flow_type: p.flow_type.toLowerCase(),
    domain: p.domain.toLowerCase(),
    registered_by: sender,
    registered_at_input: requestData.metadata.input_index,
    bucket_definitions: p.bucket_definitions,
    data_keys: p.data_keys,
    freshness_half_life: p.freshness_half_life,
    min_freshness: p.min_freshness,
  };

  try {
    const schema = registerProviderSchema(schemaInput);

    return {
      status: 'accept',
      response: {
        success: true,
        provider: schema.provider,
        flow_type: schema.flow_type,
        domain: schema.domain,
        version: schema.version,
        bucket_keys: Object.keys(p.bucket_definitions),
        data_keys: p.data_keys,
        freshness_half_life: schema.freshness_half_life,
      },
    };
  } catch (error) {
    return {
      status: 'reject',
      response: {
        error: 'Failed to register provider schema',
        details: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

interface DeprecateProviderSchemaPayload {
  action: 'deprecate_provider_schema';
  provider: string;
  flow_type: string;
  version: number;
}

/**
 * Deprecate a provider schema version
 */
export const handleDeprecateProviderSchema = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as DeprecateProviderSchemaPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  if (!p.provider || !p.flow_type || p.version === undefined) {
    return {
      status: 'reject',
      response: { error: 'provider, flow_type, and version required' },
    };
  }

  // Check authorization
  if (!isSchemaAdmin(sender)) {
    return {
      status: 'reject',
      response: { error: 'Not authorized. Must be schema admin.' },
    };
  }

  if (!canAddProviders(sender)) {
    return {
      status: 'reject',
      response: { error: 'Admin does not have permission to modify providers' },
    };
  }

  const success = deprecateProviderSchema(
    p.provider.toLowerCase(),
    p.flow_type.toLowerCase(),
    p.version
  );

  return {
    status: success ? 'accept' : 'reject',
    response: {
      success,
      provider: p.provider,
      flow_type: p.flow_type,
      version: p.version,
      new_status: 'deprecated',
    },
  };
};

interface AddSchemaAdminPayload {
  action: 'add_schema_admin';
  wallet_address: string;
  can_add_providers?: boolean;
  can_add_admins?: boolean;
}

/**
 * Add a schema admin
 * Only existing admins with can_add_admins permission
 */
export const handleAddSchemaAdmin = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as AddSchemaAdminPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  if (!p.wallet_address) {
    return {
      status: 'reject',
      response: { error: 'wallet_address required' },
    };
  }

  // Special case: if no admins exist, allow first admin to be added
  const allAdmins = getAllSchemaAdmins();
  if (allAdmins.length === 0) {
    // Bootstrap: first admin gets full permissions
    const admin = addSchemaAdmin(
      p.wallet_address.toLowerCase(),
      'system',
      requestData.metadata.input_index,
      true, // can_add_providers
      true  // can_add_admins
    );

    return {
      status: 'accept',
      response: {
        success: true,
        bootstrap: true,
        wallet_address: admin.wallet_address,
        can_add_providers: admin.can_add_providers,
        can_add_admins: admin.can_add_admins,
      },
    };
  }

  // Check authorization
  if (!isSchemaAdmin(sender)) {
    return {
      status: 'reject',
      response: { error: 'Not authorized. Must be schema admin.' },
    };
  }

  if (!canAddAdmins(sender)) {
    return {
      status: 'reject',
      response: { error: 'Admin does not have permission to add admins' },
    };
  }

  try {
    const admin = addSchemaAdmin(
      p.wallet_address.toLowerCase(),
      sender,
      requestData.metadata.input_index,
      p.can_add_providers ?? true,
      p.can_add_admins ?? false
    );

    return {
      status: 'accept',
      response: {
        success: true,
        wallet_address: admin.wallet_address,
        added_by: admin.added_by,
        can_add_providers: admin.can_add_providers,
        can_add_admins: admin.can_add_admins,
      },
    };
  } catch (error) {
    return {
      status: 'reject',
      response: {
        error: 'Failed to add schema admin',
        details: error instanceof Error ? error.message : String(error),
      },
    };
  }
};

interface RemoveSchemaAdminPayload {
  action: 'remove_schema_admin';
  wallet_address: string;
}

/**
 * Remove a schema admin
 */
export const handleRemoveSchemaAdmin = async (
  requestData: AdvanceRequestData,
  payload: unknown
): Promise<{ status: RequestHandlerResult; response?: unknown }> => {
  const p = payload as RemoveSchemaAdminPayload;
  const sender = requestData.metadata.msg_sender.toLowerCase();

  if (!p.wallet_address) {
    return {
      status: 'reject',
      response: { error: 'wallet_address required' },
    };
  }

  // Check authorization
  if (!isSchemaAdmin(sender)) {
    return {
      status: 'reject',
      response: { error: 'Not authorized. Must be schema admin.' },
    };
  }

  if (!canAddAdmins(sender)) {
    return {
      status: 'reject',
      response: { error: 'Admin does not have permission to remove admins' },
    };
  }

  // Prevent removing self if you're the last admin with can_add_admins
  const targetAddress = p.wallet_address.toLowerCase();
  if (targetAddress === sender) {
    const adminsWithAddPermission = getAllSchemaAdmins().filter(a => a.can_add_admins);
    if (adminsWithAddPermission.length <= 1) {
      return {
        status: 'reject',
        response: { error: 'Cannot remove yourself as the last admin with add permissions' },
      };
    }
  }

  const success = removeSchemaAdmin(targetAddress);

  return {
    status: success ? 'accept' : 'reject',
    response: {
      success,
      wallet_address: targetAddress,
      removed: success,
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Get provider schema
 */
export const handleInspectProviderSchema = async (
  query: InspectQuery
): Promise<unknown> => {
  const { provider, flow_type } = query.params;

  if (!provider || !flow_type) {
    return { error: 'provider and flow_type parameters required' };
  }

  const schema = getProviderSchema(provider.toLowerCase(), flow_type.toLowerCase());
  if (!schema) {
    return {
      error: 'Schema not found',
      provider,
      flow_type,
    };
  }

  return {
    schema: {
      provider: schema.provider,
      flow_type: schema.flow_type,
      domain: schema.domain,
      version: schema.version,
      bucket_definitions: JSON.parse(schema.bucket_definitions),
      data_keys: JSON.parse(schema.data_keys),
      freshness_half_life: schema.freshness_half_life,
      min_freshness: schema.min_freshness,
      registered_by: schema.registered_by,
      registered_at_input: schema.registered_at_input,
      status: schema.status,
    },
  };
};

/**
 * Get all provider schemas
 */
export const handleInspectAllProviderSchemas = async (
  query: InspectQuery
): Promise<unknown> => {
  const { active_only, domain } = query.params;

  const activeOnly = active_only !== 'false';
  let schemas = getAllProviderSchemas(activeOnly);

  // Filter by domain if specified
  if (domain) {
    schemas = schemas.filter(s => s.domain === domain.toLowerCase());
  }

  return {
    count: schemas.length,
    schemas: schemas.map(s => ({
      provider: s.provider,
      flow_type: s.flow_type,
      domain: s.domain,
      version: s.version,
      freshness_half_life: s.freshness_half_life,
      status: s.status,
    })),
  };
};

/**
 * Get schema admin info
 */
export const handleInspectSchemaAdmin = async (
  query: InspectQuery
): Promise<unknown> => {
  const { wallet } = query.params;

  if (!wallet) {
    return { error: 'wallet parameter required' };
  }

  const admin = getSchemaAdmin(wallet.toLowerCase());
  if (!admin) {
    return {
      is_admin: false,
      wallet,
    };
  }

  return {
    is_admin: true,
    wallet: admin.wallet_address,
    added_by: admin.added_by,
    added_at_input: admin.added_at_input,
    can_add_providers: admin.can_add_providers,
    can_add_admins: admin.can_add_admins,
  };
};

/**
 * Get all schema admins
 */
export const handleInspectAllSchemaAdmins = async (
  _query: InspectQuery
): Promise<unknown> => {
  const admins = getAllSchemaAdmins();

  return {
    count: admins.length,
    admins: admins.map(a => ({
      wallet_address: a.wallet_address,
      added_by: a.added_by,
      can_add_providers: a.can_add_providers,
      can_add_admins: a.can_add_admins,
    })),
  };
};
