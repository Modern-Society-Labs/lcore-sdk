/**
 * Entity Handlers
 *
 * Handlers for core entity management (create, update, query).
 *
 * CUSTOMIZATION GUIDE:
 * 1. Modify Entity interface and payload types for your domain
 * 2. Add validation rules specific to your entity types
 * 3. Customize sanitization logic for response data
 */

import { AdvanceHandler, InspectHandler, InspectQuery, AdvanceRequestData } from '../router';
import {
  createEntity,
  getEntityById,
  getEntityByExternalId,
  updateEntityStatus,
  Entity,
  EntityInput,
} from '../db';

// ============= Payload Types =============

interface CreateEntityPayload {
  action: 'create_entity';
  id: string;
  external_id?: string;
  entity_type?: string;
  metadata?: Record<string, unknown>;
}

interface UpdateEntityPayload {
  action: 'update_entity';
  id: string;
  status?: string;
  metadata?: Record<string, unknown>;
}

// ============= Valid Status Values =============

const VALID_STATUSES = ['active', 'inactive', 'pending', 'suspended', 'completed'];

// ============= Sanitization =============

/**
 * Sanitize entity data for public response.
 * Removes sensitive information.
 *
 * CUSTOMIZE: Add fields to omit for your domain
 */
function sanitizeEntity(entity: Entity): Partial<Entity> {
  return {
    id: entity.id,
    external_id: entity.external_id,
    entity_type: entity.entity_type,
    status: entity.status,
    created_at: entity.created_at,
    updated_at: entity.updated_at,
    // metadata is intentionally omitted unless needed
  };
}

// ============= Advance Handlers =============

/**
 * Handle entity creation.
 */
export const handleCreateEntity: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { id, external_id, entity_type, metadata } = payload as CreateEntityPayload;

  // Validate ID
  if (!id || typeof id !== 'string') {
    throw new Error('Valid id is required');
  }

  // Validate ID format (CUSTOMIZE: adjust for your ID format)
  if (id.length > 100) {
    throw new Error('ID exceeds maximum length');
  }

  // Check if entity already exists
  const existing = getEntityById(id);
  if (existing) {
    return {
      status: 'accept',
      response: {
        action: 'create_entity',
        success: true,
        entity: sanitizeEntity(existing),
        message: 'Entity already exists',
      },
    };
  }

  // Create new entity
  const entity = createEntity({
    id,
    external_id,
    entity_type,
    metadata,
  });

  console.log(`Entity created: ${id}`);

  return {
    status: 'accept',
    response: {
      action: 'create_entity',
      success: true,
      entity: sanitizeEntity(entity),
    },
  };
};

/**
 * Handle entity update.
 */
export const handleUpdateEntity: AdvanceHandler = async (
  data: AdvanceRequestData,
  payload: unknown
) => {
  const { id, status } = payload as UpdateEntityPayload;

  // Validate ID
  if (!id || typeof id !== 'string') {
    throw new Error('Valid id is required');
  }

  // Check if entity exists
  const entity = getEntityById(id);
  if (!entity) {
    throw new Error('Entity not found');
  }

  // Validate status if provided
  if (status) {
    if (!VALID_STATUSES.includes(status)) {
      throw new Error(`Invalid status. Must be one of: ${VALID_STATUSES.join(', ')}`);
    }
    updateEntityStatus(id, status);
  }

  console.log(`Entity updated: ${id}`);

  // Get updated entity
  const updated = getEntityById(id)!;

  return {
    status: 'accept',
    response: {
      action: 'update_entity',
      success: true,
      entity: sanitizeEntity(updated),
    },
  };
};

// ============= Inspect Handlers =============

/**
 * Handle inspect query for entity data.
 */
export const handleInspectEntity: InspectHandler = async (query: InspectQuery) => {
  const { params } = query;

  // Get entity by ID
  if (params.id) {
    const entity = getEntityById(params.id);
    if (!entity) {
      return { error: 'Entity not found', id: params.id };
    }
    return { entity: sanitizeEntity(entity) };
  }

  // Get entity by external ID
  if (params.external_id) {
    const entity = getEntityByExternalId(params.external_id);
    if (!entity) {
      return { error: 'Entity not found', external_id: params.external_id };
    }
    return { entity: sanitizeEntity(entity) };
  }

  return { error: 'ID or external_id parameter required' };
};
