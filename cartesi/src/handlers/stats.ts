/**
 * Stats Handlers
 *
 * Handlers for database statistics and aggregations.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Add domain-specific statistics
 * 2. Implement caching if stats queries are expensive
 */

import { InspectHandler, InspectQuery } from '../router';
import { getDatabaseStats } from '../db';

// ============= Inspect Handlers =============

/**
 * Handle inspect query for database statistics.
 * Provides aggregate data safe for public viewing.
 */
export const handleInspectStats: InspectHandler = async (query: InspectQuery) => {
  const stats = getDatabaseStats();

  return {
    statistics: {
      total_entities: stats.total_entities,
      total_records: stats.total_records,
      total_computations: stats.total_computations,
      entities_by_status: stats.entities_by_status,
      records_by_source: stats.records_by_source,
    },
    timestamp: new Date().toISOString(),
  };
};
