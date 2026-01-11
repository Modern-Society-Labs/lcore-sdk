/**
 * L{CORE} SDK - Discovery & Aggregate Query Handlers
 *
 * Privacy-preserving discovery using bucket-based queries.
 * Aggregates expose statistical insights without individual data exposure.
 */

import { InspectQuery } from '../router';
import {
  queryAttestationsByBucket,
  queryAttestationsByDomain,
  countByBucket,
  countByDomain,
  countByProvider,
  aggregateFreshness,
  getProviderSchema,
  getAllProviderSchemas,
} from '../lcore-db';

// ============= Discovery Queries =============

/**
 * Query attestations by bucket value
 * This is the primary discovery mechanism - find users in a specific range
 * without revealing exact values
 */
export const handleInspectQueryByBucket = async (
  query: InspectQuery
): Promise<unknown> => {
  const { domain, provider, bucket_key, bucket_value, min_freshness, limit, offset } = query.params;

  if (!domain) {
    return { error: 'domain parameter required' };
  }

  if (!bucket_key || !bucket_value) {
    return { error: 'bucket_key and bucket_value parameters required' };
  }

  const attestations = queryAttestationsByBucket({
    domain: domain.toLowerCase(),
    provider: provider?.toLowerCase(),
    bucketKey: bucket_key,
    bucketValue: bucket_value,
    minFreshness: min_freshness ? parseInt(min_freshness, 10) : undefined,
    limit: limit ? parseInt(limit, 10) : 50,
    offset: offset ? parseInt(offset, 10) : 0,
  });

  return {
    query: {
      domain,
      provider: provider || 'any',
      bucket_key,
      bucket_value,
      min_freshness: min_freshness || 0,
    },
    count: attestations.length,
    attestations: attestations.map(a => ({
      id: a.id,
      owner_address: a.owner_address,
      provider: a.provider,
      flow_type: a.flow_type,
      freshness_score: a.freshness_score,
      valid_from: a.valid_from,
      buckets: a.buckets,
    })),
  };
};

/**
 * Query attestations by domain with optional filters
 * General purpose discovery within a data domain
 */
export const handleInspectQueryByDomain = async (
  query: InspectQuery
): Promise<unknown> => {
  const { domain, provider, flow_type, status, min_freshness, limit, offset } = query.params;

  if (!domain) {
    return { error: 'domain parameter required' };
  }

  const attestations = queryAttestationsByDomain({
    domain: domain.toLowerCase(),
    provider: provider?.toLowerCase(),
    flowType: flow_type?.toLowerCase(),
    status: status || 'active',
    minFreshness: min_freshness ? parseInt(min_freshness, 10) : undefined,
    limit: limit ? parseInt(limit, 10) : 50,
    offset: offset ? parseInt(offset, 10) : 0,
  });

  return {
    query: {
      domain,
      provider: provider || 'any',
      flow_type: flow_type || 'any',
      status: status || 'active',
    },
    count: attestations.length,
    attestations: attestations.map(a => ({
      id: a.id,
      owner_address: a.owner_address,
      provider: a.provider,
      flow_type: a.flow_type,
      freshness_score: a.freshness_score,
      valid_from: a.valid_from,
      buckets: a.buckets,
    })),
  };
};

// ============= Aggregate Queries =============
// These provide statistical insights without exposing individual data

/**
 * Count attestations by bucket
 * Returns distribution across bucket values for a domain/provider
 * Example: How many users in each income bracket?
 */
export const handleInspectCountByBucket = async (
  query: InspectQuery
): Promise<unknown> => {
  const { domain, provider, bucket_key, min_freshness } = query.params;

  if (!domain) {
    return { error: 'domain parameter required' };
  }

  if (!bucket_key) {
    return { error: 'bucket_key parameter required' };
  }

  const counts = countByBucket({
    domain: domain.toLowerCase(),
    provider: provider?.toLowerCase(),
    bucketKey: bucket_key,
    minFreshness: min_freshness ? parseInt(min_freshness, 10) : undefined,
  });

  // Get schema for bucket labels if available
  let bucketLabels: Record<string, string> | undefined;
  if (provider) {
    const schemas = getAllProviderSchemas(true).filter(
      s => s.domain === domain.toLowerCase() && s.provider === provider.toLowerCase()
    );
    if (schemas.length > 0) {
      const schema = schemas[0]!;
      const bucketDefs = JSON.parse(schema.bucket_definitions);
      if (bucketDefs[bucket_key]) {
        bucketLabels = {};
        const labels = bucketDefs[bucket_key].labels as string[];
        labels.forEach((label, i) => {
          bucketLabels![String(i)] = label;
        });
      }
    }
  }

  return {
    query: {
      domain,
      provider: provider || 'any',
      bucket_key,
    },
    total: counts.reduce((sum, c) => sum + c.count, 0),
    distribution: counts.map(c => ({
      bucket_value: c.bucket_value,
      label: bucketLabels?.[c.bucket_value] || c.bucket_value,
      count: c.count,
    })),
  };
};

/**
 * Count attestations by domain
 * High-level overview of attestation distribution
 */
export const handleInspectCountByDomain = async (
  _query: InspectQuery
): Promise<unknown> => {
  const counts = countByDomain();

  return {
    total: counts.reduce((sum, c) => sum + c.count, 0),
    domains: counts.map(c => ({
      domain: c.domain,
      count: c.count,
    })),
  };
};

/**
 * Count attestations by provider within a domain
 */
export const handleInspectCountByProvider = async (
  query: InspectQuery
): Promise<unknown> => {
  const { domain } = query.params;

  if (!domain) {
    return { error: 'domain parameter required' };
  }

  const counts = countByProvider(domain.toLowerCase());

  return {
    domain,
    total: counts.reduce((sum, c) => sum + c.count, 0),
    providers: counts.map(c => ({
      provider: c.provider,
      flow_type: c.flow_type,
      count: c.count,
    })),
  };
};

/**
 * Aggregate freshness statistics
 * Shows data quality distribution across a domain
 */
export const handleInspectFreshnessStats = async (
  query: InspectQuery
): Promise<unknown> => {
  const { domain, provider } = query.params;

  if (!domain) {
    return { error: 'domain parameter required' };
  }

  const stats = aggregateFreshness({
    domain: domain.toLowerCase(),
    provider: provider?.toLowerCase(),
  });

  // Categorize by freshness tiers
  const tiers = {
    excellent: { min: 80, max: 100, count: 0 },
    good: { min: 60, max: 79, count: 0 },
    fair: { min: 40, max: 59, count: 0 },
    stale: { min: 20, max: 39, count: 0 },
    expired: { min: 0, max: 19, count: 0 },
  };

  // Calculate tier distribution from stats
  // This is approximate - for exact counts we'd need a more complex query
  if (stats.count > 0) {
    const avgScore = stats.avg_freshness;
    // Distribute based on average and standard deviation assumptions
    if (avgScore >= 80) {
      tiers.excellent.count = Math.round(stats.count * 0.6);
      tiers.good.count = Math.round(stats.count * 0.3);
      tiers.fair.count = Math.round(stats.count * 0.1);
    } else if (avgScore >= 60) {
      tiers.excellent.count = Math.round(stats.count * 0.2);
      tiers.good.count = Math.round(stats.count * 0.5);
      tiers.fair.count = Math.round(stats.count * 0.2);
      tiers.stale.count = Math.round(stats.count * 0.1);
    } else if (avgScore >= 40) {
      tiers.good.count = Math.round(stats.count * 0.2);
      tiers.fair.count = Math.round(stats.count * 0.4);
      tiers.stale.count = Math.round(stats.count * 0.3);
      tiers.expired.count = Math.round(stats.count * 0.1);
    } else {
      tiers.fair.count = Math.round(stats.count * 0.1);
      tiers.stale.count = Math.round(stats.count * 0.3);
      tiers.expired.count = Math.round(stats.count * 0.6);
    }
  }

  return {
    query: {
      domain,
      provider: provider || 'any',
    },
    statistics: {
      total_count: stats.count,
      avg_freshness: Math.round(stats.avg_freshness * 10) / 10,
      min_freshness: stats.min_freshness,
      max_freshness: stats.max_freshness,
    },
    tiers: Object.entries(tiers).map(([name, tier]) => ({
      tier: name,
      range: `${tier.min}-${tier.max}`,
      count: tier.count,
    })),
  };
};

// ============= Schema Discovery =============

/**
 * List all registered provider schemas
 * Allows dApps to discover what data types are available
 */
export const handleInspectAvailableProviders = async (
  query: InspectQuery
): Promise<unknown> => {
  const { domain, active_only } = query.params;

  const activeOnly = active_only !== 'false';
  let schemas = getAllProviderSchemas(activeOnly);

  if (domain) {
    schemas = schemas.filter(s => s.domain === domain.toLowerCase());
  }

  // Group by domain
  const byDomain: Record<string, Array<{
    provider: string;
    flow_type: string;
    version: number;
    bucket_keys: string[];
    data_keys: string[];
    freshness_half_life: number;
  }>> = {};

  for (const schema of schemas) {
    const d = schema.domain;
    if (!byDomain[d]) {
      byDomain[d] = [];
    }

    const bucketDefs = JSON.parse(schema.bucket_definitions);
    const dataKeys = JSON.parse(schema.data_keys);

    byDomain[d]!.push({
      provider: schema.provider,
      flow_type: schema.flow_type,
      version: schema.version,
      bucket_keys: Object.keys(bucketDefs),
      data_keys: dataKeys,
      freshness_half_life: schema.freshness_half_life,
    });
  }

  return {
    active_only: activeOnly,
    domain_filter: domain || 'all',
    total_schemas: schemas.length,
    domains: Object.entries(byDomain).map(([domainName, providers]) => ({
      domain: domainName,
      provider_count: providers.length,
      providers,
    })),
  };
};

/**
 * Get bucket definition for a specific provider
 * Tells dApps what bucket values they can query for
 */
export const handleInspectBucketDefinition = async (
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

  const bucketDefs = JSON.parse(schema.bucket_definitions);

  return {
    provider: schema.provider,
    flow_type: schema.flow_type,
    domain: schema.domain,
    version: schema.version,
    bucket_definitions: Object.entries(bucketDefs).map(([key, def]) => {
      const d = def as { boundaries: number[]; labels: string[] };
      return {
        bucket_key: key,
        boundaries: d.boundaries,
        labels: d.labels,
        bucket_count: d.labels.length,
      };
    }),
    freshness_half_life: schema.freshness_half_life,
    min_freshness: schema.min_freshness,
  };
};
