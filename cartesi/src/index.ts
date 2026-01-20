/**
 * Cartesi SQLite Framework - Entry Point
 *
 * This is the main entry point for the Cartesi rollup application.
 * It initializes the database, configures the router, and runs the main event loop.
 *
 * CUSTOMIZATION GUIDE:
 * 1. Import your handlers from handlers/index.ts
 * 2. Configure the routeConfig with your advance and inspect handlers
 * 3. Add any additional initialization in the main() function
 */

import createClient from 'openapi-fetch';
import { components, paths } from './schema';
import { initDatabase } from './db';
import { createRouter, RouteConfig } from './router';
import { initEncryption, initInputDecryption } from './encryption';
import {
  // Entity handlers
  handleCreateEntity,
  handleUpdateEntity,
  handleInspectEntity,
  // Data handlers
  handleSyncData,
  handleInspectData,
  // Computation handlers
  handleCompute,
  handleInspectComputation,
  // Proof handlers
  handleSubmitProof,
  handleInspectProof,
  // Approval handlers
  handleApprove,
  handleReject,
  handleInspectApprovals,
  // Stats handlers
  handleInspectStats,
} from './handlers';
import {
  // Device attestation handlers
  handleDeviceAttestation,
  handleInspectDeviceAttestations,
  handleInspectDeviceLatest,
  handleInspectDeviceStats,
} from './handlers/lcore-device';

// ============= Type Definitions =============

type AdvanceRequestData = components['schemas']['Advance'];
type InspectRequestData = components['schemas']['Inspect'];
type RequestHandlerResult = components['schemas']['Finish']['status'];
type RollupsRequest = components['schemas']['RollupRequest'];

// ============= Configuration =============

const rollupServer = process.env.ROLLUP_HTTP_SERVER_URL;
console.log('HTTP rollup_server url is ' + rollupServer);

/**
 * Route configuration for all handlers.
 *
 * CUSTOMIZE: Add your own handlers here.
 *
 * Advance handlers: State-changing operations (create, update, delete)
 * Inspect handlers: Read-only queries (get, list, stats)
 */
const routeConfig: RouteConfig = {
  advance: {
    // Entity management
    create_entity: handleCreateEntity,
    update_entity: handleUpdateEntity,

    // External data sync
    sync_data: handleSyncData,

    // Computations
    compute: handleCompute,

    // Proof submission
    submit_proof: handleSubmitProof,

    // Approval workflow
    approve: handleApprove,
    reject: handleReject,

    // Device attestation (fraud-provable JWS verification)
    device_attestation: handleDeviceAttestation,
  },
  inspect: {
    // Entity queries
    entity: handleInspectEntity,

    // Data queries
    data: handleInspectData,

    // Computation queries
    computation: handleInspectComputation,

    // Proof queries
    proof: handleInspectProof,

    // Approval queries
    approvals: handleInspectApprovals,

    // Statistics
    stats: handleInspectStats,

    // Device attestation queries
    device_attestations: handleInspectDeviceAttestations,
    device_latest: handleInspectDeviceLatest,
    device_stats: handleInspectDeviceStats,
  },
};

// ============= Main Function =============

const main = async () => {
  // Initialize database
  console.log('Initializing database...');
  await initDatabase();
  console.log('Database initialized');

  // Initialize encryption/decryption
  // Output encryption (for query responses)
  const adminPublicKey = process.env.LCORE_ADMIN_PUBLIC_KEY;
  if (adminPublicKey) {
    initEncryption(adminPublicKey);
    console.log('Output encryption initialized');
  } else {
    console.warn('[LCORE] LCORE_ADMIN_PUBLIC_KEY not set - output encryption disabled');
  }

  // Input decryption (for device attestation privacy)
  const inputPrivateKey = process.env.LCORE_INPUT_PRIVATE_KEY;
  if (inputPrivateKey) {
    initInputDecryption(inputPrivateKey);
    console.log('Input decryption initialized');
  } else {
    console.warn('[LCORE] LCORE_INPUT_PRIVATE_KEY not set - input decryption disabled');
  }

  // Create router with all handlers
  const router = createRouter(routeConfig);
  console.log('Router configured with handlers');

  const { POST } = createClient<paths>({ baseUrl: rollupServer });
  let status: RequestHandlerResult = 'accept';

  console.log('Starting main loop...');

  // Main event loop
  while (true) {
    const { response } = await POST('/finish', {
      body: { status },
      parseAs: 'text',
    });

    if (response.status === 200) {
      const data = (await response.json()) as RollupsRequest;

      switch (data.request_type) {
        case 'advance_state':
          // Handle state-changing request
          status = await router.handleAdvance(data.data as AdvanceRequestData);
          break;

        case 'inspect_state':
          // Handle read-only query
          await router.handleInspect(data.data as InspectRequestData);
          status = 'accept';
          break;
      }
    } else if (response.status === 202) {
      // Idle - no pending requests
      console.log(await response.text());
    }
  }
};

// ============= Startup =============

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
