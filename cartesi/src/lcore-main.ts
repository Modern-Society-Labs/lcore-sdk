/**
 * L{CORE} SDK - Entry Point
 *
 * This is the main entry point for the L{CORE} SDK Cartesi rollup application.
 * It initializes the database with L{CORE} schema and runs the attestation
 * data layer.
 *
 * USAGE:
 * 1. Use this directly if you only need L{CORE} functionality
 * 2. Or import lcoreRouteConfig/mergeLCoreRoutes into your own index.ts
 *    to combine with custom handlers
 */

import createClient from 'openapi-fetch';
import { components, paths } from './schema';
import { initDatabase } from './db';
import { initLCoreSchema, getLCoreStats } from './lcore-db';
import { createRouter } from './router';
import { lcoreRouteConfig } from './handlers/lcore-index';
import { initInputDecryption } from './encryption';

// ============= Type Definitions =============

type AdvanceRequestData = components['schemas']['Advance'];
type InspectRequestData = components['schemas']['Inspect'];
type RequestHandlerResult = components['schemas']['Finish']['status'];
type RollupsRequest = components['schemas']['RollupRequest'];

// ============= Configuration =============

const rollupServer = process.env.ROLLUP_HTTP_SERVER_URL;
console.log('L{CORE} SDK - HTTP rollup_server url is ' + rollupServer);

// ============= Main Function =============

const main = async () => {
  console.log('=== L{CORE} SDK Starting ===');

  // Initialize core database
  console.log('Initializing database...');
  await initDatabase();
  console.log('Core database initialized');

  // Initialize L{CORE} schema
  console.log('Initializing L{CORE} schema...');
  initLCoreSchema();
  console.log('L{CORE} schema initialized');

  // Initialize input decryption (for device attestation privacy)
  const inputPrivateKey = process.env.LCORE_INPUT_PRIVATE_KEY;
  if (inputPrivateKey) {
    initInputDecryption(inputPrivateKey);
    console.log('[LCORE] Input decryption initialized');
  } else {
    console.warn('[LCORE] LCORE_INPUT_PRIVATE_KEY not set - input decryption disabled');
  }

  // Create router with L{CORE} handlers
  const router = createRouter(lcoreRouteConfig);
  console.log('Router configured with L{CORE} handlers');

  // Log registered handlers
  console.log('Advance handlers:');
  for (const action of Object.keys(lcoreRouteConfig.advance)) {
    console.log(`  - ${action}`);
  }
  console.log('Inspect handlers:');
  for (const queryType of Object.keys(lcoreRouteConfig.inspect)) {
    console.log(`  - ${queryType}`);
  }

  const { POST } = createClient<paths>({ baseUrl: rollupServer });
  let status: RequestHandlerResult = 'accept';

  console.log('=== L{CORE} SDK Ready ===');
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
          console.log(`Advance request received`);
          status = await router.handleAdvance(data.data as AdvanceRequestData);
          console.log(`Advance request completed: ${status}`);

          // Log stats after each advance
          const stats = getLCoreStats();
          console.log(`Stats: ${stats.active_attestations} active attestations, ${stats.active_access_grants} active grants`);
          break;

        case 'inspect_state':
          // Handle read-only query
          console.log(`Inspect request received`);
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
  console.error('L{CORE} SDK Fatal error:', e);
  process.exit(1);
});
