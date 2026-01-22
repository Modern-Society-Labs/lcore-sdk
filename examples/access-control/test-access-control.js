/**
 * L{CORE} Access Control Test
 *
 * Tests that only the deployer address can query device attestations.
 * This runs against a LOCAL Cartesi rollup server (not production).
 *
 * Usage:
 *   cd examples/access-control-test
 *   npm install
 *   npm test
 */

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

// Configuration
const ROLLUP_URL = process.env.ROLLUP_URL || 'http://127.0.0.1:5004';
const AUTHORIZED_ADDRESS = process.env.AUTHORIZED_ADDRESS || '0xYOUR_AUTHORIZED_ADDRESS_HERE';
const UNAUTHORIZED_ADDRESS = '0xDEADBEEF00000000000000000000000000000000';

// Test device DID
const TEST_DEVICE_DID = 'did:key:zQ3shY8d8U8q4dJvWrVfTwCp7L6aE8z8EepJHqT8k5V9vzABC';

console.log('=== L{CORE} Access Control Test ===\n');
console.log(`Rollup URL: ${ROLLUP_URL}`);
console.log(`Authorized Address: ${AUTHORIZED_ADDRESS}`);
console.log(`Unauthorized Address: ${UNAUTHORIZED_ADDRESS}\n`);

/**
 * Send an inspect query to the Cartesi rollup
 */
async function inspect(queryType, params) {
  const url = `${ROLLUP_URL}/input/inspect`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: queryType,
        params: params
      })
    });
    const data = await response.json();

    // The rollup server returns reports with payloadJson already parsed
    if (data.reports && data.reports.length > 0) {
      return data.reports[0].payloadJson || JSON.parse(data.reports[0].payload);
    }

    return data;
  } catch (error) {
    return { error: error.message };
  }
}

/**
 * Test 1: Query with authorized address (deployer)
 */
async function testAuthorizedAccess() {
  console.log('[Test 1] Query with AUTHORIZED address...');

  const result = await inspect('device_latest', {
    device_did: TEST_DEVICE_DID,
    sender: AUTHORIZED_ADDRESS
  });

  if (result.error === 'ACCESS DENIED') {
    console.log('  ❌ FAIL: Was denied access (should have been allowed)');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return false;
  }

  // Either we get data or "No attestations found" (both are valid - means access was granted)
  if (result.error === 'No attestations found for device' || result.device_did || result.id !== undefined) {
    console.log('  ✅ PASS: Access granted to deployer');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return true;
  }

  console.log('  ⚠️  UNEXPECTED: Got unexpected response');
  console.log('  Result:', JSON.stringify(result, null, 2));
  return false;
}

/**
 * Test 2: Query with unauthorized address
 */
async function testUnauthorizedAccess() {
  console.log('\n[Test 2] Query with UNAUTHORIZED address...');

  const result = await inspect('device_latest', {
    device_did: TEST_DEVICE_DID,
    sender: UNAUTHORIZED_ADDRESS
  });

  if (result.error === 'ACCESS DENIED') {
    console.log('  ✅ PASS: Access correctly denied');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return true;
  }

  console.log('  ❌ FAIL: Access was NOT denied (should have been blocked)');
  console.log('  Result:', JSON.stringify(result, null, 2));
  return false;
}

/**
 * Test 3: Query with no sender (should be denied)
 */
async function testNoSender() {
  console.log('\n[Test 3] Query with NO sender...');

  const result = await inspect('device_latest', {
    device_did: TEST_DEVICE_DID
    // No sender provided
  });

  if (result.error === 'ACCESS DENIED') {
    console.log('  ✅ PASS: Access correctly denied (no sender)');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return true;
  }

  console.log('  ❌ FAIL: Access was NOT denied (should have been blocked)');
  console.log('  Result:', JSON.stringify(result, null, 2));
  return false;
}

/**
 * Test 4: Stats endpoint (should remain public)
 */
async function testPublicStats() {
  console.log('\n[Test 4] Query device_stats (public endpoint)...');

  const result = await inspect('device_stats', {});

  // Stats should work without access control
  if (result.error === 'ACCESS DENIED') {
    console.log('  ❌ FAIL: Stats endpoint should be public');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return false;
  }

  if (result.total_attestations !== undefined || result.unique_devices !== undefined) {
    console.log('  ✅ PASS: Stats endpoint is public');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return true;
  }

  console.log('  ⚠️  UNEXPECTED: Got unexpected response');
  console.log('  Result:', JSON.stringify(result, null, 2));
  return false;
}

/**
 * Run all tests
 */
async function runTests() {
  let passed = 0;
  let failed = 0;

  // Check if Cartesi is running
  console.log('Checking Cartesi server...');
  try {
    const healthCheck = await fetch(`${ROLLUP_URL}/health`);
    if (!healthCheck.ok) {
      console.log(`\n⚠️  Cartesi server at ${ROLLUP_URL} is not responding.`);
      console.log('   Make sure to start it first:');
      console.log('   cd cartesi && npm run dev\n');
      process.exit(1);
    }
    console.log('Cartesi server is running.\n');
  } catch (error) {
    console.log(`\n⚠️  Cannot connect to Cartesi server at ${ROLLUP_URL}`);
    console.log('   Make sure to start it first:');
    console.log('   cd cartesi && npm run dev\n');
    console.log('   Error:', error.message);
    process.exit(1);
  }

  // Run tests
  if (await testAuthorizedAccess()) passed++; else failed++;
  if (await testUnauthorizedAccess()) passed++; else failed++;
  if (await testNoSender()) passed++; else failed++;
  if (await testPublicStats()) passed++; else failed++;

  // Summary
  console.log('\n=== Summary ===');
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Total:  ${passed + failed}`);

  if (failed === 0) {
    console.log('\n✅ All access control tests passed!');
    process.exit(0);
  } else {
    console.log('\n❌ Some tests failed.');
    process.exit(1);
  }
}

runTests();
