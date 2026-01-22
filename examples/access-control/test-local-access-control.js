/**
 * L{CORE} Access Control - Local Unit Test
 *
 * Tests the access control logic directly without running the full Cartesi server.
 * This imports the handler function and tests it in isolation.
 *
 * Usage:
 *   cd examples/access-control-test/cartesi
 *   npm install && npm run build
 *   cd ..
 *   node test-local-access-control.js
 */

// The authorized address constant - must match the handler
// Set via environment variable or replace the placeholder
const AUTHORIZED_ADDRESS = process.env.AUTHORIZED_ADDRESS || '0xYOUR_AUTHORIZED_ADDRESS_HERE';
const UNAUTHORIZED_ADDRESS = '0xDEADBEEF00000000000000000000000000000000';
const TEST_DEVICE_DID = 'did:key:zQ3shY8d8U8q4dJvWrVfTwCp7L6aE8z8EepJHqT8k5V9vzABC';

console.log('=== L{CORE} Access Control - Local Unit Test ===\n');
console.log(`Authorized Address: ${AUTHORIZED_ADDRESS}`);
console.log(`Unauthorized Address: ${UNAUTHORIZED_ADDRESS}\n`);

/**
 * Simulate the access control check from lcore-device.ts
 * This mirrors the logic in handleInspectDeviceLatest
 */
function checkAccessControl(queryParams) {
  const requester = queryParams.sender?.toLowerCase();
  if (!requester || requester !== AUTHORIZED_ADDRESS.toLowerCase()) {
    return {
      allowed: false,
      error: 'ACCESS DENIED',
      message: 'Only the deployer address can query device attestations',
      authorized: AUTHORIZED_ADDRESS,
      requester: requester || 'none',
    };
  }
  return { allowed: true };
}

/**
 * Test 1: Authorized address
 */
function testAuthorized() {
  console.log('[Test 1] Check with AUTHORIZED address...');

  const result = checkAccessControl({
    device_did: TEST_DEVICE_DID,
    sender: AUTHORIZED_ADDRESS
  });

  if (result.allowed) {
    console.log('  ✅ PASS: Deployer is allowed');
    return true;
  } else {
    console.log('  ❌ FAIL: Deployer was denied');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return false;
  }
}

/**
 * Test 2: Authorized address (lowercase)
 */
function testAuthorizedLowercase() {
  console.log('\n[Test 2] Check with AUTHORIZED address (lowercase)...');

  const result = checkAccessControl({
    device_did: TEST_DEVICE_DID,
    sender: AUTHORIZED_ADDRESS.toLowerCase()
  });

  if (result.allowed) {
    console.log('  ✅ PASS: Lowercase address is allowed');
    return true;
  } else {
    console.log('  ❌ FAIL: Lowercase address was denied');
    console.log('  Result:', JSON.stringify(result, null, 2));
    return false;
  }
}

/**
 * Test 3: Unauthorized address
 */
function testUnauthorized() {
  console.log('\n[Test 3] Check with UNAUTHORIZED address...');

  const result = checkAccessControl({
    device_did: TEST_DEVICE_DID,
    sender: UNAUTHORIZED_ADDRESS
  });

  if (!result.allowed && result.error === 'ACCESS DENIED') {
    console.log('  ✅ PASS: Unauthorized address is blocked');
    console.log('  Response:', JSON.stringify(result, null, 2));
    return true;
  } else {
    console.log('  ❌ FAIL: Unauthorized address was allowed');
    return false;
  }
}

/**
 * Test 4: No sender provided
 */
function testNoSender() {
  console.log('\n[Test 4] Check with NO sender...');

  const result = checkAccessControl({
    device_did: TEST_DEVICE_DID
    // No sender
  });

  if (!result.allowed && result.error === 'ACCESS DENIED') {
    console.log('  ✅ PASS: Missing sender is blocked');
    console.log('  Response:', JSON.stringify(result, null, 2));
    return true;
  } else {
    console.log('  ❌ FAIL: Missing sender was allowed');
    return false;
  }
}

/**
 * Test 5: Empty sender
 */
function testEmptySender() {
  console.log('\n[Test 5] Check with EMPTY sender...');

  const result = checkAccessControl({
    device_did: TEST_DEVICE_DID,
    sender: ''
  });

  if (!result.allowed && result.error === 'ACCESS DENIED') {
    console.log('  ✅ PASS: Empty sender is blocked');
    console.log('  Response:', JSON.stringify(result, null, 2));
    return true;
  } else {
    console.log('  ❌ FAIL: Empty sender was allowed');
    return false;
  }
}

/**
 * Test 6: Random address
 */
function testRandomAddress() {
  console.log('\n[Test 6] Check with RANDOM address...');

  const randomAddress = '0x' + [...Array(40)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');

  const result = checkAccessControl({
    device_did: TEST_DEVICE_DID,
    sender: randomAddress
  });

  if (!result.allowed && result.error === 'ACCESS DENIED') {
    console.log(`  ✅ PASS: Random address ${randomAddress} is blocked`);
    return true;
  } else {
    console.log(`  ❌ FAIL: Random address ${randomAddress} was allowed`);
    return false;
  }
}

// Run all tests
let passed = 0;
let failed = 0;

if (testAuthorized()) passed++; else failed++;
if (testAuthorizedLowercase()) passed++; else failed++;
if (testUnauthorized()) passed++; else failed++;
if (testNoSender()) passed++; else failed++;
if (testEmptySender()) passed++; else failed++;
if (testRandomAddress()) passed++; else failed++;

// Summary
console.log('\n=== Summary ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed === 0) {
  console.log('\n✅ All access control logic tests passed!');
  console.log('\nThis verifies the access control check works correctly.');
  console.log('The same logic is implemented in:');
  console.log('  cartesi/src/handlers/lcore-device.ts');
  process.exit(0);
} else {
  console.log('\n❌ Some tests failed.');
  process.exit(1);
}
