/**
 * Chain clock regression tests.
 *
 * BACKGROUND — the bug this guards against
 * ----------------------------------------
 * The Cartesi machine has no real clock. To keep execution deterministic (which
 * is what makes fraud proofs possible), the platform gives the machine a clock
 * that starts at the 1970 epoch and only ticks while inputs are being processed.
 * Measured on a real machine (cartesi CLI 1.5.0, sdk 0.9.0, riscv64):
 *
 *     Date.now()                -> 3337
 *     new Date().toISOString()  -> 1970-01-01T00:00:03.933Z
 *
 * Three identity inspect handlers used to do:
 *
 *     const now = Math.floor(Date.now() / 1000);   // == 3 inside the machine
 *     ... WHERE expires_at > ?                     // expires_at is a REAL unix ts
 *
 * `expires_at > 3` is unconditionally true, so the expiry filter never filtered:
 * EXPIRED IDENTITY ATTESTATIONS WERE REPORTED AS VALID, FOREVER.
 *
 * The fix mirrors block production time (`metadata.timestamp`, carried on every
 * advance input) into a single-row `chain_clock` table, and has inspect read it
 * via getChainTime(). Inspect requests carry no metadata of their own, so state
 * is the only channel available.
 */
import { initDatabase, getDatabase } from '../src/db';
import { initLCoreSchema, recordChainTime, getChainTime } from '../src/lcore-db';
import {
  handleInspectIdentity,
  handleInspectIdentityStats,
} from '../src/handlers/lcore-identity';

/** Realistic block time (2026-08-04T00:00:00Z). What matters is that it is
 *  astronomically larger than the machine clock (~3 seconds past the epoch). */
const BLOCK_NOW = 1785974400;
const ONE_YEAR = 365 * 24 * 60 * 60;
/** What the machine's own clock actually reports — the value the bug compared against. */
const MACHINE_CLOCK_SECONDS = 3;

const USER_DID = 'did:key:zQ3shTestUserForChainClock';

function insertIdentity(sessionId: string, expiresAt: number): void {
  getDatabase().run(
    `INSERT INTO identity_attestations
       (user_did, provider, country_code, verification_level, verified,
        issued_at, expires_at, attestor_signature, session_id,
        input_index, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'))`,
    [
      USER_DID, 'test-provider', 'US', 'document', 1,
      BLOCK_NOW - ONE_YEAR, expiresAt, 'sig', sessionId, 1, BLOCK_NOW,
    ]
  );
}

beforeAll(async () => {
  await initDatabase();
  initLCoreSchema();
});

describe('chain_clock', () => {
  it('is 0 before any advance input has been processed', () => {
    // Safe by construction: every time-filtered record is itself created by an
    // advance, so an unset clock implies there is nothing to filter.
    expect(getChainTime()).toBe(0);
  });

  it('returns the block time recorded by an advance', () => {
    recordChainTime(BLOCK_NOW, 42);
    expect(getChainTime()).toBe(BLOCK_NOW);
  });

  it('advances on the next input and stays a single row', () => {
    recordChainTime(BLOCK_NOW + 60, 43);
    expect(getChainTime()).toBe(BLOCK_NOW + 60);

    const rows = getDatabase().exec('SELECT COUNT(*) FROM chain_clock')[0]?.values[0]?.[0];
    expect(rows).toBe(1);
  });
});

describe('identity expiry filtering (the bug this fixes)', () => {
  beforeAll(() => {
    recordChainTime(BLOCK_NOW, 44);
    insertIdentity('session-expired', BLOCK_NOW - ONE_YEAR / 2); // expired 6 months ago
    insertIdentity('session-valid', BLOCK_NOW + ONE_YEAR);       // valid for another year
  });

  it('returns the unexpired attestation and filters the expired one', async () => {
    const result = (await handleInspectIdentity({
      type: 'identity',
      params: { user_did: USER_DID },
    } as never)) as { verified?: boolean; attestation?: { session_id: string } };

    expect(result.verified).toBe(true);
    expect(result.attestation?.session_id).toBe('session-valid');
  });

  it('reports no valid identity once chain time passes expires_at', async () => {
    // This is the assertion that would have FAILED before the fix: with the raw
    // machine clock the handler always found something, no matter how stale.
    recordChainTime(BLOCK_NOW + ONE_YEAR * 2, 45);

    const result = (await handleInspectIdentity({
      type: 'identity',
      params: { user_did: USER_DID },
    } as never)) as { verified?: boolean };

    expect(result.verified).toBe(false);

    recordChainTime(BLOCK_NOW, 46); // restore
  });

  it('counts only unexpired attestations as active in stats', async () => {
    const stats = (await handleInspectIdentityStats({
      type: 'identity_stats',
      params: {},
    } as never)) as { total?: number; active?: number };

    expect(stats.total).toBe(2);   // both rows exist
    expect(stats.active).toBe(1);  // only one is unexpired
  });
});

describe('regression guard: the old behaviour must not come back', () => {
  const expiredAt = BLOCK_NOW - ONE_YEAR / 2;

  it('an expired record WOULD pass against the raw machine clock (the bug was real)', () => {
    expect(expiredAt > MACHINE_CLOCK_SECONDS).toBe(true);
  });

  it('the same record does NOT pass against chain time (the fix works)', () => {
    recordChainTime(BLOCK_NOW, 47);
    expect(expiredAt > getChainTime()).toBe(false);
  });
});
