# L{CORE} Tests

Every suite below runs without external infrastructure — no attestor server, no
Cartesi node, no database, no network. The attestor tests drive the real router
in-process. The one exception (`test:smoke`) is called out explicitly.

## Layout

| Location | Runner | What it covers |
|---|---|---|
| `tests/attestor/` | `node --test` | DID parsing, device submit endpoint, inspect-proxy re-encryption, submission batcher |
| `cartesi/src/__tests__/unit.*` | jest | JWS verification and encryption units inside the rollup |
| `cartesi/test/` | jest | Chain clock + determinism regressions |
| `attestor/test/` | `node --test` | Salted-hash (H-2) regressions incl. the real `/api/device/submit` route |
| `packages/python/tests/` | pytest | Device identity, DID, and the salted-hash signing contract |
| `packages/c/tests/` | ctest | did:key, JWS, base58/base64url, salted `data_hash` vector |

## Running

```bash
# Attestor (DID, device endpoint, inspect proxy, batcher)
npm test

# Cartesi rollup (units + chain clock); e2e specs are excluded by default
cd cartesi && npm test

# Attestor H-2 salted-hash regressions
cd attestor && npm test

# Python SDK
cd packages/python && pip install -e '.[dev]' && pytest tests/

# C SDK
cd packages/c && cmake -B build -DLCORE_USE_CURL=OFF && cmake --build build && ./build/test_lcore
```

## Requires a running server

```bash
# Deployment smoke test — asserts security headers set by the real HTTP server,
# so it cannot run in-process. Point it at a deployment:
ATTESTOR_URL=http://your-attestor:8001 npm run test:smoke
```

## Rollup e2e — requires the local dev servers

`cartesi/src/__tests__/e2e.*.test.ts` (182 tests) drive the rollup application
through the dev rollup-server harness on port 5004. They do **not** need a real
Cartesi node, an L2, or a wallet — but they do need both servers running, so they
are excluded from `npm test` via `--testPathIgnorePatterns=e2e`.

```bash
cd cartesi
npm run build          # once

# Terminal 1 — rollup-server on :5004 plus the application
npm run start:servers

# Terminal 2
npm run test:e2e
```

No environment variables are needed; the rollup server URL defaults to
`http://127.0.0.1:5004`. Set `ROLLUP_HTTP_SERVER_URL` to point elsewhere.

These tests share one long-lived database across the run, so use `--runInBand`
(already set in the `test:e2e` script) to keep them ordered.

## Machine-level determinism

Proves that identical inputs produce an identical state root — the property fraud
proofs depend on. Requires Docker and a built machine:

```bash
cd cartesi && npx cartesi build && ./scripts/verify-determinism.sh
```

## Note on the salted hash

Device submissions sign a salted hash:

```
data_hash = sha256(JCS(payload) + did + timestamp + salt)
```

Tests that build submissions must send the `salt` alongside, and must sign the
**hash** (`createJWSOverHash`), not the raw payload. Signing the payload directly
is the pre-v2.1 protocol and will be rejected with a 401.
