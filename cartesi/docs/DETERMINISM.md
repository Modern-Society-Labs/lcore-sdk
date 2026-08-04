# Determinism & Deployment Invariants

The Cartesi rollup's security rests on **bit-identical re-execution**: any validator
must be able to re-run the machine over the same on-chain inputs and reproduce the
exact same SQLite state hash and output (notice/voucher) hashes. If two honest
validators diverge, fraud proofs cannot adjudicate.

The **machine image is the consensus artifact** — everyone runs the *same* image.
So the rules below are about making sure nothing outside that image (host clock,
per-node env, engine/library versions) can change an advance-path result.

The deployed application is `src/lcore-main.ts` (the Docker image runs
`lcore-main.js`; see `Dockerfile`). `src/index.ts` is a **generic non-hardened
template** — not the deployed entrypoint (see its header).

---

## Invariant 1 — Consensus-affecting config must be baked into the machine image

Several behaviours are read from `process.env`. Any env var that can change an
**advance-path** accept/reject decision, stored state, or emitted output is
consensus-critical: it must be set **at machine build time**, identically for every
validator, and must never depend on a host default or a per-node runtime override.

### Deployed `lcore-main` path — consensus-critical

The surface is small — only sender authorization:

| Env var | Where | Gates | Requirement |
|---|---|---|---|
| `AUTHORIZED_SENDERS` | `router.ts:80` | accept/reject of **every** advance input | Bake explicitly. Must be identical across validators. |
| `ALLOW_ALL_SENDERS` | `router.ts:101` | fallback when whitelist empty | Bake explicitly (or leave unset with a non-empty `AUTHORIZED_SENDERS`). |
| `NODE_ENV` | `config.ts:118` (`isDevelopmentMode`, used in `router.ts:101`) | empty-whitelist fail-open fallback | Bake `NODE_ENV=production` so the dev fallback can never trigger. |

`isAuthorizedSender` already fails closed in production, so the residual risk is a
validator running with `NODE_ENV` unset (dev fallback) or a mismatched
`AUTHORIZED_SENDERS`. Baking both removes it.

**Verified NOT a consensus-config risk (no action needed):**
- **Input size limits** — the router enforces them with **hardcoded constants**
  (`MAX_PAYLOAD_SIZE`, `MAX_STRING_LENGTH` at `router.ts:63,69`), which are baked into
  the image. `config.ts`'s env-based `getMaxPayloadSize`/`getMaxStringLength` are
  **unused** (dead). So size accept/reject is already deterministic.
- **`LCORE_OUTPUT_MODE`** — defaults to `raw` (`config.ts:153`; the "encrypted
  (default)" comment above it is stale — the code returns `raw`). It only affects
  **inspect reports** (`processOutputSync` runs on the inspect path only), never
  advance notices/vouchers. Not consensus-relevant. Do not set `encrypted` anyway —
  see Invariant 2.

### Template-only (`src/index.ts`) — not deployed, but hazardous if you build on it

| Env var | Where | Gates |
|---|---|---|
| `PROOF_SIGNING_KEY` | `config.ts:76` | `submit_proof` accept/reject (HMAC) |
| `REQUIRE_APPROVAL` | `config.ts:19` | `compute` immediate vs pending state |
| `DEFAULT_THRESHOLD` | `config.ts:43` | computed result / threshold |
| `COMPUTATION_LOOKBACK_MONTHS` | `config.ts:58` | record window for `compute` |

### How to enforce

1. **Bake, don't inject.** Set these with `ENV` in the Cartesi `Dockerfile` *before*
   the machine snapshot is produced, so they are part of the machine hash. Do not
   pass them at container/node runtime — that lets two operators run divergent apps
   from the "same" code.
2. **Fail loudly on missing required config.** For the deployed path, prefer
   asserting at boot (`lcore-main.ts`) that `AUTHORIZED_SENDERS` is set and
   `NODE_ENV=production`, rather than silently taking a dev fallback. (`isAuthorizedSender`
   already fails closed in production — keep that; the risk is `NODE_ENV` being unset.)
3. **Treat a config change as a new deployment.** Changing any consensus-critical
   var produces a different machine image / app address. That is correct — coordinate
   it like a contract upgrade, not a hot env tweak.

---

## Invariant 2 — Never encrypt advance-path outputs

`encryptOutput()` (`encryption.ts`) uses a random ephemeral keypair + random nonce,
so the same plaintext yields different ciphertext each call. This is **safe only for
inspect reports** (not part of the on-chain output claim) and is wired that way today
(`processOutputSync` runs on the inspect path only, `router.ts`).

Notices and vouchers are hashed into the epoch's output Merkle root. Encrypting one
with random bytes → different output hash per replay → fraud proofs break. Likewise,
storing random ciphertext in SQLite diverges the state hash.

**Rule:** never call `encryptOutput`/`encryptResponse` on an advance handler's
`response`, notice, voucher, or any value written to state. If encrypted advance
output is ever needed, derive the nonce + ephemeral key deterministically from the
input (e.g. HKDF over `input_hash` + a counter) — accepting the loss of forward
secrecy — or encrypt off-chain in the attestor. See the note in `encryption.ts`.

---

## Design proposal — inspect-path expiry

### Problem

Some inspect handlers decide "is this still valid?" using the **host wall clock**:

- `lcore-identity.ts:235, 336, 376` — `const now = Math.floor(Date.now()/1000)`,
  then filter `expires_at > now` (identity attestations carry a unix-seconds
  `expires_at`).

Inspect is a read (not fraud-proved), so this is **not a consensus break**. But it is
**non-reproducible**: the same query returns different results depending on when/where
it runs, and it reaches for a host clock inside code that is otherwise clock-free.

Note the codebase is already **inconsistent** here: access-grant expiry
(`check_access`, `attestation_data`) is evaluated against a caller-supplied
`current_input` index (`lcore-access.ts`), not `Date.now()`. Only the identity path
uses the host clock.

### Options

| Option | Idea | Pros | Cons |
|---|---|---|---|
| **A. Leave as-is** | keep `Date.now()` on inspect | zero work | results depend on host clock; two nodes disagree; not reproducible |
| **B. Store last block time in state** | maintain a singleton `last_block_timestamp`, updated every advance; inspect compares `expires_at > last_block_timestamp` | deterministic given the state; reflects chain time; no host clock; no caller trust | one tiny state write per advance; "now" lags to the latest processed block (fine for expiry semantics) |
| **C. Caller passes the time** | add a `current_time`/`current_input` inspect param (as `check_access` already does) | explicit; matches existing access pattern | caller must supply it; a caller could pass a false time — but it only fools their own read |

### Recommendation — **B**, with a nod to C's precedent

Store the block timestamp of the most recent advance input in a one-row state table
(e.g. `chain_clock(last_block_timestamp INTEGER)`), updated at the top of the router's
advance path from `data.metadata.timestamp`. Have the identity inspect handlers read
that value instead of `Date.now()`.

Why B over C for identity: `expires_at` is an absolute unix timestamp, so the natural
"now" is chain time — B gives that deterministically and without trusting the caller,
whereas C would require every reader to supply a trustworthy clock. (C remains fine
where it's already used — index-based grant expiry — because the unit there is an
input index the caller legitimately tracks.)

Cost is negligible (one `UPDATE` per advance) and it removes the last host-clock
dependency from query results. It also composes with a future "expire on read"
or "sweep expired on advance" feature, since chain time is then available in state.

**Status:** proposal only — not yet implemented. Implementing B is mechanical:
add the singleton table + one update in the advance path + swap three `Date.now()`
reads in `lcore-identity.ts`.

---

## What is NOT a determinism risk (audited, for reference)

- Inside the real Cartesi machine, `Date.now()` reads an emulated clock that is a
  deterministic function of cycle count — pure machine re-execution converges on it.
  Divergence bites in **host/nonodo mode**, with **randomness** (not clock-derived),
  or across **build drift** (libm/`Math.pow`, SQLite version, baked env). The fixes in
  this repo target those cases.
- `utils/notice-batcher.ts`, `utils/db-maintenance.ts`, `utils/voucher-generator.ts`
  are exported but unused — no handler calls them.
- `rollup-server.ts` is a local dev mock of the rollup HTTP API, not machine code.
- JWS verification (`crypto/jws.ts`) is pure `@noble` integer/hash code — deterministic.

## The acceptance test that still owes proof

None of the determinism work has been proven at the **machine level**: build the
RISC-V machine, feed an identical input sequence twice, and diff the resulting
state-root and output hashes. That requires the `cartesi` build toolchain and is the
real end-to-end check. Type-checking, `sql.js` round-trips, and unit tests are what
has been run so far.
