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

## Inspect-path expiry — the chain clock (IMPLEMENTED)

### Problem — and it was worse than "non-reproducible"

Three identity inspect handlers decided "is this still valid?" by asking the machine
for the current time:

- `lcore-identity.ts` (`handleInspectIdentity`, `handleInspectIdentityByCountry`,
  `handleInspectIdentityStats`) — `const now = Math.floor(Date.now()/1000)`,
  then filter `expires_at > now` (identity attestations carry a unix-seconds
  `expires_at`, set by the attestor from a *real* host clock as `now + oneYear`).

The Cartesi machine has no real clock. Measured on an actual machine
(cartesi CLI 1.5.0, sdk 0.9.0, riscv64) by building a minimal app that printed it:

```
DATE_NOW_MS=3337
ISO=1970-01-01T00:00:03.933Z
SECONDS=3
```

So the comparison was effectively `expires_at > 3` against a real timestamp of
~1.79 billion — **unconditionally true**. The expiry filter never filtered anything:
**expired identity attestations were reported as valid, forever.**

This is not a consensus break (inspect is not fraud-proved) but it was a genuine
correctness bug, not merely a reproducibility wart as first assessed.

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

### Chosen: **B** — the chain clock

Why B over C for identity: `expires_at` is an absolute unix timestamp, so the natural
"now" is chain time — B gives that deterministically and without trusting the caller,
whereas C would require every reader to supply a trustworthy clock. (C remains fine
where it's already used — index-based grant expiry — because the unit there is an
input index the caller legitimately tracks.)

### How it works

1. **`chain_clock` table** (`lcore-db.ts`, created in `initLCoreSchema`) — a single
   row (`id = 1`, enforced by a `CHECK`) holding `last_block_timestamp` and
   `last_input_index`.
2. **`recordChainTime(blockTimestamp, inputIndex)`** is called once per advance in
   `lcore-main.ts`, **before** dispatching to the handler, using
   `data.metadata.timestamp` — the block production time carried on every input.
3. **`getChainTime()`** returns that value. The three identity inspect handlers call
   it instead of `Date.now()`.

Properties worth knowing:

- **Rejected inputs don't move the clock.** Cartesi rolls state back when a handler
  returns `reject`, so the write is discarded with everything else that input did.
  A rejected input never happened, as far as state is concerned.
- **`getChainTime()` returns 0 before any advance.** Safe by construction: every
  time-filtered record is itself created by an advance, so an unset clock means
  there is nothing to filter.
- **"Now" means the last input's block time, not real-time-now.** If the chain is
  idle for an hour, the value is an hour old. Immaterial for credentials measured in
  months, and it is the same clock the rest of the rollup reasons about.
- **Deterministic.** The value lives in state and comes from the input, so any
  replay reproduces it exactly.

### Rule going forward

> **Never call `Date.now()` or `new Date()` inside the Cartesi machine.**
> Advance handlers: use `data.metadata.timestamp`.
> Inspect handlers: use `getChainTime()`.

### Tests

`test/chain-clock.test.ts` (runs under `npm test`) covers the singleton behaviour,
the expiry filtering, and a regression guard asserting that an expired record *would*
have passed against the raw machine clock (proving the bug was real) but does *not*
pass against chain time (proving the fix holds).

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

## Machine-level acceptance test (RUN — results below)

`scripts/verify-determinism.sh` builds nothing but loads the built machine, feeds it a
rollup input, and prints the resulting state root. Run `npx cartesi build` first, then:

```
./scripts/verify-determinism.sh
```

Measured results below are from the build at commit `69203b2` (cartesi CLI 1.5.0,
sdk 0.9.0), whose machine template hash was
`0xfd0f83947de8ac1d9ee58098aaf8643cb1be7e3f1e0fa7f8ce31b5c20bb28de6`.

> **The hash and the state roots are properties of one specific build.** Any change
> to `cartesi/src`, the Dockerfile, or a dependency produces a different template
> hash — and therefore different state roots — by design. Re-run
> `npx cartesi build && npx cartesi hash` after any such change; do not expect the
> values below to match a later build. What must stay true is the *relationship*:
> run A and run B identical, run C different.

| Run | Block timestamp | Final state root |
|---|---|---|
| A | 1785974400 | `e070fa02…ce0990eb` |
| B | 1785974400 (identical) | `e070fa02…ce0990eb` — **identical** |
| C | 1785978000 (+1h) | `72c427ec…f8af8b5e` — **different** |

- **A == B** proves determinism: the same input yields a bit-identical state root, so
  two honest validators converge.
- **A != C** proves the check is not vacuous: block time genuinely reaches state (via
  `chain_clock`), so the harness would notice if state stopped depending on the input.
- Rebuilding from unchanged source reproduced A's hash *and* cycle count exactly
  (3630211648), which also demonstrates build reproducibility.

### What this test does NOT catch — and why that matters

We deliberately re-ran the harness against a build with the old, non-deterministic
`key_id = \`key_${inputIndex}_${Date.now()}\`` restored. **It still produced identical
hashes across two runs.**

That is not a flaw in the harness — it is a fact about the platform, and it corrects a
tempting overstatement. Inside the machine, `Date.now()` is a deterministic function of
cycle count, so pure machine re-execution *converges even on buggy wall-clock code*.
A wall-clock read in-machine is therefore not primarily a fraud-proof problem. Its real
consequences are:

1. **Correctness** — the value is meaningless (1970 + a few seconds), which is exactly
   how the identity-expiry bug above went unnoticed. This is the one that actually bit.
2. **Host-mode divergence** — anything run outside the machine (the dev `rollup-server`,
   `nonodo`, unit tests) sees a real clock and behaves differently from production.
3. **Cross-build fragility** — the value depends on cycle counts, which change between
   builds. The buggy build ran to 3633138568 cycles versus 3630211648 for the fixed one,
   so its "timestamp" would shift with any change to the image.

So: use this harness to catch *state divergence*, and use code review plus the rule
below to catch *wall-clock reads*. Neither substitutes for the other.
