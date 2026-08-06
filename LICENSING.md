# Licensing

L{CORE} is licensed by component. The device SDKs are permissive so they can be
embedded in commercial and proprietary firmware. The server-side components are
copyleft.

## Structure

| Path | License | License file |
|---|---|---|
| Repository root | **AGPL-3.0-only** | [`LICENSE`](./LICENSE) |
| `cartesi/` | **AGPL-3.0-only** | [`cartesi/LICENSE`](./cartesi/LICENSE) |
| `attestor/` | **AGPL-3.0-only** | [`attestor/LICENSE`](./attestor/LICENSE) |
| `packages/typescript/` | **MIT** | [`packages/typescript/LICENSE`](./packages/typescript/LICENSE) |
| `packages/python/` | **MIT** | [`packages/python/LICENSE`](./packages/python/LICENSE) |
| `packages/c/` | **MIT** | [`packages/c/LICENSE`](./packages/c/LICENSE) |

In short:

- **Building a device or client that talks to L{CORE}?** The SDKs are MIT. Embed them
  in closed-source firmware or products with no obligation to publish your code.
- **Running or modifying the attestor or rollup application?** Those are AGPL-3.0. If
  you modify them and offer the service over a network, you must publish your
  modifications.

## Why the SDKs can be MIT

`attestor/` is a fork of [`reclaimprotocol/attestor-core`](https://github.com/reclaimprotocol/attestor-core),
which is AGPL-3.0. That copyleft is inherited, not elective — it applies to the attestor
and to anything that links against it.

The device SDKs do not link against it. They communicate with the attestor **over HTTP**
and do not import, link, or vendor any AGPL source. Verified 2026-08-05:

- `packages/typescript/src/attestor.ts` is a self-contained HTTP client. The
  `./attestor.js` import in `client.ts` and `index.ts` resolves to that local file, not
  to `attestor/`.
- No import, `require`, or dependency in any SDK resolves into `attestor/` or
  `@localecore/attestor-core`.
- `cartesi/` likewise contains no imports from `attestor/`.
- All third-party SDK dependencies are permissive:
  - **TypeScript** — `@noble/curves`, `@noble/hashes`, `canonicalize`, `ethers`, `multiformats`
  - **Python** — `httpx`, `pynacl`, `coincurve`, `base58`
  - **C** — MbedTLS (Apache-2.0)

> **Maintainer note:** this separation is what makes MIT available for the SDKs. If an
> SDK ever imports from `attestor/`, MIT is no longer available for that package and it
> becomes AGPL. Re-verify before adding any dependency that crosses that boundary.

## SPDX identifiers

```
Root, cartesi/         AGPL-3.0-only
attestor/              AGPL-3.0-only
packages/typescript/   MIT
packages/python/       MIT
packages/c/            MIT
```

## Third-party attribution

- [`reclaimprotocol/attestor-core`](https://github.com/reclaimprotocol/attestor-core) — AGPL-3.0, the basis of `attestor/`
- [Cartesi](https://cartesi.io) — rollups framework and RISC-V machine
- MbedTLS — Apache-2.0, used by the C SDK

## Questions

For licensing questions or commercial arrangements, please open an issue.
