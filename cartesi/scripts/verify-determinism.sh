#!/usr/bin/env bash
#
# Machine-level determinism acceptance test.
#
# Builds nothing — run `npx cartesi build` first. This loads the built machine,
# feeds it a rollup input, and prints the resulting state root hash. Running it
# with identical inputs must produce an identical hash; that is what lets two
# honest validators converge and makes fraud proofs meaningful.
#
# Three checks:
#   A vs B  identical input        -> hashes MUST match  (determinism)
#   A vs C  input + 1h block time  -> hashes MUST differ (block time reaches state,
#                                     i.e. the test is not vacuous)
#
# Usage:
#   npx cartesi build
#   ./scripts/verify-determinism.sh
#
# Requires: docker, and a machine built into .cartesi/image.
set -euo pipefail

CARTESI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${CARTESI_DIR}/.cartesi"
SDK="cartesi/sdk:0.9.0"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ ! -d "${IMAGE}/image" ]; then
  echo "error: no machine at ${IMAGE}/image — run 'npx cartesi build' first" >&2
  exit 1
fi

BASE_TS=1785974400   # a fixed, realistic block time
SENDER=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266

# Rollup input metadata is 5 big-endian 32-byte words:
#   msg_sender, block_number, timestamp, epoch_index, input_index
gen_input() {
  local dir="$1" ts="$2"
  mkdir -p "$dir"
  python3 - "$dir" "$ts" "$SENDER" <<'PY'
import base64, json, sys
d, ts, sender = sys.argv[1], int(sys.argv[2]), sys.argv[3]
w = lambda v: v.to_bytes(32, 'big')
meta = w(int(sender, 16)) + w(100) + w(ts) + w(0) + w(0)
# set_encryption_key is accepted via the bootstrap path and, like every accepted
# advance, causes chain_clock to be written from metadata.timestamp.
payload = json.dumps({
    "action": "set_encryption_key",
    "public_key": base64.b64encode(bytes(range(32))).decode(),
}).encode()
open(f"{d}/epoch-0-input-0.bin", "wb").write(payload)
open(f"{d}/epoch-0-input-metadata-0.bin", "wb").write(meta)
PY
}

cat > "$WORK/run.sh" <<'EOF'
set -e
jsonrpc-remote-cartesi-machine --server-address=127.0.0.1:5002 >/tmp/server.log 2>&1 &
sleep 1.5
cartesi-machine \
  --remote-address=127.0.0.1:5002 --remote-protocol=jsonrpc \
  --load=/data/image --final-hash \
  --rollup-advance-state=epoch_index:0,input_index_begin:0,input_index_end:1 \
  --remote-shutdown 2>&1
EOF

run_machine() {
  docker run --rm \
    -v "${IMAGE}:/data:ro" -v "$1:/work" -v "$WORK/run.sh:/run.sh:ro" -w /work \
    "$SDK" bash /run.sh 2>&1 | grep -oE '[0-9a-f]{64}' | tail -1
}

gen_input "$WORK/A" "$BASE_TS"
gen_input "$WORK/B" "$BASE_TS"
gen_input "$WORK/C" "$((BASE_TS + 3600))"

echo "Running machine three times (this takes a few minutes)..."
HASH_A=$(run_machine "$WORK/A"); echo "  A (ts=$BASE_TS)            $HASH_A"
HASH_B=$(run_machine "$WORK/B"); echo "  B (ts=$BASE_TS, identical) $HASH_B"
HASH_C=$(run_machine "$WORK/C"); echo "  C (ts=$((BASE_TS + 3600)))            $HASH_C"

echo
fail=0
if [ "$HASH_A" = "$HASH_B" ]; then
  echo "PASS  determinism: identical input -> identical state root"
else
  echo "FAIL  determinism: identical input produced DIFFERENT state roots"; fail=1
fi
if [ "$HASH_A" != "$HASH_C" ]; then
  echo "PASS  block time reaches state: different block time -> different state root"
else
  echo "FAIL  block time does NOT reach state — the determinism check above is vacuous"; fail=1
fi

exit $fail
