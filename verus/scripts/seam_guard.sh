#!/usr/bin/env bash
# Fails when files with Verus twins change without
# a verus/ change in the same range: twin-drift guard.
#
# Usage: verus/scripts/seam_guard.sh [BASE_REF]
# SEAM_ACK=1 skips after human review ('seam-ack' PR label in CI).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE="${1:-origin/main}"

git rev-parse --verify --quiet "$BASE^{commit}" > /dev/null || {
  echo "error: base ref '$BASE' not found" >&2
  exit 2
}

SEAM="src/towers src/fft/additive.rs src/algebra.rs src/hardware.rs src/packable.rs build"

# shellcheck disable=SC2086
CHANGED=$(git diff --name-only "$BASE"...HEAD -- $SEAM)

# Docs/scripts under verus/ are not re-sync evidence
TWINS=$(git diff --name-only "$BASE"...HEAD -- verus/ | grep '\.rs$' || true)

if [ -z "$CHANGED" ]; then
  echo "seam guard: no twinned production files changed"
  exit 0
fi

if [ -n "$TWINS" ]; then
  echo "seam guard: production and verus/ changed together; twins assumed re-synced:"
  echo "$CHANGED" | sed 's/^/  /'
  exit 0
fi

if [ "${SEAM_ACK:-0}" = "1" ]; then
  echo "seam guard: overridden by SEAM_ACK; twinned files changed without verus/:"
  echo "$CHANGED" | sed 's/^/  /'
  exit 0
fi

echo "error: twinned production files changed with no verus/ change:" >&2
echo "$CHANGED" | sed 's/^/  /' >&2
echo "" >&2
echo "Re-sync the Verus twins (seam rows in verus/TRUSTED_AXIOMS.md)," >&2
echo "or, if no twinned kernel was touched, set SEAM_ACK=1" >&2
echo "(CI: apply the 'seam-ack' PR label)." >&2
exit 1
