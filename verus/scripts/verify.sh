#!/usr/bin/env bash

# nextest-style runner for the verus/ proof tree:
# one PASS line per function discharged by the solver,
# per proof unit, then the tool's own verified/error counts.
#
# Usage:
#   verus/scripts/verify.sh # every unit under verus/
#   verus/scripts/verify.sh verus/neon/flat.rs [...]
#
# Runs from the repo root; unit paths are repo-relative.
# Binary resolution:
# $VERUS, then `verus` on PATH.
# VERUS_SEED=N sets the Z3 random seed.
# Requires jq.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

VERUS_BIN="${VERUS:-$(command -v verus || true)}"
DELAY_S=$(awk "BEGIN { print ${VERIFY_DELAY_MS:-0} / 1000 }")
SEED_ARGS=${VERUS_SEED:+--smt-option smt.random_seed=$VERUS_SEED}

# Z3 silently ignores a malformed seed value.
case "${VERUS_SEED:-0}" in
  *[!0-9]*)
    echo "error: VERUS_SEED must be an unsigned integer, got '$VERUS_SEED'" >&2
    exit 2
    ;;
esac

if [ -z "$VERUS_BIN" ]; then
  echo "error: verus not found; set VERUS=/path/to/verus" >&2
  exit 2
fi

if ! command -v jq > /dev/null; then
  echo "error: jq is required" >&2
  exit 2
fi

# Silent-shrink guard: bump with TRUSTED_AXIOMS.md.
EXPECTED_EXTERNAL_BODY=4
EXPECTED_VERIFIED=2872

# The whole verifier::external* family is trusted;
# only external_body, only in axioms_t.rs, only on its own line.
EXTERNAL=$(grep -rnE --include='*.rs' '#\[verifier::external' verus || true)
EXTERNAL_TOTAL=$(printf '%s\n' "$EXTERNAL" | grep -c .)
EXTERNAL_BODY=$(printf '%s\n' "$EXTERNAL" \
  | grep -cE '^verus/axioms_t\.rs:[0-9]+:[[:space:]]*#\[verifier::external_body\]$')

if [ "$EXTERNAL_BODY" -ne "$EXPECTED_EXTERNAL_BODY" ] || [ "$EXTERNAL_TOTAL" -ne "$EXTERNAL_BODY" ]; then
  echo "error: expected exactly $EXPECTED_EXTERNAL_BODY external_body items, all in verus/axioms_t.rs; found:" >&2
  printf '%s\n' "$EXTERNAL" | sed 's/^/  /' >&2
  exit 2
fi

# axiom fn verifies with no body;
# it must never appear here.
FORBIDDEN=$(grep -rnE --include='*.rs' \
  '\badmit\(\)|\bassume\(|assume_specification|axiom[[:space:]]+fn' verus || true)

if [ -n "$FORBIDDEN" ]; then
  echo "error: unproven items under verus/:" >&2
  echo "$FORBIDDEN" | sed 's/^/  /' >&2
  exit 2
fi

FULL=0

if [ "$#" -gt 0 ]; then
  FILES="$*"
else
  FULL=1
  FILES=$(find verus -name '*.rs' | sort)
  N=$(echo "$FILES" | wc -l | tr -d ' ')

  # Silent-shrink guard:
  # bump when adding or removing a proof file.
  if [ "$N" -ne 18 ]; then
    echo "error: expected 18 verus files, found $N" >&2
    exit 2
  fi

  # axioms_t.rs is a #[path] child of gf_model.rs,
  # verified through every unit including it, not a root.
  FILES=$(echo "$FILES" | grep -v '/axioms_t\.rs$')
fi

GHA="${GITHUB_ACTIONS:-}"

if [ -t 1 ]; then
  GRN=$'\033[32m' RED=$'\033[31m' CYN=$'\033[36m'
  BLD=$'\033[1m' DIM=$'\033[2m' RST=$'\033[0m'
else
  GRN="" RED="" CYN="" BLD="" DIM="" RST=""
fi

START=$SECONDS
TOTAL_VERIFIED=0
TOTAL_ERRORS=0
UNITS=0
UNITS_OK=0
STDERR_LOG=$(mktemp)

trap 'rm -f "$STDERR_LOG"' EXIT

for f in $FILES; do
  UNITS=$((UNITS + 1))

  if [ -n "$GHA" ]; then
    echo "::group::verus $f"
  else
    echo ""
    echo "${BLD}${CYN}━━ ${f}${RST}"
  fi

  # shellcheck disable=SC2086
  JSON=$("$VERUS_BIN" "$f" $SEED_ARGS --time-expanded --output-json 2> "$STDERR_LOG")

  OK=$(echo "$JSON" | jq -r '."verification-results".success // false')
  VERIFIED=$(echo "$JSON" | jq -r '."verification-results".verified // 0')
  ERRORS=$(echo "$JSON" | jq -r '."verification-results".errors // 999')

  [ -n "$OK" ] || OK=false
  [ -n "$VERIFIED" ] || VERIFIED=0
  [ -n "$ERRORS" ] || ERRORS=0

  echo "$JSON" | jq -r '
    ."times-ms".smt."smt-run-module-times"[]
    | ."function-breakdown"[]
    | [(if .success then "PASS" else "FAIL" end),
       ((.["time-micros"] / 100 | round) / 10),
       .["mode:"],
       .function]
    | @tsv' |
    while IFS=$'\t' read -r ST MS MODE FN; do
      if [ "$ST" = "PASS" ]; then C=$GRN; else C=$RED; fi
      printf "  %s%s%s [%7sms] %-5s %s\n" "$C" "$ST" "$RST" "$MS" "$MODE" "$FN"

      if [ "$DELAY_S" != "0" ]; then
        sleep "$DELAY_S"
      fi
    done

  if [ "$OK" = "true" ] && [ "$ERRORS" = "0" ]; then
    UNIT_OK=1
    UNITS_OK=$((UNITS_OK + 1))
    printf "  %s-> %s verified, %s errors%s\n" "$DIM" "$VERIFIED" "$ERRORS" "$RST"
  else
    UNIT_OK=0
    printf "  %s-> %s verified, %s errors%s\n" "$RED" "$VERIFIED" "$ERRORS" "$RST"
    sed 's/^/  /' "$STDERR_LOG"
  fi

  if [ -n "$GHA" ]; then
    echo "::endgroup::"

    if [ "$UNIT_OK" -eq 0 ]; then
      echo "::error file=$f::Verus verification failed"
    fi
  fi

  TOTAL_VERIFIED=$((TOTAL_VERIFIED + VERIFIED))
  TOTAL_ERRORS=$((TOTAL_ERRORS + ERRORS))
done

WALL=$((SECONDS - START))

echo ""
echo "${BLD}────────────────────────────────────────────────────────${RST}"

if [ "$TOTAL_ERRORS" -eq 0 ] && [ "$UNITS_OK" -eq "$UNITS" ]; then
  echo "${BLD} Summary${RST} [${WALL}s] ${GRN}${BLD}${TOTAL_VERIFIED} verified${RST} · 0 errors · ${UNITS_OK}/${UNITS} units"

  if [ "$FULL" -eq 1 ] && [ "$TOTAL_VERIFIED" -ne "$EXPECTED_VERIFIED" ]; then
    echo "error: expected $EXPECTED_VERIFIED verified, got $TOTAL_VERIFIED; update EXPECTED_VERIFIED and README.md together" >&2
    exit 1
  fi

  exit 0
fi

echo "${BLD} Summary${RST} [${WALL}s] ${TOTAL_VERIFIED} verified · ${RED}${BLD}${TOTAL_ERRORS} errors${RST} · ${UNITS_OK}/${UNITS} units"
exit 1
