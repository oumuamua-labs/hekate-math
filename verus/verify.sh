#!/usr/bin/env bash
# nextest-style runner for the verus/ proof tree:
# one PASS line per function discharged by the solver,
# per proof unit, then the tool's own verified/error counts.
#
# Usage:
#   verus/verify.sh              # every unit under verus/
#   verus/verify.sh verus/neon/flat.rs [...]
#
# Binary resolution: $VERUS, then `verus` on PATH. Requires jq.
set -uo pipefail

VERUS_BIN="${VERUS:-$(command -v verus || true)}"
DELAY_S=$(awk "BEGIN { print ${VERIFY_DELAY_MS:-0} / 1000 }")

if [ -z "$VERUS_BIN" ]; then
  echo "error: verus not found; set VERUS=/path/to/verus" >&2
  exit 2
fi

if ! command -v jq > /dev/null; then
  echo "error: jq is required" >&2
  exit 2
fi

if [ "$#" -gt 0 ]; then
  FILES="$*"
else
  FILES=$(find verus -name '*.rs' | sort)
fi

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

  echo ""
  echo "${BLD}${CYN}━━ ${f}${RST}"

  JSON=$("$VERUS_BIN" "$f" --time-expanded --output-json 2> "$STDERR_LOG")

  OK=$(echo "$JSON" | jq -r '."verification-results".success // false')
  VERIFIED=$(echo "$JSON" | jq -r '."verification-results".verified // 0')
  ERRORS=$(echo "$JSON" | jq -r '."verification-results".errors // 999')

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
    UNITS_OK=$((UNITS_OK + 1))
    printf "  %s→ %s verified, %s errors%s\n" "$DIM" "$VERIFIED" "$ERRORS" "$RST"
  else
    printf "  %s→ %s verified, %s errors%s\n" "$RED" "$VERIFIED" "$ERRORS" "$RST"
    sed 's/^/  /' "$STDERR_LOG"
  fi

  TOTAL_VERIFIED=$((TOTAL_VERIFIED + VERIFIED))
  TOTAL_ERRORS=$((TOTAL_ERRORS + ERRORS))
done

WALL=$((SECONDS - START))

echo ""
echo "${BLD}────────────────────────────────────────────────────────${RST}"

if [ "$TOTAL_ERRORS" -eq 0 ] && [ "$UNITS_OK" -eq "$UNITS" ]; then
  echo "${BLD} Summary${RST} [${WALL}s] ${GRN}${BLD}${TOTAL_VERIFIED} verified${RST} · 0 errors · ${UNITS_OK}/${UNITS} units"
  exit 0
fi

echo "${BLD} Summary${RST} [${WALL}s] ${TOTAL_VERIFIED} verified · ${RED}${BLD}${TOTAL_ERRORS} errors${RST} · ${UNITS_OK}/${UNITS} units"
exit 1
