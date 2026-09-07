#!/usr/bin/env bash

# Each twin mutation below must turn its unit red.
#
# Usage: verus/scripts/negative_controls.sh
# Binary from $VERUS, then `verus` on PATH. Requires jq.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

VERUS_BIN="${VERUS:-$(command -v verus || true)}"

if [ -z "$VERUS_BIN" ]; then
  echo "error: verus not found; set VERUS=/path/to/verus" >&2
  exit 2
fi

if ! command -v jq > /dev/null; then
  echo "error: jq is required" >&2
  exit 2
fi

TMP=$(mktemp -d)

if [ ! -d "$TMP" ]; then
  echo "error: mktemp -d failed" >&2
  exit 2
fi

trap 'rm -rf "$TMP"' EXIT

FAIL=0

# -1: no verification result (compile error).
errors_of() {
  local json count

  json=$("$VERUS_BIN" "$1" --verify-root --output-json 2> "$TMP/stderr")
  count=$(echo "$json" | jq -r '
    ."verification-results"
    | if .errors > 0 then .errors
      elif ."encountered-error" then -1
      else 0
      end' 2> /dev/null)

  echo "${count:--1}"
}

baseline() {
  local errors

  errors=$(errors_of "verus/$1")

  if [ "$errors" != "0" ]; then
    echo "error: baseline $1 is not green ($errors); run verus/scripts/verify.sh first" >&2
    exit 2
  fi
}

control() {
  local name=$1 unit=$2 item=$3 from=$4 to=$5
  local hits errors

  rm -rf "$TMP/verus"
  cp -r verus "$TMP/verus"

  hits=$(awk -v item="$item" -v from="$from" -v to="$to" '
    index($0, item) == 1 { inside = 1 }
    inside && index($0, from) {
      n = index($0, from)
      $0 = substr($0, 1, n - 1) to substr($0, n + length(from))
      hits++
    }
    inside && /^}/ { inside = 0 }
    { print > out }
    END { print hits + 0 }
  ' out="$TMP/mutant" "verus/$unit")

  if [ "$hits" != "1" ]; then
    echo "error: $name: mutation matched $hits lines in $unit, expected 1" >&2
    FAIL=1
    return
  fi

  cp "$TMP/mutant" "$TMP/verus/$unit"
  errors=$(errors_of "$TMP/verus/$unit")

  case "$errors" in
    -1)
      echo "error: $name: mutant does not compile" >&2
      sed 's/^/  /' "$TMP/stderr" >&2
      FAIL=1
      ;;
    0)
      echo "error: $name: verus accepted the mutant; the proof is vacuous" >&2
      FAIL=1
      ;;
    *)
      printf "  RED  %-14s %s errors\n" "$name" "$errors"
      ;;
  esac
}

baseline neon/flat.rs
baseline neon/packed.rs
baseline neon/convert.rs
baseline fft.rs
baseline inverse.rs
baseline neon/promote.rs

control fold_0x86 neon/flat.rs 'pub open spec fn mul_flat_128_twin(' \
  'vmull_p64_m(c2, 0x87)' \
  'vmull_p64_m(c2, 0x86)'

control halves_swapped neon/flat.rs 'pub open spec fn mul_flat_128_twin(' \
  '((final_0 as u128) | ((final_1 as u128) << 64))' \
  '((final_1 as u128) | ((final_0 as u128) << 64))'

control fold_dropped neon/flat.rs 'pub open spec fn mul_flat_128_twin(' \
  '<< 64))) ^ carry_mul' \
  '<< 64)))'

control mid_d1_d0 neon/packed.rs 'pub open spec fn reduce_packed_16_lane(' \
  'let mid = (mm ^ ll) ^ hh;' \
  'let mid = mm ^ ll;'

control shift_5320 neon/packed.rs 'pub open spec fn reduce_packed_16_lane(' \
  '((h << 1) ^ h)' \
  '((h << 2) ^ h)'

control tbl_hi_byte neon/packed.rs 'pub open spec fn tbl_hi_8(' \
  'n == 5 { 0x31 }' \
  'n == 5 { 0x30 }'

control tbl_swapped neon/packed.rs 'pub open spec fn reduce_tbl_8_m(' \
  'vqtbl1_m(tbl_lo_8_seq(), h_lo), vqtbl1_m(tbl_hi_8_seq(), h_hi)' \
  'vqtbl1_m(tbl_hi_8_seq(), h_lo), vqtbl1_m(tbl_lo_8_seq(), h_hi)'

control basis_lane0 neon/convert.rs 'fn map_ct_128_split_twin(' \
  'let b = basis[i];' \
  'let b = basis[0];'

control lift16_lane0 neon/convert.rs 'fn lift_ct_16_twin(' \
  'let bv = basis[i];' \
  'let bv = basis[0];'

control parity_6996 neon/convert.rs 'fn tower_bit_64_twin(' \
  '((0x6996u16 >> idx) & 1) as u8' \
  '((0x6996u16 >> idx) & 1) as u8 ^ 1'

control fft_fold_0x86 fft.rs 'fn mul_flat(a: u128, b: u128)' \
  'x = rr ^ 0x87;' \
  'x = rr ^ 0x86;'

control inv8_chain inverse.rs 'pub open spec fn inv8_twin(' \
  '        x2,' \
  '        x4,'

control inv16_norm inverse.rs 'pub open spec fn inv16_twin(' \
  ' ^ square8_spread(l);' \
  ';'

control trn_phase8 neon/promote.rs 'pub open spec fn phase8_m(' \
  'bytes64(vtrn1_m(lanes64(c[j]), lanes64(c[j + 8])))' \
  'bytes64(vtrn2_m(lanes64(c[j]), lanes64(c[j + 8])))'

control nib_mask neon/promote.rs 'pub open spec fn lo_nib(' \
  'vdup_m8(0x0F, 16)' \
  'vdup_m8(0x07, 16)'

control uzp_hi_bytes neon/promote.rs 'pub open spec fn hi_bytes_16(' \
  'vuzp2_m(bytes16' \
  'vuzp1_m(bytes16'

control tbl_plane neon/promote.rs 'pub open spec fn planes_8(' \
  'vqtbl1_m(tbl[1][j], hi_nib(vals))' \
  'vqtbl1_m(tbl[0][j], hi_nib(vals))'

control uzp_byte4 neon/promote.rs 'pub open spec fn byte_plane_64(' \
  'vuzp2_m(e0_lo, e0_hi)' \
  'vuzp1_m(e0_lo, e0_hi)'

if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

echo "negative controls: 18 mutants, all red"
