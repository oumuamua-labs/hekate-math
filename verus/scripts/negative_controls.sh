#!/usr/bin/env bash

# Each mutation below must turn its unit red.
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
CONTROLS=0

# -1: no verification result (compile error).
# A by (compute) refutation has no JSON count; stderr names it.
errors_of() {
  local json count refuted

  json=$("$VERUS_BIN" "$1" --verify-root --output-json 2> "$TMP/stderr")
  count=$(echo "$json" | jq -r '
    ."verification-results"
    | if .errors > 0 then .errors
      elif ."encountered-error" then -1
      else 0
      end' 2> /dev/null)

  refuted=$(grep -c 'which evaluates to false' "$TMP/stderr")

  if [ "${count:--1}" = "-1" ] && [ "$refuted" -gt 0 ]; then
    count=$refuted
  fi

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
  local name=$1 file=$2 item=$3 from=$4 to=$5 unit=${6:-$2}
  local hits errors

  CONTROLS=$((CONTROLS + 1))

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
  ' out="$TMP/mutant" "verus/$file")

  if [ "$hits" != "1" ]; then
    echo "error: $name: mutation matched $hits lines in $file, expected 1" >&2
    FAIL=1
    return
  fi

  cp "$TMP/mutant" "$TMP/verus/$file"
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

baseline flat/mul.rs
baseline flat/packed.rs
baseline flat/convert.rs
baseline fft.rs
baseline inverse.rs
baseline flat/promote.rs
baseline flat/bridge.rs
baseline flat/neon_exec.rs
baseline tower/block8.rs
baseline tower/block16.rs
baseline tower/block32.rs
baseline tower/block64.rs
baseline tower/block128.rs
baseline tower/block256.rs
baseline algebra.rs

control fold_0x86 flat/mul.rs 'pub open spec fn mul_flat_128_twin(' \
  'vdupq_n_p64_m(0x87)' \
  'vdupq_n_p64_m(0x86)'

control halves_swapped flat/mul.rs 'pub open spec fn mul_flat_128_twin(' \
  'let lo = d0 ^ vextq_m(zero, mid, 8);' \
  'let lo = d0 ^ vextq_m(mid, zero, 8);'

control fold_dropped flat/mul.rs 'pub open spec fn mul_flat_128_twin(' \
  '(lo ^ fold) ^ carry_mul' \
  '(lo ^ fold)'

control fold64_dropped flat/mul.rs 'pub open spec fn mul_flat_64_twin(' \
  'lo64((prod ^ h_red) ^ c_red)' \
  'lo64(prod ^ h_red)'

control mid_d1_d0 flat/packed.rs 'pub open spec fn reduce_packed_16_lane(' \
  'let mid = (mm ^ ll) ^ hh;' \
  'let mid = mm ^ ll;'

control shift_5320 flat/packed.rs 'pub open spec fn reduce_packed_16_lane(' \
  '((h << 1) ^ h)' \
  '((h << 2) ^ h)'

control tbl_hi_byte flat/packed.rs 'pub open spec fn tbl_hi_8(' \
  'n == 5 { 0x31 }' \
  'n == 5 { 0x30 }'

control tbl_swapped flat/packed.rs 'pub open spec fn reduce_tbl_8_m(' \
  'vqtbl1_m(tbl_lo_8_seq(), h_lo), vqtbl1_m(tbl_hi_8_seq(), h_hi)' \
  'vqtbl1_m(tbl_hi_8_seq(), h_lo), vqtbl1_m(tbl_lo_8_seq(), h_hi)'

control uzp64_his flat/packed.rs 'pub open spec fn mul_flat_packed_64_twin(' \
  'let his = lanes64_u128(vuzp2_m(' \
  'let his = lanes64_u128(vuzp1_m('

control basis_lane0 flat/convert.rs 'pub fn map_ct_128_split_twin(' \
  'let a = basis[i];' \
  'let a = basis[0];'

control lift16_lane0 flat/convert.rs 'pub fn lift_ct_16_twin(' \
  'let bv = basis[i];' \
  'let bv = basis[0];'

control parity_6996 flat/convert.rs 'pub fn tower_bit_64_twin(' \
  '((0x6996u16 >> idx) & 1) as u8' \
  '((0x6996u16 >> idx) & 1) as u8 ^ 1'

control fft_fold_0x86 fft.rs 'fn mul_flat(a: u128, b: u128)' \
  'x = rr ^ 0x87;' \
  'x = rr ^ 0x86;'

control double_noxor fft.rs '    pub fn new(log_n: u32, lift: Vec<u128>)' \
  'twiddles.push(tw ^ l);' \
  'twiddles.push(tw);'

control halve_swapped fft.rs 'fn halve(' \
  'add_flat(p, mul_flat(q, tw))' \
  'add_flat(q, mul_flat(p, tw))'

control fold_right_tw fft.rs '    fn fold(' \
  'tw = add_flat(tw0, self.betas[0]);' \
  'tw = tw0;'

control inv8_chain inverse.rs 'pub open spec fn inv8_twin(' \
  '        x2,' \
  '        x4,'

control inv16_norm inverse.rs 'pub open spec fn inv16_twin(' \
  ' ^ square8_spread(l);' \
  ';'

control trn_phase8 flat/promote.rs 'pub open spec fn phase8_m(' \
  'bytes64(vtrn1_m(lanes64(c[j]), lanes64(c[j + 8])))' \
  'bytes64(vtrn2_m(lanes64(c[j]), lanes64(c[j + 8])))'

control nib_mask flat/promote.rs 'pub open spec fn lo_nib(' \
  'vdup_m8(0x0F, 16)' \
  'vdup_m8(0x07, 16)'

control uzp_hi_bytes flat/promote.rs 'pub open spec fn hi_bytes_16(' \
  'vuzp2_m(bytes16' \
  'vuzp1_m(bytes16'

control tbl_plane flat/promote.rs 'pub open spec fn planes_8(' \
  'vqtbl1_m(tbl[1][j], hi_nib(vals))' \
  'vqtbl1_m(tbl[0][j], hi_nib(vals))'

control uzp_byte4 flat/promote.rs 'pub open spec fn byte_plane_64(' \
  'vuzp2_m(e0_lo, e0_hi)' \
  'vuzp1_m(e0_lo, e0_hi)'

control mul8_bit7 tower/block8.rs 'pub fn mul8(' \
  '{ a7 } else { 0 });' \
  '{ a6 } else { 0 });'

control tau8_fold tower/block8.rs 'pub open spec fn mul_tau8(' \
  '(h1 << 3)' \
  '(h1 << 2)'

control k16_hi tower/block16.rs 'pub open spec fn mul16_k(' \
  'v0 ^ vs)' \
  'v1 ^ vs)'

control tau16_hi tower/block16.rs 'pub open spec fn mul_tau16(' \
  'mul_tau8(a0 ^ a1)' \
  'mul_tau8(a1)'

control k32_hi tower/block32.rs 'pub open spec fn mul32_k(' \
  'v0 ^ vs)' \
  'v1 ^ vs)'

control tau32_hi tower/block32.rs 'pub open spec fn mul_tau32(' \
  'mul_tau16(a0 ^ a1)' \
  'mul_tau16(a1)'

control k64_hi tower/block64.rs 'pub open spec fn mul64_k(' \
  'v0 ^ vs)' \
  'v1 ^ vs)'

control tau64_hi tower/block64.rs 'pub open spec fn mul_tau64(' \
  'mul_tau32(a0 ^ a1)' \
  'mul_tau32(a1)'

control k128_hi tower/block128.rs 'pub open spec fn mul128_k(' \
  'v0 ^ vs)' \
  'v1 ^ vs)'

control tau128_hi tower/block128.rs 'pub open spec fn mul_tau128(' \
  'mul_tau64(a0 ^ a1)' \
  'mul_tau64(a1)'

control k256_hi tower/block256.rs 'pub open spec fn mul256_k(' \
  'v0 ^ vs)' \
  'v1 ^ vs)'

control sq16_hi algebra.rs 'pub open spec fn square16_twin(' \
  'pack(l2 ^ mul_tau8(h2), h2)' \
  'pack(l2 ^ mul_tau8(h2), l2)'

control frob_mod15 algebra.rs 'pub open spec fn frobenius16_twin(' \
  '(k % 16)' \
  '(k % 15)'

control trace_shift algebra.rs 'pub open spec fn trace_iter16(' \
  '^ sq_iter16(x, (n - 1) as nat)' \
  '^ sq_iter16(x, n)'

control tau8_trace gf_model.rs 'pub open spec fn tau_tower(' \
  'if m == 8 {' \
  'if m == 9 {' \
  algebra.rs

control pmull_shift flat/neon_t.rs 'pub open spec fn vmull_p64_m(' \
  '(vmull_p64_m(a / 2, b) << 1)' \
  '(vmull_p64_m(a / 2, b) << 2)' \
  flat/bridge.rs

control tbl_range flat/neon_t.rs 'pub open spec fn vqtbl1_m(' \
  'idx[i] < 16' \
  'idx[i] < 15' \
  flat/packed.rs

control trn1_lane flat/neon_t.rs 'pub open spec fn vtrn1_m<T>(' \
  'b[i - 1]' \
  'b[i]' \
  flat/promote.rs

control bytes64_be flat/neon_t.rs 'pub open spec fn bytes64(' \
  '(8 * (i % 8))' \
  '(8 * (7 - i % 8))' \
  flat/promote.rs

control pmull2_lane flat/neon_t.rs 'pub open spec fn vmull_high_p64_m(' \
  'vmull_p64_m(hi64(a), hi64(b))' \
  'vmull_p64_m(lo64(a), hi64(b))' \
  flat/mul.rs

control ext_order flat/neon_t.rs 'pub open spec fn vextq_m(' \
  '(a >> ((8 * n) as u128)) | (b << ((128 - 8 * n) as u128))' \
  '(b >> ((8 * n) as u128)) | (a << ((128 - 8 * n) as u128))' \
  flat/mul.rs

control dup64_lane flat/neon_t.rs 'pub open spec fn vdupq_n_p64_m(' \
  '(x as u128) | ((x as u128) << 64)' \
  '(x as u128)' \
  flat/mul.rs

control dup64_exec flat/neon_t.rs 'pub open spec fn vdupq_n_p64_m(' \
  '(x as u128) | ((x as u128) << 64)' \
  '(x as u128)' \
  flat/neon_exec.rs

if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

echo "negative controls: $CONTROLS mutants, all red"
