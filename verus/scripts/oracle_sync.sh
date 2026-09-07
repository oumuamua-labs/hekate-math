#!/usr/bin/env bash

# Fails when build/gf_oracle.rs, the Verus schoolbooks,
# tau_tower, and production TAU disagree: oracle-drift guard.
#
# Usage: verus/scripts/oracle_sync.sh
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2

ORACLE=build/gf_oracle.rs
MODEL=verus/gf_model.rs
FAIL=0

body() {
  awk -v name="$2" '
    index($0, "fn " name "(") { p = 1; next }
    p && /^}/ { exit }
    p { print }
  ' "$1" | tr -d ' \t\n_'
}

pack_args() {
  awk -v s="$1" 'BEGIN {
    d = 0
    for (i = 1; i <= length(s); i++) {
      c = substr(s, i, 1)

      if (c == "(") d++
      if (c == ")") {
        if (d == 0) break
        d--
      }

      if (c == "," && d == 0 && !split_at) split_at = i
    }

    a = substr(s, 1, split_at - 1)
    b = substr(s, split_at + 1, i - split_at - 1)

    sub(/,$/, "", b)
    print a "," b
  }'
}

check() {
  if [ -z "$2" ] || [ -z "$3" ]; then
    echo "error: $1: nothing extracted (oracle: '$2', verus: '$3')" >&2
    FAIL=1
    return
  fi

  if [ "$2" != "$3" ]; then
    echo "error: $1 differs" >&2
    echo "  oracle: $2" >&2
    echo "  verus:  $3" >&2
    FAIL=1
  fi
}

for f in clmul8 reduce8 schoolbook8; do
  check "block8::$f" "$(body $ORACLE $f)" "$(body verus/tower/block8.rs $f)"
done

# sb8 is the oracle's memoized schoolbook8.
for n in 16 32 64 128; do
  o=$(body $ORACLE schoolbook$n | sed 's/sb8(/schoolbook8(/g')
  lo=${o#*letlo=}; lo=${lo%%;*}
  hi=${o#*lethi=}; hi=${hi%%;*}

  v=$(body verus/tower/block$n.rs schoolbook$n)
  v=$(pack_args "${v#*pack(}")

  check "schoolbook$n wiring" "$lo,$hi" "$v"
done

o=$(body $ORACLE schoolbook256)
tau256=$(echo "$o" | sed -n 's/.*constTAU:u128=\(0x[0-9a-f]*\);.*/\1/p')
o=$(echo "$o" | sed "s/,TAU)/,$tau256)/g")

lo=${o#*letlo=}; lo=${lo%%;*}
hi=${o#*lethi=}; hi=${hi%%;*}

v=$(body verus/tower/block256.rs schoolbook256)
v=$(pack_args "${v#(}")

check "schoolbook256 wiring" "$lo,$hi" "$v"

model=$(body $MODEL tau_tower)

for m in 8 16 32 64 128; do
  n=$((m * 2))

  from_model=$(echo "$model" | sed -n "s/.*ifm==$m{\(0x[0-9a-f]*\)}.*/\1/p")
  from_prod=$(grep -h "TAU: Self = Block$m(" src/towers/block$m.rs | sed 's/.*Block[0-9]*(\(0x[0-9a-fA-F_]*\)).*/\1/' | tr -d '_' | tr 'A-F' 'a-f')

  if [ "$n" -eq 256 ]; then
    from_oracle=$tau256
    from_twin=$(body verus/tower/block256.rs schoolbook256 | sed -n 's/.*(ahi,bhi),\(0x[0-9a-f]*\)).*/\1/p')
  else
    from_oracle=$(body $ORACLE schoolbook$n | sed -n 's/.*(a1,b1),\(0x[0-9a-f]*\)).*/\1/p')
    from_twin=$(body verus/tower/block$n.rs schoolbook$n | sed -n 's/.*(a1,b1),\(0x[0-9a-f]*\)).*/\1/p')
  fi

  for pair in "model:$from_model" "production:$from_prod" "oracle:$from_oracle"; do
    src=${pair%%:*}; val=${pair#*:}

    if [ -z "$val" ] || [ "$val" != "$from_twin" ]; then
      echo "error: tau at level $m: $src '$val' != twin '$from_twin'" >&2
      FAIL=1
    fi
  done
done

# POLY_N discharges phi_mult_gen; it must equal modulus(N).
model=$(body $MODEL modulus)

for n in 8 16 32 64 128; do
  from_model=$(echo "$model" | sed -n "s/.*ifk==$n{pow2($n)+\(0x[0-9a-f]*\)}.*/\1/p")
  from_build=$(grep -h "^const POLY_$n: " build/main.rs | sed 's/.*= *\(0x[0-9a-fA-F_]*\);.*/\1/' | tr -d '_' | tr 'A-F' 'a-f')

  if [ -z "$from_model" ] || [ "$from_build" != "$from_model" ]; then
    echo "error: flat modulus at $n: build POLY_$n '$from_build' != model modulus($n) '$from_model'" >&2
    FAIL=1
  fi
done

if [ "$FAIL" -ne 0 ]; then
  exit 1
fi

echo "oracle sync: gf_oracle.rs, the Verus schoolbooks, tau_tower, production TAU, and the flat moduli agree"
