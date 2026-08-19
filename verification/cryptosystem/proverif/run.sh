#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cryptosystem_dir=$(cd -- "$script_dir/.." && pwd)
if [[ -n ${PROVERIF:-} ]]; then
  proverif_bin=$PROVERIF
else
  proverif_store=$(
    nix build "path:$cryptosystem_dir#proverif" --no-link --print-out-paths
  )
  proverif_bin=$proverif_store/bin/proverif
fi
expected_banner='Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre'

actual_banner=$("$proverif_bin" -help 2>&1 | sed -n '1p')
if [[ $actual_banner != "$expected_banner" ]]; then
  printf 'Expected: %s\nActual:   %s\n' "$expected_banner" "$actual_banner" >&2
  exit 1
fi

case ${1:-summary} in
  summary)
    full_output=false
    ;;
  --full)
    full_output=true
    ;;
  *)
    printf 'Usage: %s [--full]\n' "$0" >&2
    exit 2
    ;;
esac

models=(
  paired_exchange
  pairing_activation
  rotation_step
  version_binding
  psk_compromise
  device_key_compromise
  address_offline_guess
  negative_pairing_mitm
  negative_missing_context_binding
  negative_missing_record_sequence
  negative_missing_version_binding
)

declare -A expected=(
  [paired_exchange]='false true true true true true true'
  [pairing_activation]='false true true true true true true true true'
  [rotation_step]='false true true true true true true true true'
  [version_binding]='false true'
  [psk_compromise]='true false'
  [device_key_compromise]='false false false'
  [address_offline_guess]='false'
  [negative_pairing_mitm]='false false'
  [negative_missing_context_binding]='false'
  [negative_missing_record_sequence]='false'
  [negative_missing_version_binding]='false'
)

output_file=$(mktemp)
trap 'rm -f -- "$output_file"' EXIT

printf '%s\n' "$actual_banner"
for model in "${models[@]}"; do
  printf '\n## %s.pv\n' "$model"
  "$proverif_bin" "$script_dir/$model.pv" >"$output_file" 2>&1
  actual=$(
    sed -n '/Verification summary:/,/^---/p' "$output_file" |
      sed -nE 's/^(Query|Weak secret).* is (true|false)\.?$/\2/p' |
      paste -sd ' ' -
  )
  if [[ $actual != "${expected[$model]}" ]]; then
    printf 'Unexpected verdict vector for %s.pv\nExpected: %s\nActual:   %s\n' \
      "$model" "${expected[$model]}" "$actual" >&2
    sed -n '/Verification summary:/,/^---/p' "$output_file" >&2
    exit 1
  fi
  if $full_output; then
    sed -n '1,$p' "$output_file"
  else
    sed -n '/Verification summary:/,/^---/p' "$output_file"
  fi
done
