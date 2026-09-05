#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cryptosystem_dir=$(cd -- "$script_dir/.." && pwd)
(cd "$cryptosystem_dir/../.." && sha256sum -c "$cryptosystem_dir/SPECIFICATION.sha256")
if [[ -n ${PROVERIF:-} ]]; then
  proverif_bin=$PROVERIF
else
  proverif_store=$(
    nix build "path:$cryptosystem_dir#proverif" --cores 2 --max-jobs 1 --no-link --print-out-paths
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
  recorded_exchange_psk_disclosure
  recorded_exchange_device_key_disclosure
  recorded_exchange_context_disclosure
)

declare -A expected=(
  [paired_exchange]='false true true true true true true'
  [pairing_activation]='false true true true true true true true true'
  [rotation_step]='false true true true true true true true true'
  [version_binding]='false true'
  [psk_compromise]='true true true false false'
  [device_key_compromise]='false false false'
  [address_offline_guess]='false'
  [negative_pairing_mitm]='false false'
  [negative_missing_context_binding]='false'
  [negative_missing_record_sequence]='false'
  [negative_missing_version_binding]='false'
  [recorded_exchange_psk_disclosure]='equivalent'
  [recorded_exchange_device_key_disclosure]='distinguisher'
  [recorded_exchange_context_disclosure]='distinguisher'
)

ulimit -v 2097152
exec 9>/tmp/agentknock-cryptosystem-proverif.lock
flock -n 9 || { echo 'another Agentknock ProVerif runner is active' >&2; exit 1; }
python3 -B "$cryptosystem_dir/check_results.py" inventory proverif "$script_dir" "${models[@]}"
output_file=$(mktemp)
trap 'rm -f -- "$output_file"' EXIT

printf '%s\n' "$actual_banner"
for model in "${models[@]}"; do
  printf '\n## %s.pv\n' "$model"
  args=()
  if [[ $model == recorded_exchange_* ]]; then
    args=(-lib "$script_dir/recorded_exchange")
  fi
  if ! timeout --kill-after=10s 3m "$proverif_bin" "${args[@]}" "$script_dir/$model.pv" >"$output_file" 2>&1; then
    cat "$output_file" >&2
    exit 1
  fi
  python3 -B "$cryptosystem_dir/check_results.py" proverif "$output_file" "${expected[$model]}"
  if $full_output; then
    sed -n '1,$p' "$output_file"
  else
    sed -n '/Verification summary:/,/^---/p' "$output_file"
  fi
done
