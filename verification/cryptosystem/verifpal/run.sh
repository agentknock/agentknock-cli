#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
suite_dir=$(dirname -- "$script_dir")
(cd "$suite_dir/../.." && sha256sum -c "$suite_dir/SPECIFICATION.sha256")
ulimit -v 8388608
exec 9>/tmp/agentknock-cryptosystem-verifpal.lock
flock -n 9 || { echo 'another Agentknock Verifpal runner is active' >&2; exit 1; }

verifpal_store=$(nix build "path:$suite_dir#verifpal" --cores 2 --max-jobs 1 --no-link --print-out-paths)
verifpal_bin=$verifpal_store/bin/verifpal
version=$("$verifpal_bin" --version)
if [[ $version != 'verifpal 1.4.3' ]]; then
  printf 'unexpected Verifpal version: %s\n' "$version" >&2
  exit 1
fi
printf '%s\n' "$version"

tmp_dir=$(mktemp -d /tmp/agentknock-verifpal.XXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
python3 -B "$suite_dir/check_results.py" verifpal-cases "$script_dir" > "$tmp_dir/cases"
while read -r model mode sessions; do
  printf '%s %s sessions=%s ... ' "$model" "$mode" "$sessions"
  args=()
  if [[ $mode == auto ]]; then args=(--auto-queries); fi
  if ! timeout --kill-after=20s 15m "$verifpal_bin" verify "$script_dir/$model.vp" \
      --format json --quiet --sessions "$sessions" "${args[@]}" \
      > "$tmp_dir/report.json" 2> "$tmp_dir/stderr"; then
    cat "$tmp_dir/stderr" "$tmp_dir/report.json" >&2
    exit 1
  fi
  python3 -B "$suite_dir/check_results.py" verifpal "$tmp_dir/report.json" \
    "$script_dir/cases.json" "$model" "$mode" "$sessions"
done < "$tmp_dir/cases"
printf 'Verifpal: every registered analysis matched its complete verdict and search envelope.\n'
