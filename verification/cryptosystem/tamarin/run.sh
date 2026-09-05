#!/usr/bin/env bash
set -eu

if [ "$#" -gt 2 ]; then
  printf 'usage: %s [theory [lemma]]\n' "$0" >&2
  exit 2
fi

theory_filter=${1-}
lemma_filter=${2-}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
suite_dir=$(dirname -- "$script_dir")

python3 -B "$suite_dir/check_results.py" tamarin-inventory "$script_dir"
(cd "$suite_dir/../.." && sha256sum -c "$suite_dir/SPECIFICATION.sha256")
ulimit -v 8388608

lock_file=/tmp/agentknock-cryptosystem-tamarin.lock
exec 9>"$lock_file"
if ! flock -n 9; then
  printf 'another Agentknock Tamarin runner is active\n' >&2
  exit 1
fi

tmp_dir=$(mktemp -d /tmp/agentknock-tamarin.XXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

tamarin_store=$(nix build "path:$suite_dir#tamarin" --cores 2 --max-jobs 1 --no-link --print-out-paths)
tamarin_bin=$tamarin_store/bin/tamarin-prover

version_output=$($tamarin_bin --version +RTS -M384m -N1 -RTS 2>&1)
case $version_output in
  *'Tamarin version 1.12.0'*'Maude version 3.5.1'*) ;;
  *)
    printf 'unexpected Tamarin toolchain:\n%s\n' "$version_output" >&2
    exit 1
    ;;
esac

run_lemma() {
  theory=$1
  lemma=$2
  heuristic=$3
  strategy=$4
  model=$script_dir/$theory.spthy
  output=$tmp_dir/$theory--$lemma.out

  if [ -n "$theory_filter" ] && [ "$theory_filter" != "$theory" ]; then
    return
  fi
  if [ -n "$lemma_filter" ] && [ "$lemma_filter" != "$lemma" ]; then
    return
  fi

  selected=$((selected + 1))
  printf '%s/%s ... ' "$theory" "$lemma"

  set +e
  timeout --signal=TERM --kill-after=20s 3m \
    "$tamarin_bin" \
      --derivcheck-timeout=120 \
      --quit-on-warning \
      --heuristic="$heuristic" \
      --stop-on-trace="$strategy" \
      --quiet \
      --prove="$lemma" \
      "$model" \
      +RTS -M384m -N1 -RTS \
      >"$output" 2>&1
  status=$?
  set -e

  if [ "$status" -ne 0 ]; then
    printf 'FAILED (exit %s)\n' "$status" >&2
    tail -n 30 "$output" >&2
    exit "$status"
  fi

  if ! grep -Eq "^  $lemma \\((all-traces|exists-trace)\\): verified" "$output"; then
    printf 'FAILED (no exact verified verdict)\n' >&2
    sed -n '/summary of summaries:/,$p' "$output" >&2
    exit 1
  fi

  printf 'verified\n'
}

selected=0
while read -r theory lemma heuristic strategy; do
  [ -n "$theory" ] || continue
  run_lemma "$theory" "$lemma" "$heuristic" "$strategy"
done < "$script_dir/cases.tsv"

if [ "$selected" -eq 0 ]; then
  printf 'no proof case matched the requested filter\n' >&2
  exit 2
fi

printf 'Tamarin: %s/%s selected lemmas verified sequentially.\n' \
  "$selected" "$selected"
