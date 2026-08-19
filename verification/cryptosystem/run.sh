#!/usr/bin/env bash
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)

cd "$repo_dir"
sha256sum -c "$script_dir/SPECIFICATION.sha256"

printf '\n== Tamarin ==\n'
bash "$script_dir/tamarin/run.sh"

printf '\n== ProVerif ==\n'
bash "$script_dir/proverif/run.sh"

printf '\n== Verifpal ==\n'
bash "$script_dir/verifpal/run.sh"

printf '\nAll cryptosystem verification portfolios matched their recorded verdicts.\n'
