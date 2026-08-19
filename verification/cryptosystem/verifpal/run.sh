#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cryptosystem_dir="$(cd "${script_dir}/.." && pwd)"

verifpal_store="$(
	nix build "path:${cryptosystem_dir}#verifpal" \
		--no-link \
		--print-out-paths
)"
verifpal_bin="${verifpal_store}/bin/verifpal"

version="$(${verifpal_bin} --version)"
if [[ "${version}" != "verifpal 1.0.0" ]]; then
	printf 'unexpected Verifpal version: %s\n' "${version}" >&2
	exit 1
fi
printf '%s\n' "${version}"

models=(
	pairing_activation.vp
	paired_exchange.vp
	rotation.vp
	compromise_psk.vp
	compromise_device_key.vp
	psk_holder_authority.vp
	negative_missing_request_id.vp
	negative_record_key_reuse.vp
	negative_rotation_candidate_pre_gate.vp
)

declare -A expected=(
	[pairing_activation.vp]=c1c1e1c0c0c0a0a0a0e0e0e0
	[paired_exchange.vp]=c0c0c0a0a0a0e0e0e0f0f0f0
	[rotation.vp]=c0c0c0a0a0e0e0
	[compromise_psk.vp]=c0e0
	[compromise_device_key.vp]=c1c1c1c1c1
	[psk_holder_authority.vp]=e0e0
	[negative_record_key_reuse.vp]=e1e1
	[negative_rotation_candidate_pre_gate.vp]=e1
)

status=0
for sessions in 1 2 4 8; do
	for model in "${models[@]}"; do
		want="${expected[${model}]:-}"
		if [[ "${model}" == negative_missing_request_id.vp ]]; then
			if [[ "${sessions}" == 1 ]]; then
				want=e0
			else
				want=e1
			fi
		fi

		printf 'checking %-42s sessions=%d ... ' "${model}" "${sessions}"
		actual="$(
			"${verifpal_bin}" verify "${script_dir}/${model}" \
				--sessions "${sessions}" \
				--result-code |
				tail -n 1
		)"
		if [[ "${actual}" == "${want}" ]]; then
			printf '%s\n' "${actual}"
		else
			printf 'got %s, expected %s\n' "${actual}" "${want}" >&2
			status=1
		fi
	done
done

exit "${status}"
