#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cryptosystem_dir="$(cd "${script_dir}/.." && pwd)"

# Keep an accidentally expensive bounded search from pressuring the host.  The
# ceiling is a safety stop, not part of the expected analysis.
ulimit -v 8388608

verifpal_store="$(
	nix build "path:${cryptosystem_dir}#verifpal" \
		--cores 2 \
		--max-jobs 1 \
		--no-link \
		--print-out-paths
)"
verifpal_bin="${verifpal_store}/bin/verifpal"

version="$(${verifpal_bin} --version)"
if [[ "${version}" != "verifpal 1.3.2" ]]; then
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

declare -A expected_all_sessions=(
	[pairing_activation.vp]=c1c1e1c0c0c0a0a0a0e0e0e0
	[compromise_device_key.vp]=c1c1c1c1c1
	[negative_record_key_reuse.vp]=e1e1
	[negative_rotation_candidate_pre_gate.vp]=e1
)

declare -A expected_one_session=(
	[paired_exchange.vp]=c0c0c0a0a0a0e0e0e0f0f0f0
	[rotation.vp]=c0c0c0a0a0e0e0
	[compromise_psk.vp]=c0e0
	[psk_holder_authority.vp]=e0e0
	[negative_missing_request_id.vp]=e0
)

declare -A expected_multiple_sessions=(
	[paired_exchange.vp]=c0c0c0a1a1a1e1e1e1f0f0f0
	[rotation.vp]=c0c0c0a1a1e1e1
	[compromise_psk.vp]=c0e1
	[psk_holder_authority.vp]=e1e1
	[negative_missing_request_id.vp]=e1
)

status=0
for sessions in 1 2 4 8; do
	for model in "${models[@]}"; do
		want="${expected_all_sessions[${model}]:-}"
		if [[ -z "${want}" && "${sessions}" == 1 ]]; then
			want="${expected_one_session[${model}]}"
		elif [[ -z "${want}" ]]; then
			want="${expected_multiple_sessions[${model}]}"
		fi

		printf 'checking %-42s sessions=%d ... ' "${model}" "${sessions}"
		actual="$(
			timeout 15m "${verifpal_bin}" verify "${script_dir}/${model}" \
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

auto_query_models=(
	pairing_activation.vp
	paired_exchange.vp
	rotation.vp
	compromise_psk.vp
	compromise_device_key.vp
	psk_holder_authority.vp
)

declare -A expected_auto_queries=(
	[1:pairing_activation.vp]=c1c1c1c0c1c1c0c1c0c0c0c0c1a0a0a0a0a1a0a0a1a0a0a0a0a0a1a0a0f0f0f1f0f1f0f0f1f0f0f0f0f0f1f0f0
	[2:pairing_activation.vp]=c1c1c1c0c1c1c0c1c0c0c0c0c1a0a0a0a0a1a0a0a1a0a0a0a0a0a1a0a0f0f0f1f0f1f0f0f1f0f0f0f0f0f1f0f0
	[1:paired_exchange.vp]=c0c0c1c0c0c0c0c1a0a0a0a0a1a0a0f1f0f0f0f1f0f0
	[2:paired_exchange.vp]=c0c0c1c0c0c0c0c1a0a1a1a1a1a1a1f1f0f0f0f1f0f0
	[1:rotation.vp]=c0c0c0c1c0c0c0c1a0a0a0a0a0a1a0f1f0f0f0f0f1f0
	[2:rotation.vp]=c0c0c0c1c0c0c0c1a0a1a1a1a1a1a1f1f0f0f0f0f1f0
	[1:compromise_psk.vp]=c1c0c1c0c0a0a1a1a0f1f1f1f0
	[2:compromise_psk.vp]=c1c0c1c0c0a0a1a1a1f1f1f1f0
	[1:compromise_device_key.vp]=c1c1c0c1c0c1c0c1c0c1a0f1f0f0
	[2:compromise_device_key.vp]=c1c1c0c1c0c1c0c1c0c1a0f1f0f0
	[1:psk_holder_authority.vp]=c0c0c1c0c0c0c1c0c0a0a1a1a0a1a1a1a0f1f1f1f0f1f1f1f0
	[2:psk_holder_authority.vp]=c0c0c1c0c0c0c1c0c0a0a1a1a1a1a1a1a1f1f1f1f0f1f1f1f0
)

for sessions in 1 2; do
	for model in "${auto_query_models[@]}"; do
		want="${expected_auto_queries[${sessions}:${model}]}"
		printf 'auto-query %-38s sessions=%d ... ' "${model}" "${sessions}"
		actual="$(
			timeout 15m "${verifpal_bin}" verify "${script_dir}/${model}" \
				--auto-queries \
				--sessions "${sessions}" \
				--result-code \
				--quiet
		)"
		if [[ "${actual}" == "${want}" ]]; then
			printf '%s\n' "${actual}"
		else
			printf 'got %s, expected %s\n' "${actual}" "${want}" >&2
			status=1
		fi
	done
done

declare -A expected_saturation_sessions=(
	[pairing_activation.vp]=2
	[paired_exchange.vp]=3
	[rotation.vp]=3
	[compromise_psk.vp]=3
	[compromise_device_key.vp]=2
	[psk_holder_authority.vp]=3
	[negative_missing_request_id.vp]=3
	[negative_record_key_reuse.vp]=2
	[negative_rotation_candidate_pre_gate.vp]=2
)

for model in "${models[@]}"; do
	want="${expected_saturation_sessions[${model}]}"
	printf 'saturation %-38s ... ' "${model}"
	report="$(
		timeout 15m "${verifpal_bin}" verify "${script_dir}/${model}" \
			--format json \
			--quiet \
			--saturate
	)"
	if [[ "${report}" == *'"exhausted":false'* ]] ||
		[[ "${report}" == *'"truncations":["'* ]]; then
		printf 'unexpected non-exhausted or truncated search envelope\n' >&2
		status=1
	fi
	actual="$(
		printf '%s\n' "${report}" |
			sed -n 's/^.*"analysis":{"model":"[^"]*","sessions":\([0-9][0-9]*\),"code":"[^"]*".*$/\1/p'
	)"
	if [[ "${actual}" == "${want}" ]]; then
		printf 'sessions=%s envelope=exhausted\n' "${actual}"
	else
		printf 'got sessions=%s, expected sessions=%s\n' "${actual}" "${want}" >&2
		status=1
	fi
done

exit "${status}"
