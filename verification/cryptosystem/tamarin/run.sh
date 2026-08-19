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

lock_file=/tmp/agentknock-cryptosystem-tamarin.lock
exec 9>"$lock_file"
if ! flock -n 9; then
  printf 'another Agentknock Tamarin runner is active\n' >&2
  exit 1
fi

tmp_dir=$(mktemp -d /tmp/agentknock-tamarin.XXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT HUP INT TERM

tamarin_store=$(nix build "path:$suite_dir#tamarin" --no-link --print-out-paths)
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
      --stop-on-trace=SEQDFS \
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
while read -r theory lemma heuristic; do
  [ -n "$theory" ] || continue
  run_lemma "$theory" "$lemma" "$heuristic"
done <<'CASES'
activation_traffic activation_request_confidentiality c
activation_traffic activation_response_confidentiality c
activation_traffic C01_compromised_psk_exposes_attacker_initiated_activation_response c
activation_traffic activation_completion_confidentiality c
binding_isolation R09_two_bindings_rotation_isolation_executable c
binding_isolation R09_other_binding_stable_without_its_own_mutation c
client_rotation_state R01_successor_is_export_of_one_rotation_context c
client_rotation_state R01_pending_requests_repeat_fixed_encapsulation i
client_rotation_serialization R01_no_second_client_rotation_before_confirmation i
previous_psk_expiry R05_expired_previous_never_authenticates_later s
previous_psk_replacement R05_second_rotation_retires_older_generation s
binding_invalidation R09_no_new_request_acceptance_after_invalidation s
rotation_confirmation R06_confirmation_matches_device_successor c
rotation_confirmation R06_only_matching_pending_encapsulation_is_cleared c
honest_rotation_trace R00_honest_rotation_and_confirmation_executable c
rotation_recovery_trace R07_lost_confirmation_recovery_executable c
current_psk_compromise C01_compromised_current_psk_can_race_rotation c
previous_psk_compromise R05_compromised_previous_psk_cannot_rotate c
previous_psk_authority R05_previous_ordinary_use_is_executable c
honest_end_to_end_trace composition_pairing_activation_rotation_executable c
end_to_end_lineage C03_late_device_key_recovers_initial_psk s
end_to_end_lineage C03_late_device_key_recovers_successor_lineage s
end_to_end_lineage C03_late_device_key_decrypts_pre_and_post_rotation_traffic s
end_to_end_lineage no_initial_psk_disclosure_without_device_key c
end_to_end_lineage domain_and_mode_contexts_are_distinct c
end_to_end_lineage honest_request_id_is_not_rotation_reserved_id c
honest_pairing_activation P01_honest_pairing_activation_executable c
paired_exchange X00_honest_full_exchange_executable c
paired_exchange X01_request_confidentiality_even_after_psk_disclosure c
paired_exchange X01_request_authentication c
paired_exchange X02_honest_response_confidentiality c
paired_exchange X02_response_authenticates_context_possession_not_device_origin c
paired_exchange X02_client_can_construct_valid_response_negative_control c
paired_exchange X03_completion_confidentiality c
paired_exchange X03_completion_authentication_and_record_order c
paired_exchange X04_accepted_request_matches_all_context_identifiers c
paired_exchange live_context_reveal_allows_first_request_replacement c
paired_exchange live_context_reveal_allows_completion_forgery c
paired_exchange X05_one_ciphertext_cannot_cross_request_contexts c
paired_exchange X05_request_record_cannot_be_completion_record c
paired_exchange X06_request_application_effect_once c
paired_exchange X06_fixed_response_redelivery c
paired_exchange X06_completion_application_effect_once c
paired_exchange X06_replay_redelivers_without_reprocessing c
paired_exchange X07_one_plaintext_per_response_key_nonce c
paired_exchange C01_psk_disclosure_enables_impersonation c
paired_exchange C02_recorded_request_survives_psk_only_disclosure c
paired_exchange joint_device_key_and_psk_compromise_breaks_recorded_request c
paired_exchange honest_request_id_is_not_rotation_reserved_id c
pairing_activation P02_completion_matches_committed_secret c
pairing_activation P02_ordered_distinct_base_records c
pairing_activation P03_sas_full_transcript_agreement c
pairing_activation P03_sas_injective c
pairing_activation P05_no_activation_before_sas c
pairing_activation P05_rejected_attempt_cannot_activate c
pairing_activation P06_device_activation_agreement c
pairing_activation P07_client_activation_authenticates_response c
pairing_activation P08_one_pairing_response_tuple c
pairing_activation P08_pairing_completion_processed_once c
pairing_activation P08_pairing_response_redelivery_executable c
pairing_activation P08_pairing_completion_redelivery_executable c
pairing_activation P08_activation_processed_once c
pairing_activation P08_activation_response_redelivery_is_exact c
pairing_activation P08_activation_completion_accepted_once c
pairing_activation pairing_application_secret_after_verified_sas c
pairing_activation honest_request_id_is_not_rotation_reserved_id c
pairing_pre_sas_attacks P04_active_relay_learns_pre_sas_application c
pairing_pre_sas_attacks P05_device_pending_metadata_can_be_attacker_chosen c
psk_rotation R02_adoption_requires_candidate_authenticated_request i
psk_rotation R03_no_bare_rotation_state_change i
psk_rotation R04_current_psk_success_ignores_rotation_field i
psk_rotation R05_previous_request_does_not_rotate i
psk_rotation R08_second_rotation_replaces_previous_state i
psk_rotation R09_rotation_changes_only_selected_binding i
psk_rotation X08_completion_uses_accepted_request_generation i
psk_rotation honest_request_id_is_not_rotation_reserved_id i
retained_invalidation_traces R09_retained_completion_survives_invalidation c
retained_invalidation_traces R09_cached_response_survives_invalidation c
old_completion_rotation_trace X08_old_request_completion_after_rotation_executable c
rollback_clone C04_two_clones_fork_distinct_successors s
rollback_clone C04_forked_rotations_race_one_device_lineage s
rollback_clone C04_at_most_one_distinct_fork_candidate_is_adopted i
rollback_clone_causality C04_rotation_is_not_compromise_recovery c
rollback_clone honest_request_id_is_not_rotation_reserved_id i
CASES

if [ "$selected" -eq 0 ]; then
  printf 'no proof case matched the requested filter\n' >&2
  exit 2
fi

printf 'Tamarin: %s/%s selected lemmas verified sequentially.\n' \
  "$selected" "$selected"
