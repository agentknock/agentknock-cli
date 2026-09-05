# Tamarin 1.12.0 results

The complete sequential run verified **114/114 lemmas** in 23 theories:
**79 universal properties and 35 reachable witnesses**, using Tamarin 1.12.0
and Maude 3.5.1. Every declared lemma, including every reused support invariant,
is registered in [cases.tsv](cases.tsv) and checked. No warning, derivation-check
exemption, precomputation exemption, unfinished proof, or timeout counts as success.

Reproduce with `bash verification/cryptosystem/tamarin/run.sh`. Exact toolchain,
resource controls, filtering, and proof boundaries are in [README.md](README.md).

## Per-theory results

| Theory | Verified | Role |
| --- | ---: | --- |
| `activation_traffic.spthy` | 4/4 | Activation request/response/completion secrecy and the current-PSK compromise control. |
| `binding_isolation.spthy` | 2/2 | Actual-state observations and arbitrary-sequence per-binding isolation, with a two-binding witness. |
| `binding_state.spthy` | 14/14 | Nested successor lineage, active/rejected/invalid state, fixed overlap and retirement, one successor per generation, support invariants, and an executable lifecycle. |
| `client_rotation_serialization.spthy` | 1/1 | No second client rotation before confirmation. |
| `client_rotation_state.spthy` | 2/2 | One successor derivation and one fixed pending encapsulation. |
| `current_psk_compromise.spthy` | 1/1 | Expected competing-rotation authority after current-PSK disclosure. |
| `end_to_end_lineage.spthy` | 6/6 | One-successor recorded lineage, delayed device-key compromise, secrecy before reveal, and domain/ID separation. |
| `honest_end_to_end_trace.spthy` | 1/1 | Ordered pairing-through-successor composition witness. |
| `honest_pairing_activation.spthy` | 1/1 | Complete honest pairing/activation trace, including accepted completion. |
| `honest_rotation_trace.spthy` | 1/1 | Honest rotation and confirmation witness. |
| `old_completion_rotation_trace.spthy` | 1/1 | Retained old-generation completion after rotation. |
| `paired_exchange.spthy` | 24/24 | Active-network exchange secrecy, context/record binding, replay state, all-three-record C02 disclosure queries, and compromise controls. |
| `pairing_activation.spthy` | 21/21 | Independent-PSK SAS comparison, key and full-completion agreement, device-local rejection, activation, retained slots, and compromise controls. |
| `pairing_pre_sas_attacks.spthy` | 2/2 | Expected pre-SAS plaintext disclosure and attacker-chosen pending metadata. |
| `previous_psk_authority.spthy` | 1/1 | Ordinary request authority during previous-generation overlap. |
| `previous_psk_compromise.spthy` | 3/3 | Active-network previous-only candidate-forgery exclusion, honest accepted candidate, and current-key disclosure forgery control. |
| `psk_rotation.spthy` | 7/7 | Candidate-authenticated adoption with current-PSK disclosure, current/previous handling, derived-successor separation, and retained completion context. |
| `retained_invalidation_traces.spthy` | 2/2 | Retained completion and cached-response behavior after invalidation. |
| `rollback_clone.spthy` | 4/4 | Expected fork/race, one-winner invariant, and request-ID separation. |
| `rollback_clone_causality.spthy` | 1/1 | Active-network adoption correspondence without fictitious clone attribution. |
| `rotation_confirmation.spthy` | 3/3 | Matching historical successor/encapsulation confirmation and delayed confirmation after invalidation. |
| `rotation_recovery_trace.spthy` | 1/1 | Lost-confirmation recovery and idempotent current-first retry. |
| `slot_lifecycle.spthy` | 11/11 | Atomic slot state, cache compaction and discard, request/completion uniqueness, fixed response bytes, support invariants, and an executable lifecycle. |
| **Total** | **114/114** | **79 universal properties; 35 reachable witnesses.** |

## Interpretation

The corrected pairing model compares only SAS codes. Key and full completion
agreement are separate lemmas, with a device-key compromise control admitting
equal SAS and different PSKs. Device activation and client response acceptance
are tied to the exact matching request/response, with the stated compromises.

The previous-key gate is checked on the active network. Its honest-acceptance
and current-key-disclosure controls establish that acceptance is executable.
The ordinary-exchange model directly checks all three recorded plaintexts under
PSK-only disclosure and includes a completed-exchange disclosure witness.

`binding_state` preserves the nested current-bound successor terms through
unbounded rotations. It abstracts successful authenticated inputs; the core
models check the full cryptographic schedule. `binding_isolation` compares real
observations across arbitrary updates. The old separate expiry, replacement,
and invalidation models are superseded by this combined lifecycle analysis.

`slot_lifecycle` uses one linear atomic slot record for cache phase and completion
disposition. Compaction discards response bytes while retaining a marker;
completion handling and cache retention can advance independently within that
record. The discarded phase is inert analysis bookkeeping, not a requirement
for real storage to retain the marker forever. Fresh allocation abstracts the
external policy that a forgotten identifier cannot be accepted anew. No slot
uniqueness restriction is used in this focused model; the cryptographic cores
still state their own explicit slot restrictions.

The lifecycle witnesses select particular finite schedules inside their
`exists-trace` formulas. Their universal safety lemmas remain unbounded. Core
executability complements phase-indexed composition witnesses; a reachable
honest path does not prove every safety antecedent is reachable.

The verified witnesses also include expected pre-SAS disclosure, attacker-chosen
metadata, context-holder response construction, live-context replacement and
forgery, current-PSK authority, retrospective device-key recovery, clone races,
and delayed confirmation after invalidation. They are controls and advertised
non-properties, not failed positive proofs. In particular, confirmation proves
historical device possession, and activation-response secrecy is relative to an
honest request: a compromised holder can initiate its own request and know its
response context.

Atomic persistence, real freshness/deadline enforcement, primitive security,
exact encodings, and implementation conformance remain separate obligations.
The retrospective compromise models mechanically cover one rotation edge;
a longer recorded lineage still uses the documented manual induction.
See [../RESULTS.md](../RESULTS.md) for the complete claim map.
