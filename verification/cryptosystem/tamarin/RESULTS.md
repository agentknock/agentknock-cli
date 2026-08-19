# Tamarin 1.12.0 results

Toolchain:

```text
Tamarin version 1.12.0
Maude version 3.5.1
```

The strict sequential runner verified all 84 selected lemmas: 57 universal
`all-traces` properties and 27 reachable `exists-trace` witnesses. Every
theory passed derivation checks; no `no_derivcheck`, `no_precomp`, warning, or
unfinished proof is accepted by the runner.

The exact command and resource controls are documented in
[`README.md`](README.md).

## Per-theory result

| Theory | Verified | Role |
| --- | ---: | --- |
| `activation_traffic.spthy` | 4/4 | Activation request/response/completion secrecy and the current-PSK compromise control. |
| `binding_invalidation.spthy` | 1/1 | No later new-request acceptance after invalidation. |
| `binding_isolation.spthy` | 2/2 | Two-binding witness and one-step noninterference. |
| `client_rotation_serialization.spthy` | 1/1 | No second client rotation before confirmation. |
| `client_rotation_state.spthy` | 2/2 | One successor derivation and one fixed pending encapsulation. |
| `current_psk_compromise.spthy` | 1/1 | Expected competing-rotation authority after current-PSK disclosure. |
| `end_to_end_lineage.spthy` | 6/6 | One-successor recorded lineage, delayed device-key compromise, secrecy before reveal, and domain/ID separation. |
| `honest_end_to_end_trace.spthy` | 1/1 | Ordered pairing-through-successor composition witness. |
| `honest_pairing_activation.spthy` | 1/1 | Complete honest pairing/activation trace, including accepted completion. |
| `honest_rotation_trace.spthy` | 1/1 | Honest rotation and confirmation witness. |
| `old_completion_rotation_trace.spthy` | 1/1 | Retained old-generation completion after rotation. |
| `paired_exchange.spthy` | 22/22 | Active-attacker exchange secrecy, correspondences, context/record binding, replay state, compromises, and negative controls. |
| `pairing_activation.spthy` | 17/17 | Active pairing/SAS/activation agreement, gating, slot state, redelivery, and post-SAS secrecy. |
| `pairing_pre_sas_attacks.spthy` | 2/2 | Expected pre-SAS plaintext disclosure and attacker-chosen pending metadata. |
| `previous_psk_authority.spthy` | 1/1 | Ordinary request authority during previous-generation overlap. |
| `previous_psk_compromise.spthy` | 1/1 | Compromised previous PSK cannot pass the current-derived rotation gate. |
| `previous_psk_expiry.spthy` | 1/1 | Expired previous authority is not recreated by later use. |
| `previous_psk_replacement.spthy` | 1/1 | A later rotation retires the older previous generation. |
| `psk_rotation.spthy` | 8/8 | Active-attacker candidate adoption, current/previous handling, selected-binding mutation, and retained-generation correspondence. |
| `retained_invalidation_traces.spthy` | 2/2 | Retained completion and cached-response behavior after invalidation. |
| `rollback_clone.spthy` | 4/4 | Expected fork/race, one-winner invariant, and request-ID separation. |
| `rollback_clone_causality.spthy` | 1/1 | Active-network adoption correspondence without fictitious clone attribution. |
| `rotation_confirmation.spthy` | 2/2 | Matching successor/encapsulation confirmation in the composed state model. |
| `rotation_recovery_trace.spthy` | 1/1 | Lost-confirmation recovery and idempotent current-first retry. |
| **Total** | **84/84** | **57 universal properties; 27 reachability witnesses.** |

## Expected traces and qualifications

The verified reachability witnesses include the specification's advertised
non-properties: pre-SAS relay substitution, attacker-chosen pre-SAS metadata,
client-context-holder response construction, live-context request replacement
and completion forgery, future authority after current-PSK disclosure,
retrospective recovery after delayed device-key disclosure, and cloned-state
fork/race behavior.
Their reachability is a successful negative control, not a failed proof.

One activation nuance is explicit in `activation_traffic.spthy`: a response to
an honest uncompromised activation request remains secret, while a disclosed
current PSK lets the attacker initiate its own valid activation request and
therefore know that request's response context. A blanket “all activation
responses remain secret after PSK compromise” statement would be false; this
is the authority described by C01.

Portfolio-level limits and cross-tool evidence are recorded in
[`../RESULTS.md`](../RESULTS.md).
