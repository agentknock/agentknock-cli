# Verifpal 1.0.0 results

Each principal is replicated at 1, 2, 4, and 8 concurrent sessions. Verifpal
emits one letter/digit pair per query, in model order: `c`, `a`, `e`, and `f`
mean confidentiality, authentication, equivalence, and freshness; `0` means
the bounded search found no attack and `1` means it found an attack.

| Model | 1 session | 2 sessions | 4 sessions | 8 sessions |
| --- | --- | --- | --- | --- |
| `pairing_activation.vp` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` |
| `paired_exchange.vp` | `c0c0c0a0a0a0e0e0e0f0f0f0` | `c0c0c0a0a0a0e0e0e0f0f0f0` | `c0c0c0a0a0a0e0e0e0f0f0f0` | `c0c0c0a0a0a0e0e0e0f0f0f0` |
| `rotation.vp` | `c0c0c0a0a0e0e0` | `c0c0c0a0a0e0e0` | `c0c0c0a0a0e0e0` | `c0c0c0a0a0e0e0` |
| `compromise_psk.vp` | `c0e0` | `c0e0` | `c0e0` | `c0e0` |
| `compromise_device_key.vp` | `c1c1c1c1c1` | `c1c1c1c1c1` | `c1c1c1c1c1` | `c1c1c1c1c1` |
| `psk_holder_authority.vp` | `e0e0` | `e0e0` | `e0e0` | `e0e0` |
| `negative_missing_request_id.vp` | `e0` | `e1` | `e1` | `e1` |
| `negative_record_key_reuse.vp` | `e1e1` | `e1e1` | `e1e1` | `e1e1` |
| `negative_rotation_candidate_pre_gate.vp` | `e1` | `e1` | `e1` | `e1` |

## Interpretation of reported attacks

All reported attacks are expected and have a minimized executable narration in
Verifpal's full output:

- In `pairing_activation.vp`, the first two `c1` results confirm P04: before
  SAS acceptance, an active relay can replace the clear device response with
  its own KEM public key, recover the base-mode `client_secret`, and open the
  pairing application record. The `e1` confirms the P05 premise that this
  unauthenticated exchange alone does not agree on the intended device public
  key. All post-SAS activation queries remain `0`.
- In `compromise_device_key.vp`, all five `c1` results are the advertised C03
  compromise chain: a later device-key disclosure opens recorded pairing
  traffic, recovers the initial PSK, derives the recorded rotation successor,
  and opens traffic in both generations.
- `negative_missing_request_id.vp` needs two sessions, then moves a ciphertext
  between request slots that share the intentionally broken schedule. The
  one-session `e0` and multi-session `e1` are both expected.
- `negative_record_key_reuse.vp` swaps request and completion records that
  intentionally reuse the same effective symbolic key/nonce material, so both
  agreement queries fail even with one session. This represents missing
  record-sequence separation; concrete HPKE may retain the key while changing
  the nonce.
- `negative_rotation_candidate_pre_gate.vp` substitutes a well-formed
  attacker-created encapsulation under the public device key and changes the
  uncommitted raw candidate. The checked request in `rotation.vp` prevents
  that candidate from reaching adoption; this is a denial-of-service
  diagnostic, not a protocol-security counterexample.

The all-zero portions are bounded evidence only: Verifpal 1.0.0 explicitly has
an incomplete active-attacker search, including a whole-term basis restriction,
and does not model the state-machine properties listed in
[`README.md`](README.md).
