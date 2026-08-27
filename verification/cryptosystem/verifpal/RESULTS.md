# Verifpal 1.3.2 results

Each principal is replicated at 1, 2, 4, and 8 concurrent sessions. Verifpal
emits one letter/digit pair per query, in model order: `c`, `a`, `e`, and `f`
mean confidentiality, authentication, equivalence, and freshness; `0` means
the bounded search found no attack and `1` means it found an attack.

| Model | 1 session | 2 sessions | 4 sessions | 8 sessions |
| --- | --- | --- | --- | --- |
| `pairing_activation.vp` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` |
| `paired_exchange.vp` | `c0c0c0a0a0a0e0e0e0f0f0f0` | `c0c0c0a1a1a1e1e1e1f0f0f0` | `c0c0c0a1a1a1e1e1e1f0f0f0` | `c0c0c0a1a1a1e1e1e1f0f0f0` |
| `rotation.vp` | `c0c0c0a0a0e0e0` | `c0c0c0a1a1e1e1` | `c0c0c0a1a1e1e1` | `c0c0c0a1a1e1e1` |
| `compromise_psk.vp` | `c0e0` | `c0e1` | `c0e1` | `c0e1` |
| `compromise_device_key.vp` | `c1c1c1c1c1` | `c1c1c1c1c1` | `c1c1c1c1c1` | `c1c1c1c1c1` |
| `psk_holder_authority.vp` | `e0e0` | `e1e1` | `e1e1` | `e1e1` |
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
- In `paired_exchange.vp`, all confidentiality and freshness queries continue
  to hold through eight sessions. At two sessions the attacker can replay a
  complete valid request, response, or completion tuple into a sibling role
  instance. Verifpal 1.3.2 checks injective authentication, so the three
  authentication queries fail; the recipient also compares the replayed
  plaintext with its sibling session's local plaintext, so the three
  equivalence queries fail. The model deliberately has no retained request
  slot, cache, or processed marker. These are expected witnesses for the X06
  state dependency, not cryptographic forgeries or counterexamples to the
  stateful Tamarin results.
- `rotation.vp` has the analogous two-session whole-tuple replay: successor,
  request, and response confidentiality still hold, while injective request
  and response authentication and same-session agreement fail without R01/R06
  pending and confirmation state.
- In `compromise_psk.vp`, recorded-request confidentiality still holds after
  PSK-only disclosure at every bound. Its equivalence query fails from two
  sessions onward only because a complete recorded request can be routed into
  the sibling stateless receiver. `psk_holder_authority.vp` has the same
  cross-session agreement artifact; its one-session executions remain the
  intended constructive C01 witnesses.
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

## New 1.3 analysis modes

The generated-query audit asks broader mechanically selected questions. Many
reported attacks are intentionally non-properties: public identifiers and KEM
components, declared leaks, static long-term values, or the advertised pre-SAS
pairing exposure. The increase at two sessions is entirely the whole-tuple
replay boundary described above; no additional cryptographic confidentiality
failure was found.

| Model | Generated queries | Attacks at 1 session | Attacks at 2 sessions |
| --- | ---: | ---: | ---: |
| `pairing_activation.vp` | 45 | 14 | 14 |
| `paired_exchange.vp` | 22 | 5 | 10 |
| `rotation.vp` | 22 | 5 | 10 |
| `compromise_psk.vp` | 13 | 7 | 8 |
| `compromise_device_key.vp` | 14 | 7 | 7 |
| `psk_holder_authority.vp` | 25 | 13 | 15 |

Saturating search compares successive result codes from one session upward and
stops at the first equality, with a maximum of four sessions. The recorded
stopping points are:

| Model | Saturation stop count | Result code there |
| --- | ---: | --- |
| `pairing_activation.vp` | 2 | `c1c1e1c0c0c0a0a0a0e0e0e0` |
| `paired_exchange.vp` | 3 | `c0c0c0a1a1a1e1e1e1f0f0f0` |
| `rotation.vp` | 3 | `c0c0c0a1a1e1e1` |
| `compromise_psk.vp` | 3 | `c0e1` |
| `compromise_device_key.vp` | 2 | `c1c1c1c1c1` |
| `psk_holder_authority.vp` | 3 | `e1e1` |
| `negative_missing_request_id.vp` | 3 | `e1` |
| `negative_record_key_reuse.vp` | 2 | `e1e1` |
| `negative_rotation_candidate_pre_gate.vp` | 2 | `e1` |

These stopping points are evidence only. In particular, equality at sessions
1 and 2 does not preclude a new attack first requiring session 3. The fixed
eight-session runs remain the recorded bound.

All holding queries in the structured reports carry an exhausted search
envelope at the reported session count and no truncation reason. They remain
bounded evidence only: Verifpal has an incomplete active-attacker search,
including a whole-term basis restriction, and does not model the state-machine
properties listed in [`README.md`](README.md).
