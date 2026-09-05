# Verifpal 1.4.3 results

The recorded portfolio contains **47 completed analyses**: 35 explicit-query
analyses and 12 generated-query analyses. Every query has an exhausted,
untruncated envelope at its stated bound. These are bounded search results;
see [README.md](README.md) for primitive abstractions and interpretation limits.

Reproduce with `bash verification/cryptosystem/verifpal/run.sh`. The exact
query text, order, and codes are checked against [cases.json](cases.json).
In the codes, `c/a/e/f` denotes confidentiality/authentication/term-equality/
freshness, and `1` denotes a reported violation; `0` denotes no attack found.

## Explicit queries

| Model | 1 session | 2 sessions | 4 sessions | 8 sessions |
| --- | --- | --- | --- | --- |
| `compromise_device_key` | `c1c1c1c1c1` | `c1c1c1c1c1` | `c1c1c1c1c1` | `c1c1c1c1c1` |
| `compromise_psk` | `c0c0c0e0e0e0` | `c0c0c0e1e1e1` | `c0c0c0e1e1e1` | `c0c0c0e1e1e1` |
| `negative_missing_request_id` | `e1` | `e1` | `e1` | `e1` |
| `negative_record_nonce_reuse` | `c1e1e1` | `c1e1e1` | `c1e1e1` | `c1e1e1` |
| `negative_rotation_candidate_pre_gate` | `e1` | `e1` | `e1` | `e1` |
| `paired_exchange` | `c0c0c0a0a0a0e0e0e0f0f0f0` | `c0c0c0a1a0a1e1e1e1f0f0f0` | `c0c0c0a1a0a1e1e1e1f0f0f0` | `c0c0c0a1a0a1e1e1e1f0f0f0` |
| `pairing_activation` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` | `c1c1e1c0c0c0a0a0a0e0e0e0` | not tested |
| `psk_holder_authority` | `e0e0` | `e1e1` | `e1e1` | `e1e1` |
| `rotation` | `c0c0c0a0a0e0e0` | `c0c0c0a1a0e1e1` | `c0c0c0a1a0e1e1` | `c0c0c0a1a0e1e1` |

The combined pairing model completed at four sessions in approximately ten
minutes. Its eight-session case is not part of the recorded portfolio.

## Interpretation of reported violations

- **Pairing:** the two secrecy failures and early public-key mismatch precede
  SAS. A relay substitutes its public key in the unauthenticated response and
  opens the base records. All post-SAS activation queries hold at the tested bounds.
- **Ordinary traffic and rotation:** confidentiality holds. From two sessions,
  a full valid request tuple can be replayed into another stateless receiver,
  breaking injective request/completion authentication and same-instance term
  equality. The response-equality trace can instead replay a request into
  another device role, which generates its own valid response. Response
  authentication holds; the old version's `a1` response result is superseded.
- **PSK disclosure:** all three recorded plaintexts remain secret. The equality
  failures from two sessions have the same stateless-role interpretation.
- **Device-key disclosure:** all five explicit secrets are recovered: base
  application, initial and successor requests, and both generations' PSKs.
- **PSK-holder authority:** both constructive one-session equalities hold;
  multi-session instance-equality failures do not remove the holder's authority.
- **Missing request identity:** replacing the outer request ID changes the
  accepted `(ID, plaintext)` tuple while the encrypted open still succeeds.
  This is a direct one-session binding sensitivity check with KEM setup retained.
- **Record nonce reuse:** swapping records passes the wrong open. A public
  request also permits recovery of the completion in the tool's nonce-reuse
  abstraction. The correct model changes the nonce and keeps the key fixed.
- **Pre-gate candidate:** altering `rotation_enc` changes the candidate before
  authentication. The query deliberately precedes the ordinary-request gate;
  it is not evidence of unauthorized adoption.

## Generated-query audit

Generated queries do not replace the explicit queries. Their names and order
are fully recorded in `cases.json`; the codes are:

| Model | 1 session | 2 sessions |
| --- | --- | --- |
| `compromise_device_key` | `c1c1c1c1c1c1c1c1c1c1c1a0f1f0f0` | `c1c1c1c1c1c1c1c1c1c1c1a0f1f0f0` |
| `compromise_psk` | `c1c0c1c0c0c0c0c1a0a0a0a0a1a0a0f1f0f0f0f1f0f0` | `c1c0c1c0c0c0c0c1a0a1a1a1a1a0a1f1f0f0f0f1f0f0` |
| `paired_exchange` | `c0c0c1c0c0c0c0c1a0a0a0a0a1a0a0f1f0f0f0f1f0f0` | `c0c0c1c0c0c0c0c1a0a1a1a1a1a0a1f1f0f0f0f1f0f0` |
| `pairing_activation` | `c1c1c1c0c1c1c1c1c0c0c0c0c1a0a0a0a0a1a0a0a1a0a0a0a0a0a1a0a0f0f0f1f0f1f0f0f1f0f0f0f0f0f1f0f0` | `c1c1c1c0c1c1c1c1c0c0c0c0c1a0a1a0a0a1a0a0a1a0a0a0a0a0a1a0a0f0f0f1f0f1f0f0f1f0f0f0f0f0f1f0f0` |
| `psk_holder_authority` | `c0c0c1c0c0c0c1c0c0a0a1a1a0a1a1a1a0f1f1f1f0f1f1f1f0` | `c0c0c1c0c0c0c1c0c0a0a1a1a1a1a1a1a1f1f1f1f0f1f1f1f0` |
| `rotation` | `c0c0c0c1c0c0c0c1a0a0a0a0a0a1a0f1f0f0f0f0f1f0` | `c0c0c0c1c0c0c0c1a0a1a1a1a1a1a0f1f0f0f0f0f1f0` |

The generated violations fall into these reviewed categories:

1. Public identifiers/randoms, explicitly disclosed PSKs/device keys, and
   pre-SAS application/secret values are obtainable by the attacker.
2. Abstract KEM seeds become obtainable under substituted or disclosed device
   keys. This follows from Verifpal's generic KEM equations; it is not a claim
   of X25519 scalar recovery.
3. Replayed requests, completions, rotation inputs, and pre-SAS commitments
   can violate injectivity in replicated roles without retained-slot state.
4. Unauthenticated values can reach intermediate calculations before a later
   open or SAS assertion rejects them. This includes response randoms, raw KEM
   encapsulations, device contributions, and pre-SAS application ciphertexts.
5. Static device keys and substituted public values do not satisfy generated
   freshness queries. Freshness is not the protocol's timestamp or replay policy.

Some reports explicitly say their substitutions were not minimized into a
smaller witness. The portfolio records the tool's reports and checks their
structure, but does not treat every generated narration as an independently
validated attack against the concrete protocol. The explicit queries and the
Tamarin/ProVerif proofs carry the stated security claims.
