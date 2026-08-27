# Verifpal model of the Agentknock v1 cryptosystem

This directory contains a bounded symbolic analysis of
[`docs/cryptosystem.md`](../../../docs/cryptosystem.md) under an active
Dolev--Yao network attacker. It covers the cryptographic core of pairing and
SAS-gated activation, ordinary paired traffic, response and completion
binding, rotation fallback and confirmation, session mixups, and the stated
PSK and device-key compromise consequences.

The result is supporting evidence, not a complete proof of the specification.
Verifpal deliberately performs a terminating, sound-but-incomplete search over
a bounded number of replicated sessions. In particular, when its attack
construction needs a whole term, it chooses only among terms computed by the
protocol and can miss an attack requiring a different term. Verifpal 1.3.2
stamps every holding query with its search envelope, such as
`[search exhausted at 8 sessions]`; that makes the applied bound explicit but
does not make the search complete or identify a missed attack. A `0` result
therefore means only that this search found no attack. The unbounded and
stateful claims are handled by the companion Tamarin and ProVerif models.

Verifpal's `equivalence?` query checks symbolic term agreement between the
named principals in these traces. It is not the observational-equivalence
notion supported by tools such as ProVerif or Tamarin.

## Reproduce the analysis

The repository flake pins Verifpal 1.3.2 and its complete build inputs. Run:

```sh
./verification/cryptosystem/verifpal/run.sh
```

The runner builds the pinned binary with one build job, applies an 8 GiB
per-process memory ceiling, and verifies its version. It then checks every
hand-written query at 1, 2, 4, and 8 sessions per principal, the generated
query audit at 1 and 2 sessions, and the saturation point of each model against
[`RESULTS.md`](RESULTS.md). The 8-session pairing run can take several minutes.
To inspect a full minimized attack narration for one model, use the same pinned
binary directly, for example:

```sh
nix run path:$PWD/verification/cryptosystem#verifpal -- \
  verify verification/cryptosystem/verifpal/negative_missing_request_id.vp \
  --sessions 2 --result-code
```

The pin resolves as follows:

- official release: `v1.3.2`;
- annotated tag object: `7538231411fc73d119510250ef501c338905709c`;
- source commit: `11ea59e2e044e564052e97e7444d375fb3bf4d39`;
- source and Cargo dependency hashes: recorded in
  [`../flake.nix`](../flake.nix).

## Models and claim coverage

Claim IDs refer to the shared [`../CLAIMS.md`](../CLAIMS.md) ledger.

| Model | Purpose and covered claims |
| --- | --- |
| `pairing_activation.vp` | Pairing base exchange, commitment check, collision-free SAS equality gate, and activation; expected pre-SAS attacks P04/P05 and bounded evidence for P06/P07 plus the activation instance of X01--X05. |
| `paired_exchange.vp` | Request, exporter-derived response, and completion; bounded secrecy, injective authentication, agreement, mixup, and freshness evidence for X01--X05 and the cryptographic part of X07. Its multi-session replay results expose the absent X06 slot state. |
| `rotation.vp` | Candidate derivation, the checked ordinary-request adoption gate, and response confirmation; bounded secrecy and one-session agreement evidence for the cryptographic parts of R02/R03/R06, plus the expected multi-session replay boundary. |
| `compromise_psk.vp` | Post-transcript PSK-only disclosure; bounded confidentiality evidence for C02. Its multi-session equivalence result has the same absent-slot qualification. |
| `compromise_device_key.vp` | Later device-private-key disclosure; expected attacks demonstrating C03. |
| `psk_holder_authority.vp` | Constructive compromised-holder traces for future request impersonation and competing rotation, C01. |
| `negative_missing_request_id.vp` | Deliberately omits `request_id`; a two-session cross-feed demonstrates why X04/X05 require it. |
| `negative_record_key_reuse.vp` | Deliberately reuses the same effective symbolic key/nonce material for records 0 and 1; a one-session swap demonstrates why X03/X05 require record-sequence separation. In concrete HPKE the sequence changes the nonce while the AEAD key may stay fixed. |
| `negative_rotation_candidate_pre_gate.vp` | Deliberate pre-gate diagnostic: a relay may alter an uncommitted candidate, but that does not establish adoption or violate R02/R06. |

## Cryptographic abstraction

Verifpal has no native HPKE construction. Each HPKE setup is represented by
`KEM_ENCAP`/checked `KEM_DECAP?`, an opaque HKDF schedule, and AEAD. Checked
decapsulation makes a receiver abort on an invalid encapsulation, matching the
specification's HPKE setup and input-validation failure. In PSK mode the KEM
secret and PSK are both inputs to the symbolic schedule. Distinct schedule
outputs stand for HPKE record sequence 0, sequence 1, and the exporter secret;
this captures their separation but not concrete HPKE counters, nonces, or byte
encoding.

`CONCAT` is used for the specification's fixed-length `info`, PSK identity
binding, and `response_salt` values. It is an injective symbolic tuple for the
unambiguous fixed-width concatenation, not an extra cryptographic hash. Public
labels remain public constants.

The response follows Section 8.2 as separate derivations: the HPKE exporter is
derived under `response_label`, then `response_key` and `response_nonce` are
derived by two HKDF calls under `response_key_label` and
`response_nonce_label`. Verifpal's AEAD primitive has no nonce parameter, so
`CONCAT(response_key, response_nonce)` is used as its symbolic key. This makes
acceptance depend on both values but cannot analyze concrete nonce formatting
or misuse.

The pairing response is intentionally attacker-mutable. The two guarded SAS
messages and checked assertions represent an honest bilateral out-of-band
comparison. This is only the collision-free branch: the model does not prove
the quantitative `10^-12` wrong-SAS bound in O02 and does not give secrecy to
the displayed digits.

## Limits on the interpretation

- Positive `authentication?` results assume honest endpoints execute the
  modeled roles and mean that the relay did not synthesize the accepted value
  in the bounded experiment. They are context-possession results, not
  endpoint-origin or non-repudiation proofs: either endpoint retaining a
  request context can construct context-consistent records in either
  direction.
- Verifpal 1.3.2 authentication is injective agreement. At two or more
  sessions, replaying one honestly sent tuple into a second role instance
  breaks authentication even though the attacker forged no cryptographic
  value. This is useful evidence that the stateless cryptographic core alone
  does not provide the one-slot, one-effect, or idempotency rules in P08, X06,
  and R01.
- A `freshness?` result says the symbolic term depends on a generated fresh
  atom. It can hold even while an entire fresh tuple is replayed, and does not
  prove state uniqueness, response caching, or nonce-reuse discipline by
  itself.
- Verifpal has no mutable protocol state or conditional equivalence query.
  Current/previous/candidate ordering, conditional adoption, overlap expiry,
  fixed terminal responses, retained per-request contexts, rotation
  idempotency, invalidation, and crash-safe atomic transitions therefore remain
  outside these models. This includes P08, X06, the stateful parts of X07/X08,
  and most of R01/R04/R05/R07--R09.
- `negative_rotation_candidate_pre_gate.vp` is intentionally not counted as a
  rotation failure. A relay can substitute a well-formed `rotation_enc` and
  change the raw candidate, but the subsequent checked ordinary request then
  fails. Verifpal cannot ask for candidate equivalence only on traces where
  adoption succeeded; the positive rotation model queries agreement after the
  gate, while Tamarin/ProVerif carry the conditional state claim.
- `--auto-queries` was run over the six non-diagnostic models at one and two
  sessions. It generated confidentiality queries for secret inputs,
  authentication queries for received values used cryptographically, and
  freshness queries for used wire values. It found the same two-session replay
  boundary and the already advertised public, leaked, or pre-SAS values, but no
  additional cryptographic confidentiality failure. Hand-written queries
  remain authoritative because automatic queries do not generate equivalence,
  unlinkability, or preconditioned properties.
- `--saturate` stopped at two or three sessions for these models. It stops at
  the first adjacent equal result code, at no more than four sessions, so this
  is an inexpensive diagnostic rather than a proof of saturation. The fixed
  1/2/4/8 matrix remains the stronger recorded bounded experiment.
- The new `scenarios[]` peer-configuration axis was reviewed but is not added
  to these models. The pairing model already exposes peer-key substitution and
  checks the SAS gate directly; after activation, each model has a fixed peer
  binding rather than a runtime peer parameter. Adding one would conflate the
  cryptographic trace with binding lookup. Multiple-binding selection and
  isolation are represented explicitly in the Tamarin state models instead.
- Algorithms, exact lengths and parsing, X25519 validation details, concrete
  probabilities, storage behavior, side channels, and implementation
  conformance are the separate O01--O07 obligations, not conclusions of this
  symbolic model.
