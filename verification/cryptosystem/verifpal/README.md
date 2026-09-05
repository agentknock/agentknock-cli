# Verifpal analysis of Agentknock v1

These models provide independent bounded symbolic evidence for
[`docs/cryptosystem.md`](../../../docs/cryptosystem.md). A `0` result means that
this search found no attack within its recorded envelope. It is not an
unbounded theorem or a computational security proof. Reported attacks must be
interpreted in the modeled primitive and endpoint semantics.

`equivalence?` checks equality of named terms in the explored executions. It
is not observational equivalence or plaintext indistinguishability. The latter
has a separate experiment in [ProVerif](../proverif/README.md).

## Reproduction and provenance

```sh
bash verification/cryptosystem/verifpal/run.sh
```

The runner pins Verifpal 1.4.3, verifies the specification hash and model
inventory, and checks full JSON reports against [cases.json](cases.json).
Every query must have the expected name, kind, verdict, session bound, and
exhausted, untruncated search envelope. Unexpected assumptions, preconditions,
errors, omitted queries, or attacks without reported steps fail the run.
Regression tests for result acceptance live in [../test_check_results.py](../test_check_results.py).

The explicit-query matrix uses 1, 2, 4, and 8 sessions per principal, except
for the combined pairing/activation model, which uses 1, 2, and 4. Its
four-session analysis took approximately ten minutes in the recorded run;
eight sessions were not tested. Automatic queries over the six non-diagnostic
models are checked at 1 and 2 sessions. A global runner lock, 8 GiB address-space
limit, and fifteen-minute per-analysis timeout bound resource use. Nix builds
use one job and two cores; upstream tests run sequentially.

The exact source pin is:

- release [v1.4.3](https://github.com/symbolicsoft/verifpal/releases/tag/v1.4.3);
- annotated tag object `19bf1213b71738b75df2c5b052788ddd95714f31`;
- source commit `035f11d0480674a519c4835c20438f7af24f2e92`;
- source and Cargo hashes in [../flake.nix](../flake.nix).

Version 1.4 fixed several attack-search errors and introduced explicit AEAD
nonces. The old 1.3.2 results are superseded, including its response-authentication
failure classification. See the [upstream release explanation](https://symbolic.software/blog/2026-09-04-verifpal-1-4/).

## Models

| Model | Purpose |
| --- | --- |
| `pairing_activation.vp` | Commitment, ordered base records, bilateral full-SAS comparison, activation, and expected pre-SAS disclosure/substitution. |
| `paired_exchange.vp` | Request, response, and completion secrecy, agreement, injective authentication, and freshness diagnostics. |
| `rotation.vp` | Candidate derivation and agreement after the checked request/response gates. |
| `compromise_psk.vp` | All three recorded plaintexts remain secret after PSK-only disclosure. |
| `compromise_device_key.vp` | Recorded base pairing, initial request, and one successor request after device-key disclosure. |
| `psk_holder_authority.vp` | Constructive request and rotation authority of a PSK holder. |
| `negative_missing_request_id.vp` | Retains fresh KEM setup but omits request identity from the schedule; an outer-ID mutation passes the open in one session. |
| `negative_record_nonce_reuse.vp` | Reuses one AEAD key/nonce for records 0 and 1; demonstrates record swaps and completion disclosure with a known request. |
| `negative_rotation_candidate_pre_gate.vp` | Queries the uncommitted candidate before authentication; substitution here is an expected denial-of-service capability. |

## Cryptographic abstraction

Checked `KEM_DECAP?`, HKDF, and AEAD represent HPKE. PSK mode includes the KEM
secret, PSK, client identity, version, device identity, and request identity.
The three HKDF schedule outputs consistently denote the AEAD key, base nonce,
and exporter root. Base, ordinary, and rotation setups use the same output
positions; rotation discards the first two outputs. Exporter and response
key/nonce labels remain distinct public constants.

AEAD has four explicit arguments: key, nonce, plaintext/ciphertext, and
associated data. Records 0 and 1 share the AEAD key. The nonce for record 1 is
represented by `CONCAT(base_nonce, record_sequence_one)`, a distinct, reversible
symbolic term standing for the concrete fixed-width XOR with sequence one.
It does **not** implement XOR algebra, nonce lengths, or HPKE counters. Responses
use separately derived key and nonce arguments directly. `CONCAT` otherwise
represents the specification's unambiguous fixed-width tuples.

The generic KEM is an ideal encapsulation abstraction, not an implementation of
DHKEM(X25519). Its [pinned primitive rules](https://github.com/symbolicsoft/verifpal/blob/035f11d0480674a519c4835c20438f7af24f2e92/src/primitive/spec.rs)
allow a matching private key to recover both the modeled shared secret and the
encapsulation seed. Consequently some automatic queries report seed disclosure
under key substitution or device-key compromise. This does not mean a real
X25519 sender private scalar is recoverable. No such claim is made here.
The nonce-reuse rule is also pessimistic: it allows plaintext recovery and
forgery after conflicting uses. It is a misuse detector, not an exact account
of ChaCha20Poly1305 leakage.

Guarded SAS messages and checked assertions model the honest bilateral
out-of-band comparison of the entire code. Hash collisions, decimal reduction,
human behavior, and bounded attempt enforcement remain separate assumptions.

## Interpretation limits

The stateless replicated roles can accept a complete request tuple in multiple
instances. Request/completion injective authentication therefore fails from
two sessions, while response authentication holds in the tested matrix.
Plaintext equality queries can also fail when a different honest role instance
produces a response for a replayed request. These are not forged AEAD records;
Tamarin checks the retained-slot and binding state that these models omit.

Automatic queries are diagnostics at the **first cryptographic use** of a
value. An authentication/freshness failure for `response_random` can occur
while computing the response salt, before the later checked response open.
It is not an accepted response or confirmation failure. Likewise, pre-SAS
application authentication and commitment replays precede SAS authorization.
The exact generated query lists and verdicts are pinned alongside the explicit
queries; their classification is in [RESULTS.md](RESULTS.md).

A freshness query asks whether a term depends on fresh generation. It does not
prove single acceptance, nonce uniqueness, persistence, or response caching.
An equality of result codes at adjacent session counts is not a saturation
proof; the runner uses explicit bounds instead of `--saturate` diagnostics.

Current/previous/candidate ordering, fixed overlap deadlines, invalidation,
cache compaction, rollback, and crash-safe storage are outside these models.
Response and completion authentication means context possession, not signatures
or non-repudiation. Primitive security, exact bytes, parsing, clocks, erasure,
and implementation conformance remain O01--O08 in the shared ledger.
