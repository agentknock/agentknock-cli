# Agentknock v1 cryptosystem verification

This directory is a reproducible, specification-level symbolic analysis of
[`docs/cryptosystem.md`](../../docs/cryptosystem.md). It analyzes the protocol
as written. The CLI informed the conformance review, but these models do not
prove or test implementation conformance. The findings and corrections are
recorded in [AUDIT.md](AUDIT.md).

The portfolio uses three complementary tools:

- **Tamarin** models the mutable pairing, request-slot, rotation, overlap,
  invalidation, and rollback/clone state machines. Its universal lemmas range
  over all traces admitted by each model.
- **ProVerif** independently checks the replicated-session cryptographic core,
  correspondences, secrecy claims, compromise experiments, recorded-transcript
  observational equivalence, and context-binding sensitivity controls.
- **Verifpal** performs a separate bounded active-attacker search at 1, 2, 4,
  and 8 sessions per principal for the smaller models, and 1, 2, and 4 for
  combined pairing/activation. Its reports are interpreted within the primitive
  abstraction; a no-attack result is supporting evidence, not a completeness result.

The claim-by-claim outcome is in [`RESULTS.md`](RESULTS.md). Stable claim IDs
and their specification wording are in [`CLAIMS.md`](CLAIMS.md). Quantitative
arguments that symbolic tools cannot make are in
[`QUANTITATIVE.md`](QUANTITATIVE.md).

## Verification target

The recorded target is the following exact specification:

```text
SHA-256  ac86cb6cb2e4808fb8eea8358c6b4b4946d5cecc5fae806307e7b5c60dcc2d6f
file     docs/cryptosystem.md
```

From the repository root, verify it with:

```sh
sha256sum -c verification/cryptosystem/SPECIFICATION.sha256
```

If the specification changes, the models and coverage ledger must be reviewed;
a matching old proof run is not evidence about the changed document.

The JSON wire representation is defined separately in
[`docs/client-device-protocol.md`](../../docs/client-device-protocol.md). It is
intentionally outside this hashed verification target: concrete serialization,
parsing, and interoperability are the O06 conformance obligation rather than a
symbolic trace claim.

## Reproducing the analysis

The local [`flake.nix`](flake.nix) and [`flake.lock`](flake.lock) pin the Nixpkgs
revision and the Verifpal source and dependency hashes. The prover-specific
runners reject an unexpected tool version and compare results with their
recorded verdicts.

Run the complete portfolio sequentially from the repository root:

```sh
bash verification/cryptosystem/run.sh
```

Or run one prover portfolio:

```sh
bash verification/cryptosystem/tamarin/run.sh
bash verification/cryptosystem/proverif/run.sh
bash verification/cryptosystem/verifpal/run.sh
```

Every prover runner checks the specification hash and tool version, uses a
global per-tool lock, and rejects incomplete inventories/results. Tamarin uses
a 384 MiB GHC heap ceiling, an 8 GiB address-space ceiling, and three minutes per
lemma. ProVerif uses 2 GiB and three minutes per model. Verifpal uses 8 GiB and
fifteen minutes per analysis; its four-session pairing case took about ten
minutes. Nix builds use one job and two cores. See the
prover-specific reports for exact commands, expected-attack conventions, and
full-output options. The Tamarin report also documents optional host-level
cgroup isolation:

- [`tamarin/README.md`](tamarin/README.md)
- [`proverif/README.md`](proverif/README.md)
- [`verifpal/README.md`](verifpal/README.md)

The models and reports are ordinary source files; no generated proof cache is
needed to reproduce the verdicts.

## Artifact inventory

| Artifact | Role |
| --- | --- |
| [`run.sh`](run.sh) | Sequential specification-hash, Tamarin, ProVerif, and Verifpal reproduction entrypoint. |
| [`AUDIT.md`](AUDIT.md) | Audit findings, corrected modeling errors, and remaining boundaries. |
| [`CLAIMS.md`](CLAIMS.md) | Stable ledger P01--P08, X01--X08, R01--R09, C01--C05, and O01--O08. |
| [`RESULTS.md`](RESULTS.md) | Portfolio-level disposition and exact evidence map for every claim ID. |
| [`QUANTITATIVE.md`](QUANTITATIVE.md) | Exact 12-digit SAS modulo-bias calculation, attempt union bound, and ULID birthday bound. |
| [`SPECIFICATION.sha256`](SPECIFICATION.sha256) | Hash of the analyzed specification. |
| [`tamarin/`](tamarin/) | Stateful multiset-rewriting theories, strict runner, and detailed results. |
| [`proverif/`](proverif/) | Replicated-process models, positive and negative controls, exact-result runner, and detailed results. |
| [`verifpal/`](verifpal/) | Independent bounded models, exact result-code matrix, and runner. |
| [`flake.nix`](flake.nix), [`flake.lock`](flake.lock) | Pinned toolchain definition and resolved inputs. |

## Model boundary

All three tools use a Dolev--Yao attacker that controls the relay: it can
observe, replay, delay, reorder, replace, and synthesize network terms. The
cryptographic operations are perfect symbolic constructors and destructors.
The models bind the HPKE mode, KEM contribution, PSK and `psk_id`, the common
`hpke_info(version_info, device_id, last16)` tuple, record number, exporter
label, encapsulation, public response random, and response KDF labels where
each is relevant.

This proves trace properties of the modeled construction under the assumed
primitive equations. It is not a computational reduction for X25519, HPKE,
HKDF-SHA256, or ChaCha20Poly1305. It also does not prove exact byte encodings,
parsing, input validation, persistence, erasure, side-channel behavior, or
implementation conformance. Those boundaries are recorded as O01 and
O03--O06.

The endpoint assumptions match the specification:

- the device and its live state are trusted;
- an honest client's live sender context is secret and behaves as specified
  for the exchange, unless an explicit compromise rule reveals it;
- durable client PSKs may be disclosed, cloned, or rolled back;
- the relay can always deny service;
- SAS equality is collision-free in symbolic models, while the real collision
  probability is handled separately in [`QUANTITATIVE.md`](QUANTITATIVE.md).

The core Tamarin models assume per-device slot uniqueness through explicit
restrictions. A separate `slot_lifecycle.spthy` uses linear state to check
one-effect behavior, cache-to-marker compaction, and eventual discard without
those restrictions. Its fresh slot allocation represents the external policy
that a forgotten identifier cannot be resurrected; it does not prove a real
ULID clock or freshness implementation. The binding lifecycle retains a nested,
current-bound successor term across arbitrary rotations, while the core models
check the full cryptographic schedule and authentication. State observations
establish arbitrary-sequence per-binding isolation in a separate map model.

Focused state and phase-witness models have explicit assume/guarantee boundaries;
this portfolio is not one machine-checked composition theorem for the whole
implementation. Atomic storage, retained state, finite pending-attempt limits,
and real deadline enforcement remain external obligations.

## How to read the verdicts

The reports distinguish five kinds of evidence:

1. **Symbolic proof**: a universal secrecy or correspondence query was proved,
   or an intended trace was shown reachable, in the stated model.
2. **Expected attack**: the tool constructed a trace for a property the
   specification explicitly says is not provided, or for a deliberately
   weakened negative-control model.
3. **Bounded evidence**: Verifpal found no attack up to the recorded session
   bounds. Reports must be interpreted in the tool and primitive abstractions;
   no-attack results do not establish completeness.
4. **Manual/quantitative argument**: the result follows from arithmetic,
   specification structure, or an induction outside the prover's direct
   query.
5. **Assumption/out of scope**: the property belongs to primitive security,
   endpoint behavior, persistence, parsing, product policy, or implementation
   verification.

Authentication results are context-possession results, not signatures or
non-repudiation. In particular, either honest endpoint retaining a request
context can construct a context-consistent response or completion. The live
context is part of the specification's honest-exchange assumption: explicit
Tamarin compromise traces show that revealing it before acceptance enables a
first-request replacement or completion forgery.

## Tool provenance

- Tamarin 1.12.0, with Maude 3.5.1, is supplied by the pinned Nixpkgs input.
  Its modeling and property semantics are documented in the
  [Tamarin manual](https://tamarin-prover.com/manual/master/book/001_introduction.html).
- ProVerif 2.05 is supplied by the same pin; the upstream release and manual
  are linked from the [official ProVerif site](https://bblanche.gitlabpages.inria.fr/proverif/).
- Verifpal 1.4.3 is built from source commit
  `035f11d0480674a519c4835c20438f7af24f2e92`, corresponding to the verified
  [v1.4.3 release](https://github.com/symbolicsoft/verifpal/releases/tag/v1.4.3).
  Its bounded-search limitations are described in the
  [pinned upstream README](https://github.com/symbolicsoft/verifpal/blob/035f11d0480674a519c4835c20438f7af24f2e92/README.md).
