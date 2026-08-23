# Tamarin model of the Agentknock v1 cryptosystem

This directory contains the stateful part of the specification-level analysis
of [`docs/cryptosystem.md`](../../../docs/cryptosystem.md). The models cover
pairing and SAS gating, request/response/completion slots, PSK rotation and
overlap, retained exchanges, invalidation, per-binding isolation, compromise,
and cloned or rolled-back client state.

The result applies to the protocol specification, not its implementation.
Tamarin reasons about the multiset-rewriting systems in these files under a
Dolev--Yao attacker and the restrictions stated by each theory.

## Reproduce the analysis

From the repository root, run:

```sh
bash verification/cryptosystem/tamarin/run.sh
```

The runner:

- obtains Tamarin 1.12.0 and Maude 3.5.1 from the pinned repository flake;
- rejects a different version;
- takes a global `flock` so two portfolio runs cannot execute concurrently;
- starts a fresh Tamarin process for every lemma;
- runs only one lemma at a time with `+RTS -M384m -N1 -RTS`;
- uses `--stop-on-trace=SEQDFS` to disable parallel proof search;
- limits each lemma to three minutes;
- requires clean derivation checks with `--derivcheck-timeout=120` and
  `--quit-on-warning`; and
- checks for the exact selected `verified` verdict.

Run one theory or one lemma with:

```sh
bash verification/cryptosystem/tamarin/run.sh paired_exchange
bash verification/cryptosystem/tamarin/run.sh paired_exchange X01_request_authentication
```

On a systemd-based Linux host, an additional process-group ceiling can be
applied without changing the proof command:

```sh
systemd-run --user --wait --collect --pipe \
  --property=MemoryMax=512M \
  --property=MemorySwapMax=0 \
  --property=TasksMax=32 \
  --property=OOMPolicy=stop \
  --working-directory="$PWD" \
  bash verification/cryptosystem/tamarin/run.sh
```

The cgroup is an optional host-level guard. The GHC heap ceiling, sequential
execution, and runner lock remain active without systemd.

## Cryptographic abstraction

HPKE KEM setup is represented as ideal public-key encapsulation
`aenc(kem_seed, pk(skD))`; only `skD` can recover the seed. Base and PSK modes
have distinct context constructors. The PSK context includes the KEM seed,
PSK, client identity, and one common `hpke_info(version, device, last16)` tuple.
The reserved all-zero final component is used only for rotation; ordinary
request identifiers are fresh names.

HPKE record keys, exporters, and the response key/nonce KDF are free symbolic
constructors. Symmetric encryption is perfect. This captures term binding and
separation but is not a computational proof of X25519, HPKE, HKDF-SHA256, or
ChaCha20Poly1305 and does not model byte parsing or concrete nonce formatting.
Those limits are O01 and O06 in the shared claim ledger.

## Stateful assumptions

The active models expose network messages through `In` and `Out`, giving the
attacker control over delivery, replay, replacement, and synthesis. Linear
facts represent current mutable state; persistent facts represent retained
slots and caches.

The `UniquePairingRequest`, `UniqueActivationRequest`, and
`UniqueDeviceRequestSlot` restrictions encode the specification's normative
device-local uniqueness and once-only acceptance rules. They are assumptions
about the specified transition system. The proofs establish their
consequences; they do not establish crash-safe storage, locking, clocks, or
implementation conformance. Accepted slots and caches are persistent in these
models; compaction to a terminal marker and garbage collection are deliberately
absent. The idempotency theorems therefore cover exact redelivery and
one-effect behavior while the modeled state is retained. Marker-based response
suppression is an O05 persistence obligation, and later handling after the
marker itself may be discarded is an external O03 freshness-policy obligation.

Several proof obligations are deliberately decomposed:

- `paired_exchange.spthy`, `pairing_activation.spthy`, and
  `psk_rotation.spthy` are the main active-attacker cryptographic/state models.
- `rotation_confirmation.spthy` composes the checked candidate-request and
  response hops established by the core rotation theory and ProVerif with the
  client confirmation state machine. Its internal wire facts are explicit
  assume/guarantee boundaries, not extra adversary channels.
- `previous_psk_compromise.spthy` similarly starts at the checked
  candidate-authentication boundary to isolate the old-versus-current
  generation invariant; `previous_psk_authority.spthy` independently shows
  that the old PSK still authorizes an ordinary overlap request.
- The `honest_*_trace.spthy`, `rotation_recovery_trace.spthy`,
  `old_completion_rotation_trace.spthy`, and
  `retained_invalidation_traces.spthy` files are phase-indexed reachability
  models. They prove that required lifecycle paths are executable without
  claiming a second active-attacker authenticity result.
- Expiry, replacement, serialization, invalidation, and binding isolation are
  focused generic transition systems. Their universal lemmas are unbounded in
  those systems. Extending one-step per-binding isolation across an arbitrary
  sequence is the usual manual induction over transitions.
- `end_to_end_lineage.spthy` mechanically records exactly one successor edge.
  Applying the same reconstruction to every later recorded edge is a manual
  induction, not an unbounded mechanized lineage theorem.

Clone labels in `rollback_clone.spthy` are local analysis metadata. They do not
appear in the protocol wire, and the device is not claimed to know which copy
sent a request. Adoption is correlated by the authenticated request and
candidate tuple.

## Interpretation

An `all-traces` lemma marked `verified` is a theorem of its stated model. An
`exists-trace` lemma marked `verified` is a reachable witness. Some witnesses
are honest non-vacuity checks; others intentionally demonstrate advertised
attacks or non-properties.

Authentication of response and completion records means possession of the
retained request context. It is not a signature, endpoint attribution, or
non-repudiation. Explicit live-context compromise witnesses show first-request
replacement and completion forgery when that assumption is removed; a separate
context-holder witness constructs a valid response.

See [`RESULTS.md`](RESULTS.md) for exact counts and the shared
[`../RESULTS.md`](../RESULTS.md) for the claim-by-claim portfolio verdict.
