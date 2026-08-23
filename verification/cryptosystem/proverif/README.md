# ProVerif models for Agentknock v1

These models independently check the unbounded-session symbolic
cryptographic core of [`docs/cryptosystem.md`](../../../docs/cryptosystem.md).
They complement the Tamarin state-machine model; they do not replace it.

## Pinned tool

The recorded results use the official ProVerif 2.05 source archive:

- URL: <https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz>
- SHA-256 (hex):
  `4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4`
- SHA-256 (SRI):
  `sha256-SHH1PDKrSgRmmgYMSIa6XZCASWlj+5gKmmLSxCnOq8Q=`
- Expected banner:
  `Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre`

The archive and hash are the upstream source and fixed-output hash used by
Nixpkgs' ProVerif 2.05 derivation. `run.sh` rejects any other tool banner.

The repository flake pins the exact Nixpkgs revision and exposes ProVerif from
that revision. The runner uses it automatically:

```sh
bash verification/cryptosystem/proverif/run.sh
```

For a fully source-pinned run, download the archive, verify the hex checksum,
build it using its included instructions, and point the runner at that binary:

```sh
PROVERIF=/absolute/path/to/proverif2.05/proverif \
  bash verification/cryptosystem/proverif/run.sh
```

Pass `--full` to retain ProVerif's derivations and reconstructed attack traces
on stdout. The runner checks the complete ordered true/false verdict vector
for every file and exits nonzero on any mismatch; the default prints the exact
verification summaries recorded in [`RESULTS.md`](RESULTS.md).

## Model inventory

| Model | Purpose | Claim IDs |
| --- | --- | --- |
| `paired_exchange.pv` | Request, exporter response, and sequence-1 completion; two device aliases deliberately share a key and PSK to stress device, client, and request identifiers | X01-X05, cryptographic part of X07 |
| `pairing_activation.pv` | Commitment, ordered base records, ideal full-SAS comparison, and PSK-mode activation | P01-P03, P05-P07 |
| `rotation_step.pv` | Ordered current-first/candidate-fallback processing for one active PSK generation and authenticated confirmation | cryptographic part of R02-R04 and R06 |
| `version_binding.pv` | Two symbolic versions sharing one key, client identity, and PSK; the receiver accepts either outer version and relies on `version_info` inside HPKE `info` | X04, X05 |
| `psk_compromise.pv` | Historical secrecy after PSK-only disclosure and future impersonation | C01, C02 |
| `device_key_compromise.pv` | Delayed `skD` compromise over a recorded base transcript, initial request, one rotation, and its successor request | C03 one-step instance |
| `address_offline_guess.pv` | Qualitative weak-secret/offline-test analysis of deterministic `address_id` | C05 |
| `negative_pairing_mitm.pv` | Deliberately omits SAS to expose the specified pre-SAS MITM | P04, P05 |
| `negative_missing_context_binding.pv` | Deliberately removes device/client/request binding | X04, X05 |
| `negative_missing_record_sequence.pv` | Deliberately removes record sequence binding | X03, X05 |
| `negative_missing_version_binding.pv` | Deliberately removes `version_info` from HPKE `info`, enabling outer-version relabeling | X04, X05 |

## Abstraction boundary

The models use perfect symbolic constructors and destructors. HPKE is an
ideal KEM-derived context whose term includes the mode, KEM secret, PSK,
`psk_id`, exact `info`, exporter label, and record sequence. All three uses of
HPKE `info` share one injective `hpke_info(version_info, device_id, last16)`
constructor, matching the specification's one fixed-width concatenation:
`last16` is the client ID for pairing, a fresh symbolic nonzero request ID for
ordinary traffic, and the public reserved-zero value for rotation. Fresh
ProVerif names are distinct from that public zero value.

The response model includes the request exporter, encapsulation, fresh public
random value, and one common symbolic KDF called with distinct public
key/nonce labels. Thus the results validate the protocol's use and binding of
assumed primitives; they do not validate RFC 9180, X25519, HKDF-SHA256, or
ChaCha20Poly1305 themselves.

The private SAS channels represent an honest out-of-band comparison of the
full display. `sas(...)` is collision-free in this symbolic branch. Neither
the 12-digit collision probability nor attempt amplification is proved here.

Positive correspondences assume the trusted endpoints execute only their
specified roles and that their secrets have not been disclosed. Event names
such as `DeviceSendResponse` and `ClientSendCompletion` are therefore evidence
that the relay cannot synthesize those records in that experiment. They must
not be read as non-repudiable origin proofs: as the specification says, an
endpoint that possesses the request context can construct context-consistent
records for either direction. The protocol-level claim is context possession.

ProVerif is particularly useful here because these processes and
correspondences are checked for unboundedly many replicated sessions. It is
not the faithful tool for the protocol's mutable retained state. In
particular, these files make no full claim for P08, X06, X08, R01, R05, or
R07-R09: atomic slot acceptance, fixed redelivery, response uniqueness,
current/previous/candidate lineage, overlap deadlines, invalidation, and
binding isolation are checked in Tamarin. Parsing, exact lengths and bytes,
ULID policy, persistence implementation, timing, erasure, and quantitative
security remain outside symbolic trace verification.

In the output, a `true` secrecy/correspondence result is a successful proof in
this abstraction. The four reachability queries intentionally ask ProVerif
to prove that an honest terminal event is unreachable, so their `false`
results are expected executable witnesses. Every `false` result in a file
named `negative_*`, both advertised compromise attacks, and the weak-address
result is likewise expected and accompanied by a concrete reconstructed trace.
