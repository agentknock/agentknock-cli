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
on stdout. The runner checks every model is registered, enforces a three-minute timeout
and 2 GiB address-space limit, and rejects incomplete or unknown verdicts. It
compares complete ordered verdict vectors and equivalence summaries; the default prints the exact
verification summaries recorded in [`RESULTS.md`](RESULTS.md).

## Model inventory

| Model | Purpose | Claim IDs |
| --- | --- | --- |
| `paired_exchange.pv` | Request, exporter response, and sequence-1 completion; two device aliases deliberately share a key and PSK to stress device, client, and request identifiers | X01-X05, cryptographic part of X07 |
| `pairing_activation.pv` | Commitment, ordered base records, ideal full-SAS comparison, and PSK-mode activation | P01-P03, P05-P07 |
| `rotation_step.pv` | Ordered current-first/candidate-fallback processing for one active PSK generation and authenticated confirmation | cryptographic part of R02-R04 and R06 |
| `version_binding.pv` | Two symbolic versions sharing one key, client identity, and PSK; the receiver accepts either outer version and relies on `version_info` inside HPKE `info` | X04, X05 |
| `psk_compromise.pv` | Recorded request, accepted response, and completion secrecy after PSK-only disclosure; future impersonation | C01, C02 |
| `recorded_exchange_*_disclosure.pv` and `recorded_exchange.pvl` | Chosen-plaintext recorded-transcript equivalence after PSK disclosure, with device-key and live-context disclosure controls | C02, C03 boundary |
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
this abstraction. The reachability queries intentionally ask ProVerif
to prove that an honest terminal event is unreachable, so their `false`
results are expected executable witnesses. Every `false` result in a file
named `negative_*`, both advertised compromise attacks, and the weak-address
result is likewise expected and accompanied by a concrete reconstructed trace.

## Recorded-transcript equivalence

`recorded_exchange_psk_disclosure.pv` proves observational equivalence between
attacker-chosen request/response/completion tuples with identical public
metadata. The shared library generates an honest recorded base pairing and
arbitrarily many ordinary recordings per binding, with arbitrarily many
bindings sharing a device key. Each recording has fresh KEM randomness and
request identity; disclosure follows its three records. Other concurrent
recordings may already have disclosed the same PSK.

This experiment strengthens the direct secrecy queries. Its scope is the
recorded ciphertext transcript. Equal byte lengths and identical public
application behavior are external premises; symbolic bitstrings do not model
length, timing, errors, or traffic patterns. It supplies no interactive
application or decryption oracle and is not a full computational IND-CCA proof.

The device-key and live-context variants return **“Observational equivalence
cannot be proved.”** In both cases ProVerif also reconstructs a concrete
equality-test distinguisher: disclosure lets the attacker reconstruct/open the
chosen record and compare the plaintext with its candidate. The runner requires
both the exact unknown summary and the concrete distinguishing-trace markers.
An unknown result without that trace is rejected; it is not relabeled a `false`
verdict. Inspect the complete traces with `--full`.

The equivalence drivers are run with `-lib recorded_exchange` (the `.pvl`
extension is implicit). See the [official ProVerif manual](https://bblanche.gitlabpages.inria.fr/proverif/manual.pdf)
for biprocess and observational-equivalence semantics.
