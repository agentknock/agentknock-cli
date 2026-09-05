# Agentknock v1 formal-verification claims

This file is the coverage ledger for the symbolic verification of
[`docs/cryptosystem.md`](../../docs/cryptosystem.md). A result is meaningful
only together with the abstraction and compromise conditions stated by the
model that proves it.

The IDs below are stable names shared by the prover-specific reports.
[`RESULTS.md`](RESULTS.md) records each claim as proved, expected attack,
bounded evidence, manual argument, assumption, or out of scope.

## Pairing and activation

| ID | Specification claim |
| --- | --- |
| P01 | An honest pairing, SAS decision, and activation trace is executable. |
| P02 | An accepted pairing completion opens both ordered base-mode records and reveals the same client secret committed in the retained clear request. |
| P03 | Honest acceptance of equal SAS values gives agreement on the client secret, device contribution, device identity, client identity, and device public key, modulo the separately quantified SAS-collision/guess event. |
| P04 | Before SAS authentication, pairing application plaintext is **not** confidential against an active relay that substitutes the clear device response. |
| P05 | The base-mode exchange alone does not authenticate the intended device, and a device binding cannot become active through the honest state machine before SAS acceptance and a valid PSK-mode activation request. |
| P06 | Device activation agrees with a PSK-mode activation request under the pending binding established by the SAS-approved pairing. |
| P07 | Client activation occurs only after an authenticated response bound to its activation request context. |
| P08 | Each pairing request, response, and completion slot is fixed once while its required state is retained. Cached response data permits exact redelivery; a retained terminal marker prevents a repeated transition or regenerated response after those data are discarded. Once the marker may also be discarded, freshness policy prevents the identifiers from being accepted as a new operation. |

## Paired request, response, and completion

| ID | Specification claim |
| --- | --- |
| X01 | A paired request remains secret from the relay and is accepted only from a holder of the binding PSK, subject to the stated endpoint-compromise exceptions. |
| X02 | A response remains secret from the relay and authenticates possession of the accepted request context; it does not prove which endpoint encrypted it. |
| X03 | A completion remains secret from the relay, is bound to record sequence 1 of the accepted request context, and follows record sequence 0. |
| X04 | Version, device identity, and request identity are bound through the HPKE context, and client identity is bound through the PSK identity and matching PSK. |
| X05 | Cross-version, cross-device, cross-client, cross-request, and cross-record substitutions do not produce a new cryptographic acceptance. |
| X06 | While the required exchange/idempotency state is retained, each request slot has one accepted request, at most one fixed terminal response, and at most one accepted completion; replay cannot repeat application effects. Cached response data permits exact redelivery, while a terminal marker suppresses regeneration after those data are discarded. Once all slot state may be discarded, freshness policy prevents resurrection as a new operation. |
| X07 | The response exporter, encapsulation, and fresh public response random bind one response key/nonce pair to one fixed terminal response; redelivery does not create a second plaintext under that pair, and a discarded response is not regenerated. |
| X08 | An accepted request retains its original HPKE context and PSK generation across later binding rotations. |

## PSK rotation and binding state

| ID | Specification claim |
| --- | --- |
| R01 | A client rotation derives a successor from the current PSK and one rotation context, atomically makes it current, and retains one fixed encapsulation until confirmation. |
| R02 | A device adopts a candidate PSK only when an ordinary request authenticates under the candidate derived from the device's current PSK and supplied rotation encapsulation. |
| R03 | A missing, malformed, bare, or substituted rotation encapsulation cannot by itself change trusted device state. |
| R04 | A request that authenticates under the current PSK ignores `rotation_enc` and cannot spuriously rotate. |
| R05 | The immediately previous PSK can authorize only an ordinary request during its fixed overlap; it cannot authorize rotation, become current again, or extend the overlap. |
| R06 | Opening a response to the matching request carrying the pending encapsulation confirms that client and device hold the same successor PSK; an unauthenticated signal cannot confirm it. |
| R07 | Reusing the fixed pending encapsulation after a lost confirmation is idempotent once the successor is already current. |
| R08 | At most one client rotation is unconfirmed, and the device retains at most the immediately previous generation; a later rotation retires older authority. |
| R09 | Rotation is limited to active bindings, activation cannot rotate, invalidation blocks both current and previous PSKs for new requests, and one binding cannot mutate another. |

R06 is historical key confirmation: the device held the successor when it
produced the authenticated response. A delayed response can arrive after a
later rotation or invalidation; it does not certify the device's current state
at receipt. The focused Tamarin confirmation model includes that witness.

## Compromise and advertised non-properties

| ID | Specification claim |
| --- | --- |
| C01 | Disclosure of a current client PSK permits client impersonation and competing rotation until device state changes. |
| C02 | Disclosure of a client PSK alone does not decrypt previously recorded HPKE traffic without the device private key or sender ephemeral state. |
| C03 | Later disclosure of the device private key recovers the client PSK from a recorded base pairing transcript and then the recorded successor lineage and paired traffic: v1 has no forward secrecy against this compromise. |
| C04 | Cloned or rolled-back valid client state can fork a PSK lineage and race a competing rotation; key evolution is not compromise recovery. |
| C05 | Pairing addresses permit offline guessing, and visible identifiers, encapsulations, rotation presence, lengths, timing, and traffic relationships are not hidden. |

## Obligations outside symbolic trace proofs

| ID | Obligation | Treatment |
| --- | --- | --- |
| O01 | Concrete security of X25519, HPKE, HKDF-SHA256, and ChaCha20Poly1305 | Cryptographic assumption. The models use perfect symbolic constructors/destructors and explicit context arguments. |
| O02 | A fixed wrong 12-digit SAS matches with probability approximately `10^-12`; `n` fixed pending attempts give at most approximately `n * 10^-12` | Quantitative/manual argument. Symbolic equality represents the collision-free branch. The `n`-attempt bound additionally assumes deployment enforcement of the finite pending-attempt limit; no symbolic model proves that operational capacity limit. |
| O03 | ULID random-field collision probability, claimed timestamp truth, and the implementation-defined freshness window | Environment assumption or product policy. Models use fresh symbolic identifiers and retained-state checks; after all slot state is discarded, they do not prove that freshness policy prevents identifier resurrection. |
| O04 | CSPRNG quality, secret erasure, constant-time comparison, and side-channel resistance | Endpoint/environment assumption. |
| O05 | Serialized, crash-safe persistence and absence of partial writes | Transition-system assumption. Tamarin can prove safety of the specified atomic transitions, not that a storage implementation realizes atomicity. |
| O06 | Exact byte lengths, ULID/Base64/JSON parsing, X25519 input handling, test vectors, and wire interoperability | Concrete conformance work, not a Dolev--Yao protocol proof. |
| O07 | Post-quantum security, availability, traffic-flow confidentiality, non-repudiation, and compromise of the trusted device | Explicitly not provided by the specification. |
| O08 | Pairing application metadata remains untrusted before SAS acceptance and causes no security-sensitive side effect | Endpoint/application-state assumption. The models show that the relay can choose or learn this metadata pre-SAS and model the later gate, but cannot prove how an application treats the bytes. |
