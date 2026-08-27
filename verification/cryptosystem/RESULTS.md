# Agentknock v1 cryptosystem verification results

Specification SHA-256:
`ac86cb6cb2e4808fb8eea8358c6b4b4946d5cecc5fae806307e7b5c60dcc2d6f`.

This report maps every ID in [`CLAIMS.md`](CLAIMS.md) to its strongest direct
evidence and its qualification. “Proved” always means symbolically proved in
the documented Dolev--Yao abstraction, not computationally proved and not
implementation-verified.

The Tamarin portfolio contains 84 selected lemmas, all with recorded `verified`
verdicts under Tamarin 1.12.0/Maude 3.5.1, clean derivation checks, and no
warning or precomputation exemption. Exact per-theory counts and the
reproduction command are in [`tamarin/RESULTS.md`](tamarin/RESULTS.md).

The recorded ProVerif 2.05 verdict vectors match
[`proverif/RESULTS.md`](proverif/RESULTS.md). The recorded Verifpal 1.3.2 matrix
matches [`verifpal/RESULTS.md`](verifpal/RESULTS.md) at 1, 2, 4, and 8 sessions
per principal. Every attack verdict is classified as an advertised compromise
or non-property, a deliberately weakened-model witness, or an expected replay
through state deliberately absent from the Verifpal models.

## Pairing and activation

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| P01 | Symbolic executability | Tamarin `P01_honest_pairing_activation_executable` exhibits the honest pairing, SAS, activation request/response, and accepted activation completion; ProVerif's expected-false negated `ClientActivate` query independently witnesses the path through client activation. Reachability prevents vacuous safety proofs. |
| P02 | Symbolic proof | Tamarin `P02_completion_matches_committed_secret` and `P02_ordered_distinct_base_records`, plus the ProVerif completion correspondence, bind the opened secret to the retained commitment and distinguish ordered records 0 and 1. Exact HPKE bytes are O06. |
| P03 | Symbolic proof plus quantitative qualification | Tamarin `P03_sas_full_transcript_agreement`/`P03_sas_injective`, ProVerif's two SAS correspondences, and bounded Verifpal agreement cover the collision-free full-SAS branch. The real wrong-SAS probability and repeated-attempt bound are O02, not symbolic proofs. |
| P04 | Expected attack witnessed | Tamarin `P04_active_relay_learns_pre_sas_application`, ProVerif `negative_pairing_mitm.pv`, and Verifpal's two expected `c1` results show that a substituted clear response exposes both base-mode plaintexts before SAS. This is an advertised non-property rather than a counterexample to a positive claim. |
| P05 | Mixed: expected attack and symbolic gate proof | The negative pairing models show that base mode alone does not authenticate the intended device. Tamarin `P05_no_activation_before_sas` and the positive ProVerif activation correspondence prove the later gate; `P05_device_pending_metadata_can_be_attacker_chosen` shows why pre-SAS metadata must remain untrusted. Whether an application avoids side effects is O08. |
| P06 | Symbolic proof | Tamarin `P06_device_activation_agreement` and ProVerif's device-activation correspondences bind activation to the pending SAS-approved PSK and a matching request, with the stated key-compromise exceptions. Verifpal supplies bounded independent evidence. |
| P07 | Symbolic proof | Tamarin `P07_client_activation_authenticates_response` and ProVerif's injective response correspondence bind client activation to the matching request context and device transition, subject to compromise. Verifpal supplies bounded evidence. This proves context possession, not a signature. |
| P08 | Conditional state-machine proof | Tamarin's `P08_one_pairing_response_tuple`, `P08_pairing_completion_processed_once`, pairing response/completion redelivery witnesses, and activation `P08_*` lemmas cover both pairing and activation slots, exact redelivery, and one accepted effect while the modeled state is retained. `UniquePairingRequest` and `UniqueActivationRequest` encode the per-device slot/freshness rules; the models neither compact a response cache to a terminal marker nor garbage-collect the slot. Section 5.6's marker-based suppression and later freshness-based rejection are O03/O05 state-machine obligations, not additional cryptographic theorems. |

## Paired request, response, and completion

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| X01 | Symbolic proof with explicit compromise boundary | Tamarin `X01_request_confidentiality_even_after_psk_disclosure` and `X01_request_authentication`, and ProVerif request secrecy/correspondence, prove relay secrecy and PSK-holder authentication. A PSK alone does not open a recorded KEM context. A pre-accept PSK disclosure or live-context disclosure is an explicit authentication exception. Verifpal adds bounded secrecy evidence; its expected two-session injective replay shows why request-slot state is also required. |
| X02 | Symbolic proof of secrecy and context possession | Tamarin `X02_honest_response_confidentiality` and `X02_response_authenticates_context_possession_not_device_origin`, plus ProVerif, cover the response; Verifpal adds bounded secrecy evidence and the expected stateless replay boundary. Tamarin's constructive client-context-holder trace confirms the advertised non-property: this is not device-origin proof or non-repudiation. |
| X03 | Symbolic proof with live-context boundary | Tamarin's X03 secrecy and authentication/order lemmas and ProVerif's completion queries bind completion to record 1 after record 0. The missing-record-sequence negative controls find the expected swap. A revealed live context permits completion forgery, exactly why the honest-live-state assumption is required. |
| X04 | Symbolic proof with sensitivity controls | Tamarin `X04_accepted_request_matches_all_context_identifiers` and ProVerif's paired/two-version models bind version, device, client, and request identities. ProVerif `negative_missing_context_binding.pv` and `negative_missing_version_binding.pv`, plus Verifpal's multi-session missing-request-ID model, produce expected substitutions when components are removed. Fixed-width byte encoding remains O06. |
| X05 | Symbolic proof with negative controls | Tamarin's two X05 separation lemmas and the ProVerif/Verifpal sensitivity models reject cross-version, device, client, request, and record use in the cryptographic model. Selecting and retaining the correct transport slot is represented by state and restrictions; concrete routing, parsing, and encodings remain O05/O06. |
| X06 | Conditional state-machine proof | Tamarin's four X06 lemmas prove one request effect, one completion effect, a fixed response, and replay redelivery without reprocessing while the modeled slot/disposition/cache state is retained. The result depends directly on `UniqueDeviceRequestSlot`; cache compaction and garbage collection are not modeled. Section 5.6's terminal-marker suppression and later freshness-based rejection are O03/O05 obligations. This proves the specified retained-state machine rather than deriving replay safety from AEAD alone. |
| X07 | Symbolic cryptographic proof plus conditional uniqueness | Tamarin `X07_one_plaintext_per_response_key_nonce`, ProVerif response secrecy/correspondence, and Verifpal's independently labeled exporter/key/nonce schedule cover exporter, encapsulation, public random, and key/nonce binding. One-use/fixed-response safety additionally relies on the X06 slot/cache state while the encrypted response is retained; Section 8.2 normatively prohibits regeneration after discard, which is an O05 persistence obligation rather than a separate prover result. Concrete nonce formatting and primitive misuse resistance are O01/O06. |
| X08 | Conditional state-machine proof | Tamarin `X08_completion_uses_accepted_request_generation` and the focused phase witness `X08_old_request_completion_after_rotation_executable` retain the original PSK generation/context through later rotation. This depends on the specified retained request state and atomic persistence (O05); the phase witness is reachability evidence, not a second active-attacker proof. |

## PSK rotation and binding state

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| R01 | Conditional state-machine proof | Tamarin's three R01 lemmas prove derivation from one rotation context, repetition of one fixed encapsulation while pending, and no second client rotation before confirmation. The atomic replace-and-retain step is modeled; crash-safe realization is O05. |
| R02 | Symbolic proof | Tamarin `R02_adoption_requires_candidate_authenticated_request` and ProVerif's candidate correspondences prove that adoption coincides with a normal request opening under the derived candidate. Verifpal supplies one-session agreement and bounded secrecy evidence; its expected multi-session replay cannot represent the adoption slot state. |
| R03 | Symbolic cryptographic/state proof; parsing excluded | Tamarin `R03_no_bare_rotation_state_change` and the absence of any adoption rule without candidate-authenticated request cover absent, bare, or well-formed substituted encapsulations. Verifpal's pre-gate negative control shows substitution can change an uncommitted candidate and cause denial of service but not adoption. “Malformed” at the Base64/length/X25519/HPKE parsing layer is O06 and is not symbolically proved. |
| R04 | Symbolic state proof | Tamarin `R04_current_psk_success_ignores_rotation_field` and ProVerif's current-first correspondence show that a current-PSK success leaves binding state unchanged regardless of the optional field. Exact ignore-before-decode behavior is a conformance obligation O06. |
| R05 | Conditional state-machine proof | Tamarin's previous-generation lemmas prove ordinary overlap use is reachable, previous use cannot rotate, expiry is not extended, a second rotation retires the older generation, and a compromised previous PSK cannot install its attempted successor. The last result composes a checked-request gate established by the core rotation model and ProVerif with the old-versus-current generation invariant. The fixed deadline and correct clock/persistence are product/environment assumptions O03/O05. |
| R06 | Composed symbolic proof | The active-attacker Tamarin R02 model and ProVerif establish the checked candidate/request and response hops; Tamarin's two focused R06 state lemmas then bind clearing to the matching pending encapsulation and adopted/already-current successor. Verifpal gives one-session agreement and bounded secrecy evidence, while its multi-session replay demonstrates the need for that pending state. Clear errors or mere relay delivery have no confirmation rule. |
| R07 | Conditional executability/idempotency result | Tamarin `R07_lost_confirmation_recovery_executable` witnesses adoption followed by another request whose current-PSK step succeeds with the same still-pending encapsulation and then confirms. The fixed pending value comes from R01 and durable state from O05. |
| R08 | Conditional state-machine proof | Tamarin's client no-second-pending lemma, one-previous device state representation, `R08_second_rotation_replaces_previous_state`, and older-generation retirement lemma establish the two bounds. The no-second-unconfirmed rule is client-local: the device may accept a later independently authenticated rotation and then retains only the newer previous generation. These are properties of the specified serialized state machine, not of HPKE alone. |
| R09 | Conditional state-machine proof plus executability | Tamarin's R09 lemmas cover no new acceptance after invalidation, retained completion/cache behavior, and one-step two-binding isolation. Rotation rules require active binding state; the separate activation model has no rotation transition. Arbitrary-sequence isolation is a manual induction over binding-local transitions. The invalidation trigger/application policy is deliberately outside the specification, and atomic per-binding state is O05. |

## Compromise and advertised non-properties

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| C01 | Expected attacks witnessed | Tamarin's PSK impersonation and competing-rotation exists-traces, ProVerif `psk_compromise.pv`, and the one-session Verifpal `psk_holder_authority.vp` executions construct future request and rotation authority after current-PSK disclosure. Verifpal's multi-session equivalence failures are stateless cross-session replays, not additional compromise power. |
| C02 | Symbolic proof with structural extension | The recorded **request** is queried directly in Tamarin `C02_recorded_request_survives_psk_only_disclosure`, ProVerif, and Verifpal. For recorded **responses and completions**, the conclusion follows structurally from the uncompromised request-context secrecy assumptions and the X02/X03 secrecy lemmas; no separate C02-labeled end-to-end query claims more. Device-key or sender-context compromise remains an exception. |
| C03 | Expected attacks witnessed for one successor; longer lineage manual | Tamarin's end-to-end theory, ProVerif `device_key_compromise.pv`, and Verifpal `compromise_device_key.vp` recover the initial PSK, one mechanically modeled successor, and traffic in both generations after delayed `skD` disclosure. An arbitrary recorded successor chain follows by repeating the same reconstruction step; that extension is a manual induction, not an unbounded mechanized lineage proof. |
| C04 | Expected fork/race witnessed; conditional one-winner invariant | Tamarin's rollback/clone theories construct two distinct successors and a race from one cloned valid state, prove at most one distinct fork candidate is adopted by the modeled device lineage, and confirm that an adoption corresponds to an authenticated fork request. Clone identity is deliberately local metadata: it is absent from the wire, so the device cannot attribute a request to a particular copy. Rotation is not compromise recovery and clone detection is not provided. |
| C05 | Mixed: expected offline attack and manual visibility audit | ProVerif's `weaksecret pairing_address` query constructs a qualitative offline test of the deterministic public address identifier; it does not quantify dictionary entropy or cost. Relay visibility of identifiers, encapsulations, rotation presence, lengths, timestamps, timing, and traffic relationships follows by inspection of the clear envelope/transport fields and is not a separate formal confidentiality proof. |

## Obligations outside symbolic trace proofs

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| O01 | Cryptographic assumption | X25519, HPKE, HKDF-SHA256, and ChaCha20Poly1305 are ideal constructors/destructors. The portfolio checks use and binding of their abstract interfaces, not their concrete security or RFC implementations. |
| O02 | Quantitative/manual plus deployment assumption | [`QUANTITATIVE.md`](QUANTITATIVE.md) gives the exact maximum fixed-wrong-SAS probability `1.0000000502143058e-12` and union bound `min(1, n*p_max)`. The full-digit UI, commit-before-contribution premises, and enforcement of a finite pending-attempt cap are assumptions; the cap is not proved by the models. |
| O03 | Environment/product-policy assumption | Fresh symbolic request/client IDs model successful uniqueness and freshness checks. The ULID birthday bound is manual; clock truth, the freshness window, overlap deadlines, rollback resistance, and actual collision handling are not proved. |
| O04 | Endpoint/environment assumption | CSPRNG quality, erasure, constant-time comparison, and resistance to side channels are outside all three symbolic models. |
| O05 | Transition-system assumption | Tamarin proves safety of atomic serialized transitions and retained state represented in the rules/restrictions. It does not prove that storage is crash-safe, durable, race-free, or free of partial writes. |
| O06 | Concrete conformance obligation | Exact lengths, JSON/Base64/ULID parsing, fixed-width concatenation bytes, X25519 input handling, test vectors, and wire interoperability are not modeled. Symbolic terms assume successful, unambiguous parsing. |
| O07 | Explicit non-properties/out of scope | The models do not establish post-quantum security, availability, traffic-flow confidentiality, non-repudiation, or security after trusted-device compromise. Expected traces confirm denial-of-service possibilities, context-holder authority, and retrospective `skD` compromise where modeled. |
| O08 | Application-state assumption with formal premise witness | Tamarin and the pairing negative controls show that the relay can learn or choose application metadata before SAS and that the later cryptographic activation gate holds. They cannot prove that an application avoids security-sensitive side effects from those untrusted bytes before the gate. |

## Interpretation and proof boundaries

The portfolio has no counterexample to its positive claims. The expected
attacks and focused models establish the following interpretation boundaries:

- **Live request-context disclosure is stronger than PSK-only disclosure.**
  Revealing the context, its exporter secret, or equivalent record-key material
  can enable a first-request replacement before device acceptance and the
  construction of a context-consistent response or completion. Tamarin contains
  explicit request-replacement and completion-forgery traces plus a
  context-holder response-construction witness. The specification excludes
  this case by assuming honest live client state for the duration of an
  exchange, so this is a query qualification rather than an attack under its
  threat model.
- **A rotation encapsulation is authenticated only by the later request gate.**
  A relay can replace a well-formed `rotation_enc`, changing the raw
  uncommitted candidate and causing failure. The candidate cannot be adopted
  unless the ordinary request authenticates under it. This is an availability
  effect, which the specification already disclaims.
- **The 12-digit reduction has a tiny calculable modulo bias.** The worst
  fixed wrong value succeeds with probability
  `1.0000000502143058e-12`, slightly above exactly `10^-12`; the advertised
  “approximately” wording is accurate.
- **State uniqueness is an explicit premise.** Replay, one-effect, fixed-cache,
  and lineage safety proofs depend on device-local freshness/slot restrictions
  and serialized retained state. They validate the specified transition
  system, not a storage implementation.
- **The mechanized retrospective lineage has one rotation edge.** Both
  generations are opened after delayed device-key compromise. Extension to
  every recorded successor is treated as manual induction rather than as an
  unbounded mechanized claim.
- **Responses and completions authenticate context possession.** They do not
  establish which endpoint constructed the record and are not third-party
  evidence or non-repudiation.
- **Activation-response secrecy is request-relative.** A response to an
  honest, uncompromised activation request remains secret. A holder of a
  disclosed current PSK can instead initiate a valid activation request and
  knows that request's response context. A blanket post-compromise response
  secrecy claim would therefore be false; this is the authority described by
  C01.
- **Clone identity is not protocol data.** A cloned client can create a
  distinct authenticated fork request, but the device cannot tell whether
  local copy A or B originated it. The one-winner result is about distinct
  authenticated candidates on one linear device binding, not endpoint
  attribution to a synthetic clone label.
