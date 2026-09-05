# Agentknock v1 cryptosystem verification results

Specification SHA-256:
`ac86cb6cb2e4808fb8eea8358c6b4b4946d5cecc5fae806307e7b5c60dcc2d6f`.

This report maps every ID in [`CLAIMS.md`](CLAIMS.md) to its strongest direct
evidence and its qualification. “Proved” always means symbolically proved in
the documented Dolev--Yao abstraction, not computationally proved and not
implementation-verified.

The Tamarin portfolio records every declared lemma in its checked case inventory,
with `verified` verdicts under Tamarin 1.12.0/Maude 3.5.1, clean derivation checks, and no
warning or precomputation exemption. Exact per-theory counts and the
reproduction command are in [`tamarin/RESULTS.md`](tamarin/RESULTS.md).

The recorded ProVerif 2.05 verdict vectors match
[`proverif/RESULTS.md`](proverif/RESULTS.md). The recorded Verifpal 1.4.3 matrix
matches [`verifpal/RESULTS.md`](verifpal/RESULTS.md): 35 explicit-query analyses
(smaller models through eight sessions, combined pairing through four) and 12
generated-query analyses. Expected violations are interpreted individually in
the tool's primitive/role abstraction; generated pre-gate and seed-recovery
reports are not promoted to concrete protocol attacks. [AUDIT.md](AUDIT.md)
records the modeling errors corrected in this revision.

## Pairing and activation

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| P01 | Symbolic executability | The core Tamarin `P01_active_network_pairing_activation_executable` and the honest phase witness cover pairing, SAS, activation, and accepted completion. ProVerif independently reaches client activation. Core witnesses establish executable intended paths; they do not establish reachability of every lemma antecedent. |
| P02 | Symbolic proof | Tamarin `P02_completion_matches_committed_secret` and `P02_ordered_distinct_base_records`, plus the ProVerif completion correspondence, bind the opened secret to the retained commitment and distinguish ordered records 0 and 1. Exact HPKE bytes are O06. |
| P03 | Symbolic proof plus quantitative qualification | The SAS comparison now matches only equal codes, with independent endpoint PSKs. Tamarin proves the full SAS transcript, injectivity, key agreement, and the corresponding complete pairing ciphertext tuple. Key/completion agreement excludes earlier device-key disclosure; a control shows equal SAS with different PSKs under that compromise. ProVerif independently proves both SAS correspondence directions (only client acceptance is injective). O02 handles real decimal collisions. |
| P04 | Expected attack witnessed | Tamarin `P04_active_relay_learns_pre_sas_application`, ProVerif `negative_pairing_mitm.pv`, and Verifpal's two expected `c1` results show that a substituted clear response exposes both base-mode plaintexts before SAS. This is an advertised non-property rather than a counterexample to a positive claim. |
| P05 | Mixed: expected attack and symbolic gate proof | The negative pairing models show that base mode alone does not authenticate the intended device. Tamarin `P05_no_activation_before_sas` and the positive ProVerif activation correspondence prove the later gate; `P05_device_pending_metadata_can_be_attacker_chosen` shows why pre-SAS metadata must remain untrusted. Whether an application avoids side effects is O08. |
| P06 | Symbolic proof | Tamarin `P06_device_activation_agreement` and ProVerif's device-activation correspondences bind activation to the pending SAS-approved PSK and a matching request, with the stated key-compromise exceptions. Verifpal supplies bounded independent evidence. |
| P07 | Symbolic proof | Tamarin `P07_client_activation_authenticates_response` and ProVerif's injective response correspondence bind client activation to the matching request context and device transition, subject to compromise. Verifpal supplies bounded evidence. This proves context possession, not a signature. |
| P08 | Conditional state-machine proof | The core P08 lemmas check fixed pairing/activation slots, one effect, and exact redelivery under explicit slot-uniqueness restrictions. The separate linear `slot_lifecycle` model checks compaction to a terminal marker and eventual discard without a uniqueness restriction. It abstracts an already authenticated exchange and assumes identifiers are not reissued after discard. Real freshness and persistence remain O03/O05. |

## Paired request, response, and completion

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| X01 | Symbolic proof with explicit compromise boundary | Tamarin and ProVerif prove request secrecy and PSK-holder authentication with the stated device/live-context exceptions. PSK-only disclosure does not open the recorded KEM context. Verifpal adds bounded secrecy evidence; request replay into replicated stateless receiver roles violates injective authentication from two sessions. |
| X02 | Symbolic proof of secrecy and context possession | Tamarin and ProVerif prove response secrecy and context-possession correspondence. Verifpal response authentication holds at the tested bounds; same-instance plaintext equality can fail when another honest device role answers a replayed request. The Tamarin client-context-holder witness confirms this is not device-origin proof or non-repudiation. |
| X03 | Symbolic proof with live-context boundary | Tamarin's X03 secrecy and authentication/order lemmas and ProVerif's completion queries bind completion to record 1 after record 0. The missing-record-sequence negative controls find the expected swap. A revealed live context permits completion forgery, exactly why the honest-live-state assumption is required. |
| X04 | Symbolic proof with sensitivity controls | Tamarin and ProVerif bind version, device, client, and request identities, including shared-device-key/binding cases and independent version tests. Removing context or version bindings produces ProVerif attacks. Verifpal's missing-request-ID control keeps the KEM and demonstrates a one-session outer-ID relabeling that still passes the open. Exact byte encoding remains O06. |
| X05 | Symbolic proof with negative controls | Tamarin's two X05 separation lemmas and the ProVerif/Verifpal sensitivity models reject cross-version, device, client, request, and record use in the cryptographic model. Selecting and retaining the correct transport slot is represented by state and restrictions; concrete routing, parsing, and encodings remain O05/O06. |
| X06 | Conditional state-machine proof | The cryptographic core checks fixed response/redelivery and one request/completion effect under slot restrictions. The separate linear `slot_lifecycle` model directly proves those state invariants, compaction suppression, and no later effects after discard without a uniqueness restriction. Its fresh allocation rule assumes forgotten identifiers are not reissued; it does not prove the O03 freshness policy or O05 storage implementation. |
| X07 | Symbolic cryptographic and state proof | Tamarin, ProVerif, and Verifpal cover exporter, encapsulation, public random, and response key/nonce binding. Tamarin fixes one response per accepted slot; the separate cache lifecycle suppresses regeneration after compaction. Verifpal uses explicit nonce arguments, shares the HPKE key across sequences, and detects the deliberate nonce-reuse control. Exact nonce bytes and primitive security remain O01/O06. |
| X08 | Conditional state-machine proof | Tamarin `X08_completion_uses_accepted_request_generation` and the focused phase witness `X08_old_request_completion_after_rotation_executable` retain the original PSK generation/context through later rotation. This depends on the specified retained request state and atomic persistence (O05); the phase witness is reachability evidence, not a second active-attacker proof. |

## PSK rotation and binding state

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| R01 | Conditional state-machine proof | Tamarin's three R01 lemmas prove derivation from one rotation context, repetition of one fixed encapsulation while pending, and no second client rotation before confirmation. The atomic replace-and-retain step is modeled; crash-safe realization is O05. |
| R02 | Symbolic proof | Tamarin checks that adoption occurs only in the rule opening an ordinary request under the current-derived candidate, including arbitrary current-holder inputs. ProVerif independently proves candidate/request correspondences. Verifpal checks agreement after the request gate; its replicated roles omit the mutable adoption slot. |
| R03 | Symbolic cryptographic/state proof; parsing excluded | Tamarin `R03_no_bare_rotation_state_change` and the absence of any adoption rule without candidate-authenticated request cover absent, bare, or well-formed substituted encapsulations. Verifpal's pre-gate negative control shows substitution can change an uncommitted candidate and cause denial of service but not adoption. “Malformed” at the Base64/length/X25519/HPKE parsing layer is O06 and is not symbolically proved. |
| R04 | Symbolic state proof | Tamarin `R04_current_psk_success_ignores_rotation_field` and ProVerif's current-first correspondence show that a current-PSK success leaves binding state unchanged regardless of the optional field. Exact ignore-before-decode behavior is a conformance obligation O06. |
| R05 | Conditional state and cryptographic proofs | The active-network previous-key model checks the encrypted candidate gate and proves that a previous-only holder cannot forge an accepted rotation request; honest acceptance and current-key disclosure forgery are reachable controls. The generation-state model checks fixed overlap tokens, expiry, replacement, and retirement over repeated transitions. The nested successor constructor retains the current-bound lineage under ideal KDF injectivity; real primitive security, clocks, and persistence remain O01/O03/O05. |
| R06 | Composed symbolic proof with temporal qualification | The focused Tamarin state model and ProVerif bind confirmation to the matching request, pending encapsulation, and earlier device possession of the successor. This is historical agreement: a Tamarin witness confirms after device invalidation. It does not certify current state at response delivery. Clear errors and relay acknowledgments cannot confirm rotation. |
| R07 | Conditional executability/idempotency result | Tamarin `R07_lost_confirmation_recovery_executable` witnesses adoption followed by another request whose current-PSK step succeeds with the same still-pending encapsulation and then confirms. The fixed pending value comes from R01 and durable state from O05. |
| R08 | Conditional state-machine proof | Client serialization permits one unconfirmed rotation. The binding lifecycle stores one previous generation, relates previous use to the transition that established the current generation, and checks retirement after a later rotation. The nested successor terms preserve the lineage under ideal KDF injectivity. These are state-machine properties, not consequences of HPKE alone. |
| R09 | Conditional state-machine proof | The binding lifecycle checks active-only rotation, rejection, and no new acceptance after invalidation. Retained-context/cache witnesses remain independent of new-request authority. The rewritten binding-isolation model compares actual observations across arbitrary sequences of attacker-chosen updates to other entries; isolation no longer rests on a same-step preserved-state assertion or a manual extension. |

## Compromise and advertised non-properties

| ID | Disposition | Evidence and qualification |
| --- | --- | --- |
| C01 | Expected attacks witnessed | Tamarin's PSK impersonation and competing-rotation exists-traces, ProVerif `psk_compromise.pv`, and the one-session Verifpal `psk_holder_authority.vp` executions construct future request and rotation authority after current-PSK disclosure. Verifpal's multi-session equivalence failures are stateless cross-session replays, not additional compromise power. |
| C02 | Direct symbolic secrecy and recorded-transcript equivalence | Tamarin, ProVerif, and Verifpal directly query recorded requests, responses, and completions after PSK-only disclosure. ProVerif additionally proves observational equivalence between attacker-chosen plaintext tuples with the same public transcript shape. The experiment has unbounded recordings/bindings but no application/decryption oracle; equal byte lengths and public behavior are external premises. Device-key and live-context controls reconstruct distinguishers and return the exact “cannot be proved” summaries, not false verdicts. |
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

The recorded results support the qualified positive claims above in their
stated models. The expected
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
- **State and freshness have separate proof boundaries.** The cryptographic
  cores use explicit slot restrictions. Separate linear state models check
  cache compaction and per-binding transitions without those restrictions.
  They still assume atomic state and correctly enforced identifier freshness;
  they do not verify a storage or clock implementation.
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
