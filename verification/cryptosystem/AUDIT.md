# Verification audit — 2026-09-05

The audit reviewed the entire cryptosystem specification, every existing
Tamarin, ProVerif, and Verifpal model, all runners and reports, and the relevant
CLI cryptography, exchange, pairing, and persisted-state paths. The verification
target remains the specification hash in [SPECIFICATION.sha256](SPECIFICATION.sha256).
This is a specification-level portfolio, not an implementation-conformance proof.

## Corrections

1. **SAS agreement was partly assumed.** The Tamarin comparison rule unified
   the two PSKs even though users compare only SAS values. It now matches only
   the displayed code and keeps the endpoint PSKs independent. Separate
   correspondence lemmas establish key and full completion agreement under
   the device-key secrecy assumption. A device-key disclosure control admits
   equal SAS values with different PSKs. The honest phase witness was corrected
   too. Rejection is now device-local and possible in each pre-activation phase.
2. **Previous-key rotation rejection was vacuous.** The old model connected an
   old-derived candidate to a current-derived candidate through a private wire
   that could never match. The replacement checks the complete encrypted
   candidate request on the active network. It includes both an honest accepted
   request and a current-key disclosure forgery control.
3. **Some lemma names overstated their formulas.** A claimed binding-isolation
   event contained the same state twice by construction, and a claimed
   replacement lemma checked only a simultaneous mutation event. Isolation now
   compares actual state at different times across arbitrary intervening updates.
   The redundant replacement event check was removed; the successor-inequality
   lemma was renamed to describe its actual result. Focused generation and slot
   lifecycle models make their abstractions explicit.
4. **C02 directly covered only requests.** Tamarin, ProVerif, and Verifpal now
   query recorded request, response, and completion secrecy after PSK-only
   disclosure. ProVerif additionally checks a replicated chosen-plaintext
   recorded-transcript equivalence experiment, with device-key and live-context
   disclosure distinguishers. Equal lengths and identical public behavior are
   external premises; there is no application/decryption oracle in that experiment.
5. **Some protocol contexts were accidentally separated.** Ordinary Tamarin
   bindings now share a registered device key. Verifpal's base, ordinary, and
   rotation schedules consistently use the third HKDF output for the exporter.
6. **Verifpal's primitive interface and results were stale.** The pin is now
   1.4.3, built with its upstream tests. AEAD uses explicit key and nonce
   arguments; sequential records share a key and use distinct modeled nonces.
   The nonce-reuse control checks both swaps and confidentiality loss. The
   missing-request-ID control retains KEM setup and detects a direct one-session
   relabeling, rather than relying on the same multi-session replay as the
   positive model. Response-authentication failures reported by the old tool
   are superseded by the new results.
7. **Confirmation wording needed a temporal qualification.** Key confirmation
   establishes earlier device possession, not current state when a delayed
   response arrives. A focused witness confirms after device invalidation.
8. **The runners could accept incomplete evidence.** Every model and Tamarin
   lemma must be registered. ProVerif rejects unrecognized or extra summary
   lines. Verifpal checks complete JSON reports, query identities, and every
   search envelope. Resource limits, tool-version checks, specification-hash
   checks, and regression tests cover the reproduction path. Unknown positive
   proofs never count as successes. ProVerif's two equivalence controls require
   concrete distinguishing traces in addition to their unknown summaries.

## Remaining boundaries

The state proofs assume atomic transitions and a correctly enforced identifier
freshness policy. The free current-bound successor constructor retains the full
nested lineage; its ideal injectivity is not a computational proof of KDF
collision resistance. Cache compaction and identifier discard are distinct from
proving real clocks, storage durability, or crash recovery. The retrospective
compromise experiments mechanically cover
one rotation edge; a longer recorded lineage still uses the documented manual
induction.

Verifpal is supporting bounded evidence. The combined pairing model was tested
through four sessions; the smaller models through eight. Generated queries
include intermediate pre-gate uses and an ideal KEM seed-recovery abstraction;
those reports do not establish accepted protocol forgeries or X25519 scalar
recovery. [RESULTS.md](RESULTS.md) and the per-tool reports give the exact claims,
verdicts, and qualifications.
