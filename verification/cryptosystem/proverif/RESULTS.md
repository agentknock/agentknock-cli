# ProVerif 2.05 results

Tool banner:

```text
Proverif 2.05. Cryptographic protocol verifier, by Bruno Blanchet, Vincent Cheval, and Marc Sylvestre
```

Command:

```sh
bash verification/cryptosystem/proverif/run.sh
```

## Interpretation by claim

| Claims | Result | Evidence |
| --- | --- | --- |
| P01 | reachable | The deliberately negated `ClientActivate` reachability query is false with an executable honest trace. |
| P02 | proved | Pairing completion acceptance implies two successful, sequence-ordered opens and equality between the recovered client secret's commitment and the retained request commitment. |
| P03 | proved under ideal full-SAS equality | The two SAS correspondences agree on client secret, device random, device/client identities, device public key, and exported PSK; only the client-acceptance direction is injective. O02 remains manual. |
| P04-P05 | expected attacks plus proved gate | Without SAS, application secrecy and intended-device correspondence are false. In the full model, device activation implies prior SAS authorization. |
| P06-P07 | proved | Device activation agrees with the matching client PSK request; client activation injectively agrees with the authenticated matching response. |
| X01-X03 | proved against the relay with honest endpoints | All three plaintext secrecy queries are true; matching request, response, and completion correspondences are true. These correspondences establish context possession, not non-repudiable endpoint origin. |
| X04-X05 | proved, with sensitivity controls | Full bindings pass even when two device aliases share one key and PSK. A separate two-version model accepts either public outer version yet proves version agreement from the common HPKE-info tuple. Removing all context, the version component, or record sequence makes the corresponding query false. |
| X07 | cryptographic part proved | Response secrecy and injective correspondence bind exporter, encapsulation, fresh response random, and the two outputs of one label-sensitive response KDF. Fixed-state uniqueness is not modeled here. |
| R02-R04 | one-generation core proved | Current-first acceptance ignores `rotation_enc`; adoption implies both a prepared successor and an ordinary request authenticated by that candidate. |
| R06 | one-generation core proved | Client confirmation injectively agrees with the candidate-context response and earlier device adoption. It does not assert current device state at delivery. |
| C01 | expected attack | Releasing the current PSK produces a concrete future client-impersonation trace. |
| C02 | proved | Direct secrecy queries cover the recorded request, accepted response, and completion after PSK-only disclosure. The separate recorded-transcript biprocess proves observational equivalence; device-key and context variants have reconstructed distinguishers. See the experiment boundary in [README.md](README.md). |
| C03 | expected attacks, one recorded successor | Delayed `skD` release reveals the base application, initial-generation request, and one successor-generation request. Repeating the same reconstruction step over a longer recorded lineage is a manual induction, not a directly unbounded ProVerif result. |
| C05 | expected attack | `weaksecret pairing_address` is false for the public deterministic address derivation, qualitatively confirming offline testing. |

P08, X06, X08, R01, R05, R07-R09, and C04 depend on mutable state,
idempotency, or lineage and have no ProVerif proof claim. See the Tamarin
results and the shared [`CLAIMS.md`](../CLAIMS.md).

## Exact summaries

All 14 models matched the following summaries. A false reachability query is
an intended executable witness. Other false results are the advertised
compromise/offline-test cases or deliberately weakened negative controls.
The two equivalence controls have unknown summaries **with concrete reconstructed
distinguishers**, as explained in [README.md](README.md); they are not false
verdicts and do not license accepting unknown positive proofs.

### `paired_exchange.pv`

```text
Query not event(ClientAcceptResponse(did,cid,rid,message)) is false.
Query not attacker(request_plaintext[]) is true.
Query not attacker(response_plaintext[]) is true.
Query not attacker(completion_plaintext[]) is true.
Query event(DeviceAcceptRequest(did,cid,rid,message)) ==> event(ClientSendRequest(did,cid,rid,message)) is true.
Query inj-event(ClientAcceptResponse(did,cid,rid,message)) ==> inj-event(DeviceSendResponse(did,cid,rid,message)) is true.
Query event(DeviceAcceptCompletion(did,cid,rid,message)) ==> event(ClientSendCompletion(did,cid,rid,message)) is true.
```

### `pairing_activation.pv`

```text
Query not event(ClientActivate(did,cid,rid,response_1,binding_psk_2)) is false.
Query not attacker(activation_request_plaintext[]) is true.
Query not attacker(activation_response_plaintext[]) is true.
Query event(DeviceAcceptPairingCompletion(did,cid,client_secret_2,application_1,binding_psk_2)) ==> event(DeviceRetainPairingRequest(did,cid,commitment(commitment_label[],client_secret_2))) is true.
Query inj-event(ClientAcceptSAS(did,cid,public_key_3,client_secret_2,device_random_2,displayed_sas_2,binding_psk_2)) ==> inj-event(DeviceAcceptSAS(did,cid,public_key_3,client_secret_2,device_random_2,displayed_sas_2,binding_psk_2)) is true.
Query event(DeviceAcceptSAS(did,cid,public_key_3,client_secret_2,device_random_2,displayed_sas_2,binding_psk_2)) ==> event(ClientOfferSAS(did,cid,public_key_3,client_secret_2,device_random_2,displayed_sas_2,binding_psk_2)) is true.
Query event(DeviceActivate(did,cid,rid,request_1,binding_psk_2)) ==> event(ClientSendActivation(did,cid,rid,request_1,binding_psk_2)) is true.
Query event(DeviceActivate(did,cid,rid,request_1,binding_psk_2)) ==> event(DeviceAuthorizeBinding(did,cid,binding_psk_2)) is true.
Query inj-event(ClientActivate(did,cid,rid,response_1,binding_psk_2)) ==> inj-event(DeviceSendActivationResponse(did,cid,rid,response_1,binding_psk_2)) is true.
```

### `rotation_step.pv`

```text
Query not event(ClientConfirmRotation(did,cid,rid,response_1,rotation_enc_2,successor_psk_2)) is false.
Query not attacker(current_request_plaintext[]) is true.
Query not attacker(rotated_request_plaintext[]) is true.
Query not attacker(rotated_response_plaintext[]) is true.
Query event(DeviceAcceptCurrentRequest(did,cid,rid,request,current_psk_4)) ==> event(ClientSendCurrentRequest(did,cid,rid,request,current_psk_4)) is true.
Query event(DeviceAdoptCandidate(did,cid,rid,request,rotation_enc_2,successor_psk_2)) ==> event(ClientSendRotatedRequest(did,cid,rid,request,rotation_enc_2,successor_psk_2)) is true.
Query event(DeviceAdoptCandidate(did,cid,rid,request,rotation_enc_2,successor_psk_2)) ==> event(ClientPrepareRotation(did,cid,rotation_enc_2,successor_psk_2)) is true.
Query inj-event(ClientConfirmRotation(did,cid,rid,response_1,rotation_enc_2,successor_psk_2)) ==> inj-event(DeviceSendRotatedResponse(did,cid,rid,response_1,rotation_enc_2,successor_psk_2)) is true.
Query event(ClientConfirmRotation(did,cid,rid,response_1,rotation_enc_2,successor_psk_2)) ==> event(DeviceAdoptGeneration(did,cid,rid,rotation_enc_2,successor_psk_2)) is true.
```

### `version_binding.pv`

```text
Query not event(DeviceAccept(version_3,did,cid,rid,message_1)) is false.
Query event(DeviceAccept(version_3,did,cid,rid,message_1)) ==> event(ClientSend(version_3,did,cid,rid,message_1)) is true.
```

### `psk_compromise.pv`

```text
Query not attacker(historical_plaintext[]) is true.
Query not (event(RecordedResponse(response_2)) && attacker(response_2)) is true.
Query not attacker(historical_completion[]) is true.
Query not event(RecordedResponse(response_2)) is false.
Query event(DeviceAccept(cid,rid,message_1)) ==> event(HonestClientSend(cid,rid,message_1)) is false.
```

### `device_key_compromise.pv`

```text
Query not attacker(pairing_application_plaintext[]) is false.
Query not attacker(initial_psk_request_plaintext[]) is false.
Query not attacker(successor_psk_request_plaintext[]) is false.
```

### `address_offline_guess.pv`

```text
Weak secret pairing_address is false.
```

### `negative_pairing_mitm.pv`

```text
Query not attacker(pairing_application_plaintext[]) is false.
Query event(ClientCompleteBaseExchange(did,cid,public_key_2,device_random_2)) ==> event(HonestDeviceResponse(did,cid,public_key_2,device_random_2)) is false.
```

### `negative_missing_context_binding.pv`

```text
Query event(DeviceAcceptRequest(did,cid,rid,message)) ==> event(ClientSendRequest(did,cid,rid,message)) is false.
```

### `negative_missing_record_sequence.pv`

```text
Query event(DeviceAcceptCompletion(cid,rid,message)) ==> event(ClientSendCompletion(cid,rid,message)) is false.
```

### `negative_missing_version_binding.pv`

```text
Query event(DeviceAccept(version_1,did,cid,rid,message_1)) ==> event(ClientSend(version_1,did,cid,rid,message_1)) is false.
```

### `recorded_exchange_psk_disclosure.pv`

```text
Observational equivalence is true.
```

### `recorded_exchange_device_key_disclosure.pv`

```text
Observational equivalence cannot be proved.
```

### `recorded_exchange_context_disclosure.pv`

```text
Observational equivalence cannot be proved.
```
