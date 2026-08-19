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
| P03 | proved under ideal full-SAS equality | Both SAS correspondence directions agree injectively on client secret, device random, device/client identities, device public key, and exported PSK. O02 remains manual. |
| P04-P05 | expected attacks plus proved gate | Without SAS, application secrecy and intended-device correspondence are false. In the full model, device activation implies prior SAS authorization. |
| P06-P07 | proved | Device activation agrees with the matching client PSK request; client activation injectively agrees with the authenticated matching response. |
| X01-X03 | proved against the relay with honest endpoints | All three plaintext secrecy queries are true; matching request, response, and completion correspondences are true. These correspondences establish context possession, not non-repudiable endpoint origin. |
| X04-X05 | proved, with sensitivity controls | Full bindings pass even when two device aliases share one key and PSK. A separate two-version model accepts either public outer version yet proves version agreement from the common HPKE-info tuple. Removing all context, the version component, or record sequence makes the corresponding query false. |
| X07 | cryptographic part proved | Response secrecy and injective correspondence bind exporter, encapsulation, fresh response random, and the two outputs of one label-sensitive response KDF. Fixed-state uniqueness is not modeled here. |
| R02-R04 | one-generation core proved | Current-first acceptance ignores `rotation_enc`; adoption implies both a prepared successor and an ordinary request authenticated by that candidate. |
| R06 | one-generation core proved | Client confirmation injectively agrees with the candidate-context response and device adoption. |
| C01 | expected attack | Releasing the current PSK produces a concrete future client-impersonation trace. |
| C02 | proved | Releasing the current PSK alone does not reveal the already-recorded paired request without `skD` or the sender ephemeral. |
| C03 | expected attacks, one recorded successor | Delayed `skD` release reveals the base application, initial-generation request, and one successor-generation request. Repeating the same reconstruction step over a longer recorded lineage is a manual induction, not a directly unbounded ProVerif result. |
| C05 | expected attack | `weaksecret pairing_address` is false for the public deterministic address derivation, qualitatively confirming offline testing. |

P08, X06, X08, R01, R05, R07-R09, and C04 depend on mutable state,
idempotency, or lineage and have no ProVerif proof claim. See the Tamarin
results and the shared [`CLAIMS.md`](../CLAIMS.md).

## Exact summaries

### `paired_exchange.pv`

```text
Query not event(ClientAcceptResponse(did,cid,rid,message)) is false. [EXPECTED REACHABILITY WITNESS]
Query not attacker(request_plaintext[]) is true.
Query not attacker(response_plaintext[]) is true.
Query not attacker(completion_plaintext[]) is true.
Query event(DeviceAcceptRequest(did,cid,rid,message)) ==> event(ClientSendRequest(did,cid,rid,message)) is true.
Query inj-event(ClientAcceptResponse(did,cid,rid,message)) ==> inj-event(DeviceSendResponse(did,cid,rid,message)) is true.
Query event(DeviceAcceptCompletion(did,cid,rid,message)) ==> event(ClientSendCompletion(did,cid,rid,message)) is true.
```

### `pairing_activation.pv`

```text
Query not event(ClientActivate(did,cid,rid,response_1,binding_psk_2)) is false. [EXPECTED REACHABILITY WITNESS]
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
Query not event(ClientConfirmRotation(did,cid,rid,response_1,rotation_enc_2,successor_psk_2)) is false. [EXPECTED REACHABILITY WITNESS]
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
Query not event(DeviceAccept(version_3,did,cid,rid,message_1)) is false. [EXPECTED REACHABILITY WITNESS]
Query event(DeviceAccept(version_3,did,cid,rid,message_1)) ==> event(ClientSend(version_3,did,cid,rid,message_1)) is true.
```

### Compromise and negative-control summaries

```text
psk_compromise.pv:
  Query not attacker(historical_plaintext[]) is true.
  Query event(DeviceAccept(cid,rid,message_1)) ==> event(HonestClientSend(cid,rid,message_1)) is false. [EXPECTED C01 ATTACK]

device_key_compromise.pv:
  Query not attacker(pairing_application_plaintext[]) is false. [EXPECTED C03 ATTACK]
  Query not attacker(initial_psk_request_plaintext[]) is false. [EXPECTED C03 ATTACK]
  Query not attacker(successor_psk_request_plaintext[]) is false. [EXPECTED C03 ATTACK]

address_offline_guess.pv:
  Weak secret pairing_address is false. [EXPECTED C05 OFFLINE TEST]

negative_pairing_mitm.pv:
  Query not attacker(pairing_application_plaintext[]) is false. [EXPECTED P04 ATTACK]
  Query event(ClientCompleteBaseExchange(did,cid,public_key_2,device_random_2)) ==> event(HonestDeviceResponse(did,cid,public_key_2,device_random_2)) is false. [EXPECTED P05 ATTACK]

negative_missing_context_binding.pv:
  Query event(DeviceAcceptRequest(did,cid,rid,message)) ==> event(ClientSendRequest(did,cid,rid,message)) is false. [EXPECTED X04/X05 ATTACK]

negative_missing_record_sequence.pv:
  Query event(DeviceAcceptCompletion(cid,rid,message)) ==> event(ClientSendCompletion(cid,rid,message)) is false. [EXPECTED X03/X05 ATTACK]

negative_missing_version_binding.pv:
  Query event(DeviceAccept(version_1,did,cid,rid,message_1)) ==> event(ClientSend(version_1,did,cid,rid,message_1)) is false. [EXPECTED X04/X05 ATTACK]
```

Every false ProVerif verdict is classified above as an executable honest path,
an advertised compromise or non-property, or a deliberately weakened negative
control.
