# The Agentknock v1 cryptosystem

## Abstract

Agentknock lets a client and a device exchange protected application messages
through an untrusted relay. This document specifies the cryptography for
pairing the endpoints, protecting request-response-completion exchanges, and
rotating the pairing pre-shared key (PSK).

The construction uses HPKE base mode during initial pairing, an out-of-band
short authentication string (SAS) to authenticate that pairing, and HPKE PSK
mode after pairing. Responses use a key and nonce derived from the request HPKE
context. Completions use the second record in that same HPKE context.

This document fixes every cryptographic algorithm, byte and envelope encoding,
domain-separation label, context value, and message-order invariant required
for an interoperable implementation of `agentknock-v1`.

## 1. Scope

Except for values that are direct inputs to the cryptosystem, protected
application plaintexts are opaque byte strings here. Their schemas and
semantics are outside this document. JSON inside a ciphertext does not need a
canonical encoding: the cryptosystem protects the exact bytes supplied to it.

Transport behavior, application behavior, and platform-specific storage are
also outside this document except where they impose a cryptographic state or
uniqueness requirement.

The transport supplies the identifiers and cryptographic objects named below as
untrusted inputs. Values in the clear initial pairing exchange are authenticated
only by the later SAS confirmation. No trust is placed in the transport for
confidentiality, integrity, or endpoint authentication.

## 2. Roles, terminology, and threat model

### 2.1. Roles and terminology

The cryptosystem has three roles:

- The **client** initiates pairing and all later protected exchanges.
- The **device** owns a stable X25519 key pair, receives requests, and returns
  responses.
- The **relay** transports messages between them.

Pairing creates a **binding**: a long-lived association between one device
identity and one client identity that holds their shared `client_psk`. A
pending binding can be used only to finish pairing; an active binding can be
used for ordinary paired exchanges.

### 2.2. Construction overview

Protocol messages shown below travel through the untrusted relay; the arrows
indicate only their logical direction. SAS confirmation is the exception and
occurs out of band.

```text
Initial pairing and activation

Client  -> Device   clear pairing request
Client  <- Device   clear pairing response
Client  -> Device   base-mode pairing completion
Client <-> Device   out-of-band SAS confirmation
Client  -> Device   PSK-mode activation request
Client  <- Device   protected activation response
Client  -> Device   protected activation completion

Ordinary paired exchange

Client  -> Device   paired request
Client  <- Device   paired response
Client  -> Device   optional paired completion
```

The initial base-mode exchange establishes `client_psk`; SAS confirmation
authenticates the binding. The activation exchange confirms possession of that
PSK at both endpoints. Later exchanges use PSK mode. Rotation derives a
successor PSK and carries the corresponding encapsulated key in every new
paired request until the rotation is confirmed.

### 2.3. Threat model

The relay is a fully active adversary. It can observe, delay, drop, replay,
reorder, modify, and fabricate messages. It can always deny service and perform
traffic analysis. Before SAS verification, it can also replace the clear
pairing response, including the device public key.

The device is the trusted endpoint. Its implementation, random-number
generator, long-term private key, and cryptographic state are assumed to behave
as specified. Compromise of the device is outside the protection offered by
this cryptosystem.

For the confidentiality and authenticity of one honest exchange, the client
process, its random-number generator, and its live exchange state are assumed
to behave as specified for the duration of that exchange. Durable client state
has a weaker trust assumption: it can be disclosed, copied, lost, or rolled
back. The consequences of those events are part of the security analysis; the
cryptosystem does not turn general-purpose client storage into a trusted
keystore.

The device treats all client input as adversarial, including input produced by
a client that possesses a valid PSK. Such a client can act with the authority
of its own binding and can deny service to that binding. It must not be able to
make the device encrypt different plaintexts under the same key and nonce,
process more than one accepted record for one protocol slot, roll back
cryptographic state, expose the device private key, or alter another client
binding. The uniqueness and state-transition rules in this document are
device-side requirements even when the client is malicious.

## 3. Notation

The following notation is used:

| Notation | Meaning |
| --- | --- |
| `ASCII(s)` | The ASCII bytes of string `s`, with no terminator. |
| `zero(n)` | A byte string of `n` zero bytes. |
| `random(n)` | `n` bytes generated by a cryptographically secure random-number generator. |
| <code>a &#124;&#124; b</code> | Concatenation of byte strings `a` and `b`. |
| `empty` | The zero-length byte string. |
| `B64(x)` | The RFC 4648 standard-alphabet Base64 string for `x`, with required `=` padding. |
| `Hex(x)` | The lowercase hexadecimal string for `x`, with two characters per byte. |
| `OS2IP-BE(x)` | The unsigned integer represented by `x` in big-endian byte order. |
| `ULID-Encode(x)` | The canonical 26-character ASCII ULID string for a 16-byte value `x`. |
| `ULID-Decode(s)` | The 16-byte value decoded from canonical ASCII ULID text `s`, or an error. |

This document uses:

```text
HKDF-SHA256(salt, IKM, info, L) =
    HKDF-Expand(
        HKDF-Extract(salt, IKM),
        info,
        L
    )
```

The argument order above is normative. `salt` is the HKDF salt and `IKM` is
the input keying material.

HPKE operations use the notation from RFC 9180. In particular:

```text
(enc, context) = SetupBaseS(pkR, info)
context         = SetupBaseR(enc, skR, info)

(enc, context) = SetupPSKS(pkR, info, psk, psk_id)
context         = SetupPSKR(enc, skR, info, psk, psk_id)

ciphertext = context.Seal(aad, plaintext)
plaintext  = context.Open(aad, ciphertext)
secret     = context.Export(exporter_context, length)
```

HPKE record sequence numbers start at zero as specified by RFC 9180.

## 4. Cryptographic suite

Agentknock v1 uses the following fixed HPKE suite:

| Component | RFC 9180 identifier | Selection | Relevant sizes |
| --- | ---: | --- | --- |
| KEM | `0x0020` | DHKEM(X25519, HKDF-SHA256) | 32-byte public, private, and encapsulated keys |
| KDF | `0x0001` | HKDF-SHA256 | `Nh = 32` bytes |
| AEAD | `0x0003` | ChaCha20Poly1305 | 32-byte key, 12-byte nonce, 16-byte tag |

Initial pairing uses HPKE base mode. Every post-pairing exchange and PSK
rotation uses HPKE PSK mode.

All HPKE records and the separately protected response use `aad = empty`. The
full 16-byte ChaCha20Poly1305 authentication tag must be retained.

All random values and HPKE ephemeral key pairs generated in production must
use a cryptographically secure random-number generator.

## 5. Common protocol elements

### 5.1. Protocol version

The protocol version string is:

```text
version = "agentknock-v1"
```

Its ASCII encoding is 13 bytes. Where the protocol version is included in HPKE
`info`, it is padded to exactly 16 bytes:

```text
version_info = ASCII(version) || zero(3)
```

In hexadecimal:

```text
version_info = 6167656e746b6e6f636b2d7631000000
```

No other label in this document has a NUL terminator or NUL padding.

The clear `version` field selects this cryptosystem. The corresponding
`version_info` value cryptographically binds that selection to each HPKE
context.

### 5.2. ULID identifiers

`device_id`, `client_id`, and ordinary `request_id` values are 16-byte ULIDs.
Whenever one of these values is carried as text, its representation is
`ULID-Encode(value)`.

`ULID-Encode` treats its input as one unsigned 128-bit integer in big-endian
byte order and emits the canonical 26-character uppercase Crockford Base32
form, which matches:

```text
[0-7][0-9A-HJKMNP-TV-Z]{25}
```

`ULID-Decode` accepts only that canonical form, reverses this operation, and
rejects every other string. Leading zero bytes are preserved. All cryptographic
operations in this document use the 16-byte decoded value, never the 26-byte
text.

The device generates one stable `device_id` for its device identity. The
client generates one `client_id` for each pairing. Each ordinary paired
exchange uses a fresh `request_id`. A generated ULID uses the current Unix time
in milliseconds in its 48-bit timestamp field and 80 independently generated
CSPRNG bits in its randomness field. A monotonic ULID generator must not be
used: multiple identifiers in one millisecond still receive independent random
fields rather than values obtained by incrementing an earlier ULID. Every
generated ULID must be distinct within the applicable device, pairing, or
request scope.

ULIDs serve both as unique identifiers and as carriers of a claimed creation
time. Once an identifier is bound to a cryptographic context, the timestamp
bits have integrity along with the rest of the identifier. This does not prove
that a malicious client supplied the correct time. Each implementation must
define a ULID freshness policy and must apply it to every previously unseen
`client_id` or `request_id` before accepting that identifier. The policy may
use the timestamp together with local state and local time. Its duration,
clock-skew allowance, and acceptance algorithm are implementation-defined.
Neither the timestamp nor the random field is treated as secret.

For the initial pairing exchange, its `request_id` and the new `client_id` are
the same ULID. The all-zero 16-byte request identifier is reserved exclusively
for PSK rotation and must not be used for an ordinary exchange.

### 5.3. Binary encodings and the v1 envelope encoding

Sections 7 through 9 define each cryptographic message as an abstract tuple of
values. Those tuples are the normative cryptographic messages; tuple notation
does not prescribe concatenation or a binary serialization. For wire
interoperability, this document also records the v1 mapping of those tuples to
UTF-8 JSON objects. The JSON representation does not enter a cryptographic
calculation except through the decoded tuple values it carries.

Envelope mappings are written as JSON-shaped pseudocode. Quoted member names
are literal. An expression on the right-hand side is evaluated and its string
result becomes the JSON string value. For example:

```text
{
  "key": B64(enc)
}
```

means that the JSON member `key` contains the Base64 string obtained by
applying `B64` to the binary value `enc`. Literal JSON appears only where every
value is concrete, such as in the test vectors.

Every member shown in a mapping is a JSON string and is required unless its
defining section states that it may be absent. A decoder rejects a missing
required member or a member of the wrong type. It ignores unknown members: they
do not alter the abstract tuple, cryptographic processing, or trusted state.
Handling of duplicate JSON member names is implementation-defined.

A backward-compatible revision of v1 may define a new optional member. An
older decoder remains compatible by ignoring it. Such a member is not
authenticated or confidential merely because it appears beside a cryptographic
envelope. A value that requires either property must be carried in protected
application plaintext or be bound by a separately versioned cryptographic
construction.

ULID identifiers in these JSON envelopes use `ULID-Encode`. Every other binary
value uses `B64`, including X25519 public keys, HPKE encapsulated keys, random
values, and ciphertexts. Base64 encoders must use the RFC 4648 standard
alphabet and include the required terminal `=` padding. Decoders must accept
that form. They are not required to enforce a canonical textual representation
and may use the standard Base64 decoder provided by their implementation. Any
accepted representation is interpreted only through its decoded bytes.
Interoperability is guaranteed only for the padded standard-alphabet form
produced by `B64`. A decoding failure is an error, and every fixed-size value
must still have the required decoded length.

The pairing `address_id` is encoded as exactly 32 lowercase hexadecimal
characters in byte order.

JSON member order, insignificant whitespace, and the serialized bytes of an
envelope are not cryptographically meaningful. Application plaintext schemas
are outside this document. Application data and transport framing must not be
added as clear fields and then treated as authenticated merely because they are
adjacent to a cryptographic envelope.

### 5.4. Fixed labels

Every label is the exact ASCII byte string shown:

| Purpose | Bytes |
| --- | --- |
| Base derivation salt | `ASCII("agentknock-v1")` |
| Address derivation | `ASCII("agentknock-v1 address")` |
| Pairing commitment | `ASCII("agentknock-v1 commitment")` |
| Client PSK export | `ASCII("agentknock-v1 psk")` |
| SAS derivation prefix | `ASCII("agentknock-v1 sas")` |
| Response secret export | `ASCII("agentknock-v1 response")` |
| Response key derivation | `ASCII("key")` |
| Response nonce derivation | `ASCII("nonce")` |

### 5.5. HPKE context binding

Every HPKE `info` value in this cryptosystem is exactly 48 bytes:

| Context | HPKE `info` |
| --- | --- |
| Initial pairing | <code>version_info &#124;&#124; device_id &#124;&#124; client_id</code> |
| Paired exchange | <code>version_info &#124;&#124; device_id &#124;&#124; request_id</code> |
| PSK rotation | <code>version_info &#124;&#124; device_id &#124;&#124; zero(16)</code> |

All components have fixed lengths, so no separators or length prefixes are
used. Each setup call below repeats its complete `info` expression. Every
PSK-mode setup uses the 16-byte `client_id` as its `psk_id`. The client identity
is therefore bound through `psk_id`; it is not duplicated in `info`.

### 5.6. Record acceptance and redelivery

The surrounding protocol associates each request, response, and completion
with a record slot selected by its message kind and transport-supplied
identifiers. Initial pairing uses `client_id = request_id`; a paired exchange
uses `(client_id, request_id)`.

Transport handling is separate from cryptographic acceptance. Receiving,
storing, discarding, or acknowledging an envelope at the transport layer does
not authenticate it or change trusted endpoint state. The transport may end an
exchange after an invalid envelope or supply another candidate; this document
does not prescribe that behavior.

A receiver applies these rules in order:

1. It looks up retained state before decoding the envelope. If the slot is
   already cryptographically accepted or has a terminal disposition, the
   receiver handles the delivery from retained state. It does not decode,
   authenticate, or compare the later envelope, and it does not repeat an
   application action, response generation, or cryptographic state transition.
2. Otherwise, the receiver performs all applicable decoding, validation, and
   authentication. A protected record is accepted only after it authenticates
   successfully. Failure causes no trusted state transition and exposes no
   plaintext. Section 7 defines the acceptance checks for the clear pairing
   messages.
3. Lookup and acceptance are serialized. Once a record is accepted, any later
   candidate is handled from the resulting retained state.

A sender creates at most one cryptographic record for a slot. Redelivery uses
the exact previously generated cryptographic values and ciphertext bytes; it
does not repeat HPKE setup, sealing, or response encryption under the same
identifiers. Reusing the same JSON serialization is preferable but not
cryptographically required.

An endpoint retains idempotency state for at least as long as its freshness
policy could accept the identifier if it were previously unseen, and longer
while a live operation depends on it. State may be discarded after both
conditions end; subsequent handling then relies on the freshness policy rather
than retained idempotency state.

## 6. Pairing-address derivation

A pairing address consists of one or more nonempty lowercase ASCII words
separated by single hyphens:

```text
[a-z]+(?:-[a-z]+)*
```

No trimming, case conversion, Unicode normalization, or other transformation
is performed. `address_bytes` is the exact ASCII, and therefore UTF-8, encoding
of the accepted address.

The relay-visible address identifier is:

```text
address_id = HKDF-SHA256(
    salt = ASCII("agentknock-v1"),
    IKM  = address_bytes,
    info = ASCII("agentknock-v1 address"),
    L    = 16
)
```

It is serialized as `Hex(address_id)`.

`address_id` allows an observer to test address guesses offline. HKDF-SHA256 is
not a password-hardening function, so the secrecy of the pairing address is
limited by its entropy.

Neither the address nor `address_id` is included in the initial pairing HPKE
`info`, the SAS, or the active pairing state defined by this cryptosystem. The
address is not used by paired exchanges after the initial pairing request has
been routed.

## 7. Initial pairing

### 7.1. Inputs and clear messages

The device has a stable X25519 key pair:

```text
(skD, pkD)
```

`pkD` is the 32-byte X25519 public-key serialization defined by RFC 9180 and
RFC 7748.

Before it sends an initial pairing request, the client must generate:

```text
client_id     = a fresh ULID
request_id    = client_id
client_secret = random(32)
```

The initial `client_id`, which is also the transport-supplied `request_id`,
identifies one logical pairing attempt. The client retains one fixed
`client_secret` for that attempt. It must not reuse `client_id` for another
attempt or replace `client_secret` within this one.

Before receiving the device response, the client commits to its random
contribution:

```text
commitment = HKDF-SHA256(
    salt = ASCII("agentknock-v1"),
    IKM  = client_secret,
    info = ASCII("agentknock-v1 commitment"),
    L    = 32
)
```

This commit-before-peer-contribution pattern parallels the ZRTP HVI commitment
in RFC 6189, §4.4.1.1. Both prevent an active attacker from seeing both honest
contributions before choosing its own contribution to grind for a matching
short authentication string. Agentknock commits only to `client_secret` and
reveals it in the first HPKE record; it does not use the ZRTP message format or
HVI calculation.

The clear initial request is the abstract tuple:

```text
pairing_request = (version, commitment)
```

The v1 JSON envelope mapping is:

```text
{
  "version": version,
  "commitment": B64(commitment)
}
```

The initial request occupies a clear request slot under Section 5.6. An empty
slot is accepted only if `client_id` passes the freshness policy, `version` is
supported, and `commitment` decodes from Base64 to exactly 32 bytes. Once
accepted, later deliveries use its retained state.

For a new accepted pairing attempt, the device generates:

```text
device_random = random(32)
```

and returns the abstract tuple:

```text
pairing_response = (device_id, pkD, device_random)
```

The v1 JSON envelope mapping is:

```text
{
  "device_id": ULID-Encode(device_id),
  "device_key": B64(pkD),
  "device_random": B64(device_random)
}
```

The response is not authenticated at this point. As one serialized, crash-safe
transition, the device accepts the request and durably fixes its `commitment`,
`device_random`, and complete response tuple. Later deliveries return that
tuple and never create another device contribution.

### 7.2. Base-mode exchange and client PSK

`application_plaintext` is the opaque application message sent during pairing.
Its encoding and contents are outside this document.

After validating the response encodings and lengths, the client creates an
HPKE base-mode sender context and seals two records in this fixed order:

```text
(enc, pairing_context) = SetupBaseS(
    pkR  = pkD,
    info = version_info || device_id || client_id
)

secret_ciphertext = pairing_context.Seal(
    aad       = empty,
    plaintext = client_secret
)

application_ciphertext = pairing_context.Seal(
    aad       = empty,
    plaintext = application_plaintext
)

client_psk = pairing_context.Export(
    exporter_context = ASCII("agentknock-v1 psk"),
    length           = 32
)
```

`secret_ciphertext` is HPKE record sequence number 0.
`application_ciphertext` is HPKE record sequence number 1. This base-mode
context has no later completion record.

The client sends the abstract tuple:

```text
pairing_completion = (
    enc,
    secret_ciphertext,
    application_ciphertext
)
```

The v1 JSON envelope mapping is:

```text
{
  "key": B64(enc),
  "secret": B64(secret_ciphertext),
  "ciphertext": B64(application_ciphertext)
}
```

Here and in later envelopes, the JSON member named `key` carries the HPKE
encapsulated key `enc`; it does not carry an AEAD key or the device public key.
The member named `secret` carries `secret_ciphertext`, never the clear
`client_secret`. The member named `ciphertext` carries
`application_ciphertext`, consistently with the other application-message
envelopes in this document.

The pairing completion occupies a completion slot under Section 5.6. It can be
accepted only for a retained attempt awaiting this message and only after the
device completes the following validation. It reconstructs the receiver
context and opens both records in order:

```text
pairing_context = SetupBaseR(
    enc  = enc,
    skR  = skD,
    info = version_info || device_id || client_id
)

client_secret = pairing_context.Open(
    aad        = empty,
    ciphertext = secret_ciphertext
)

application_plaintext = pairing_context.Open(
    aad        = empty,
    ciphertext = application_ciphertext
)
```

The device must reject the pairing completion if either record fails to open
or if `client_secret` is not exactly 32 bytes. After both records have opened,
it derives:

```text
recovered_commitment = HKDF-SHA256(
    salt = ASCII("agentknock-v1"),
    IKM  = client_secret,
    info = ASCII("agentknock-v1 commitment"),
    L    = 32
)
```

The device compares `recovered_commitment` with the commitment retained from
the initial request. The comparison must be constant-time. If they differ, the
device rejects the pairing completion without processing
`application_plaintext`, deriving or storing a client PSK, or presenting a
SAS. Any failure leaves the pairing attempt unchanged.

Only after the commitment matches does the device export:

```text
client_psk = pairing_context.Export(
    exporter_context = ASCII("agentknock-v1 psk"),
    length           = 32
)
```

Only after both records authenticate and the commitment matches may the device
fix this message as the one accepted `pairing_completion` for the attempt and
parse or display `application_plaintext`. Until the user accepts the SAS, that
plaintext remains attacker-controlled, untrusted metadata. It must not cause a
security-sensitive side effect or become trusted durable client metadata. An
implementation may retain it as explicitly untrusted pending state for display
on the SAS confirmation interface. Acceptance of the completion and creation of
the pending binding must be one serialized, crash-safe transition.

### 7.3. Short authentication string

Both endpoints calculate:

```text
sas_bytes = HKDF-SHA256(
    salt = device_random,
    IKM  = client_secret,
    info = ASCII("agentknock-v1 sas")
        || device_id
        || client_id
        || pkD,
    L    = 8
)

sas_integer = OS2IP-BE(sas_bytes) mod 1_000_000_000_000
```

`pkD` is the exact 32-byte public-key value carried in `device_key`.

The integer is rendered as exactly 12 zero-padded decimal digits in three
groups of four:

```text
dddd dddd dddd
```

The user must confirm the full 12-digit SAS through an out-of-band interaction
before either endpoint treats the pairing as authenticated. The initial
base-mode exchange alone does not authenticate the intended device key because
the relay can replace the clear pairing response.

### 7.4. Pairing state and activation

A device-side pairing attempt moves through these states:

| State | Entry and permitted transition | Occupies a pending slot |
| --- | --- | --- |
| Awaiting pairing completion | The initial request and response are fixed. A valid `pairing_completion` advances the attempt. | Yes |
| Awaiting SAS decision | The completion, pending binding, SAS, and untrusted application metadata are fixed. The user may accept or explicitly reject the attempt. | Yes |
| Awaiting activation | The user accepted the SAS. The pending binding may authenticate only the activation exchange. | Yes |
| Active | An authenticated activation request atomically activates the binding and fixes its accepted response. | No |
| Rejected | The user explicitly rejected a non-active attempt. The binding is not activated. | No |

Every transition in this table is serialized and crash-safe.
Malformed, replaced, abandoned, or timed-out client traffic does not change
these states or release a pending slot. The device enforces a small, finite,
implementation-defined limit on the three pending states. When the limit is
reached, it rejects new attempts without altering existing state. State needed
for idempotency remains subject to Section 5.6 after a slot is released.

Activation uses the paired exchange in Section 8. After SAS acceptance, the
client sends the PSK-mode activation request. The device authenticates it with
the pending binding, then atomically activates the binding and fixes the
accepted response before releasing that response. This transition releases the
pending slot.

The client activates only after authenticating the accepted response. It then
sends the authenticated completion from Section 8.3. The completion reports
client-side activation but does not gate or change device activation. The
request, response, and completion plaintext schemas are outside this document.

### 7.5. Client transcript retention

For one `client_id`, the client fixes one `client_secret`, commitment,
`(device_id, pkD, device_random)` response tuple, base-mode sender context,
`enc`, `secret_ciphertext`, `application_ciphertext`, and exported
`client_psk`. The response tuple becomes fixed only after its envelope,
lengths, X25519 input, and HPKE setup validate; later deliveries follow Section
5.6.

The client seals exactly twice in the pairing context, in the order defined in
Section 7.2, and does not repeat setup or sealing. Until the completion has been
safely handed off and the SAS calculated, it retains enough state to reproduce
that completion and SAS. Losing that state requires a new attempt with a fresh
`client_id`.

After safe handoff and SAS calculation, the client may erase the base-mode
context, `client_secret`, `device_random`, `enc`, and both ciphertexts. It
retains the pending binding required for activation.

## 8. Paired request-response-completion exchange

Each paired operation uses one fresh nonzero `request_id` and one HPKE context.
It has one request, at most one terminal response, and at most one completion.
A successful activation exchange in Section 7.4 uses all three, although device
activation does not depend on receiving its completion.

### 8.1. Request

The client creates an HPKE PSK-mode sender context using the active binding, or
using a pending binding solely for the activation exchange in Section 7.4:

```text
(enc, request_context) = SetupPSKS(
    pkR    = pkD,
    info   = version_info || device_id || request_id,
    psk    = client_psk,
    psk_id = client_id
)

request_ciphertext = request_context.Seal(
    aad       = empty,
    plaintext = request_plaintext
)
```

`request_ciphertext` is HPKE record sequence number 0. The abstract request
message is:

```text
paired_request = (version, enc, request_ciphertext, rotation_enc?)
```

`rotation_enc` is absent unless a PSK rotation is pending. Section 9 defines
its construction.

The v1 JSON envelope mapping without rotation is:

```text
{
  "version": version,
  "key": B64(enc),
  "ciphertext": B64(request_ciphertext)
}
```

When `rotation_enc` is present, the v1 JSON envelope mapping is:

```text
{
  "version": version,
  "key": B64(enc),
  "ciphertext": B64(request_ciphertext),
  "rotation_key": B64(rotation_enc)
}
```

The JSON member named `rotation_key` must be absent when `rotation_enc` is
absent.

The device applies Section 5.6. Before accepting a new request, it applies its
freshness policy, selects the binding using `client_id`, checks the exact outer
version, and runs:

```text
request_context = SetupPSKR(
    enc    = enc,
    skR    = skD,
    info   = version_info || device_id || request_id,
    psk    = client_psk,
    psk_id = client_id
)

request_plaintext = request_context.Open(
    aad        = empty,
    ciphertext = request_ciphertext
)
```

A successful open and creation of the operation state form one serialized,
crash-safe transition.

Here `client_psk` is normally the current binding PSK. Section 9.2 defines the
ordered selection of the current PSK, an eligible previous PSK, or a rotation
candidate.

The protocol version, device identity, and request identity are bound through
HPKE `info`. The client identity is bound through `psk_id` and possession of
the corresponding PSK.

### 8.2. Response

The exporter-plus-random-value construction in this section follows the
bidirectional response construction described in HPKE-bis, Section 9.8,
specialized to the fixed Agentknock v1 suite and labels. The complete algorithm
below defines the Agentknock construction.

The response is not an HPKE record in the reverse direction. After the device
successfully opens request sequence number 0, the device invokes the HPKE
exporter once:

```text
response_secret = request_context.Export(
    exporter_context = ASCII("agentknock-v1 response"),
    length           = 32
)
```

Each endpoint must obtain this one 32-byte exporter output and use the two HKDF
derivations below. It must not make separate HPKE exporter calls with the
response key and nonce lengths.

It then generates a public random value whose length is the KDF hash length
`Nh = 32`, and derives a response key and the actual AEAD nonce:

```text
response_random = random(32)
response_salt   = enc || response_random

response_key = HKDF-SHA256(
    salt = response_salt,
    IKM  = response_secret,
    info = ASCII("key"),
    L    = 32
)

response_aead_nonce = HKDF-SHA256(
    salt = response_salt,
    IKM  = response_secret,
    info = ASCII("nonce"),
    L    = 12
)

response_ciphertext = ChaCha20Poly1305.Seal(
    key       = response_key,
    nonce     = response_aead_nonce,
    aad       = empty,
    plaintext = response_plaintext
)
```

`response_ciphertext` is the encrypted bytes followed by the full 16-byte
authentication tag, as defined by RFC 8439.

The abstract response message is:

```text
paired_response = (response_random, response_ciphertext)
```

The v1 JSON envelope mapping is:

```text
{
  "nonce": B64(response_random),
  "ciphertext": B64(response_ciphertext)
}
```

The field named `nonce` contains `response_random`. It is public HKDF input;
it is not the ChaCha20Poly1305 nonce. Its decoded length must be exactly 32
bytes.

The client applies Section 5.6. Before accepting a response, it derives the
same `response_secret`, `response_key`, and `response_aead_nonce` and attempts
to open the ciphertext. Opening a response does not advance the HPKE record
sequence.

For a given request, the device must create at most one terminal
`response_plaintext` and one `paired_response`. Before releasing the first
copy, it must durably fix `response_random` and `response_ciphertext` as request
state. Those values are sufficient to reproduce the exact encrypted response;
this cryptosystem does not require durable retention of `response_plaintext`.
Application state may separately retain a terminal result when needed. A later
delivery returns the fixed encrypted values under Section 5.6. The device must
not generate a different `paired_response` for the same request context,
including after a crash.

### 8.3. Completion

After sealing the request, the client may seal one completion in the original
sender context:

```text
completion_ciphertext = request_context.Seal(
    aad       = empty,
    plaintext = completion_plaintext
)
```

`completion_ciphertext` is HPKE record sequence number 1. The abstract
completion message is:

```text
paired_completion = (completion_ciphertext)
```

The v1 JSON envelope mapping is:

```text
{
  "ciphertext": B64(completion_ciphertext)
}
```

The completion does not repeat `version`, `enc`, `device_id`, `client_id`, or
`request_id`; they are supplied by the original request and its context. In the
v1 JSON encoding, this means that it contains no `version` or `key` member.

The device applies Section 5.6. Before accepting a completion, it reconstructs
the receiver context from the accepted request, opens request sequence number
0, and then opens the completion as sequence number 1. Acceptance and any state
transition caused by the completion plaintext form one serialized, crash-safe
transition. Response derivation and encryption do not consume an HPKE record
sequence number.

A completion may report an application-level abort even if no response was
obtained. Cryptographically, it can be generated only after the request was
sealed. Its application meaning is outside this document.

### 8.4. Message-order and uniqueness requirements

A new operation uses a fresh nonzero `request_id` and a fresh HPKE sender
context. The client seals the request exactly once at sequence number 0. If the
operation has a completion, it seals that record exactly once at sequence
number 1 and only after the request. Response derivation does not consume an
HPKE sequence number.

If the client loses the sender context before an exchange finishes, it abandons
that exchange and uses a new `request_id`; the request envelope alone cannot
reconstruct a valid completion. Record acceptance, redelivery, and state
retention follow Section 5.6.

## 9. PSK rotation

PSK rotation creates a successor PSK without a dedicated application message.
It uses a normal PSK-mode HPKE context only for export and carries that
context's encapsulated key in later requests. It does not use the RFC 9180
Export-Only AEAD identifier.

### 9.1. Client rotation

The client may rotate only an active binding and only when no rotation is
already pending. Let the current PSK be `old_psk`. The client performs a fresh
HPKE PSK-mode sender setup:

```text
(rotation_enc, rotation_context) = SetupPSKS(
    pkR    = pkD,
    info   = version_info || device_id || zero(16),
    psk    = old_psk,
    psk_id = client_id
)

new_psk = rotation_context.Export(
    exporter_context = ASCII("agentknock-v1 psk"),
    length           = 32
)
```

The client must not seal a plaintext in `rotation_context`.

The abstract optional request value is `rotation_enc`. The v1 JSON envelope
encodes it as `B64(rotation_enc)` in the member named `rotation_key`. Despite
that JSON member name, the value is an HPKE encapsulated key and is not
`new_psk`.

As one serialized, crash-safe state transition, the client must replace
`old_psk` with `new_psk` and retain the pending `rotation_enc`. After this
transition, every new paired request uses `new_psk` and includes the same
`rotation_enc` until confirmation. Consequently, every v1 JSON encoding of
such a request contains the same `rotation_key` value. The client must not have
more than one unconfirmed rotation.

### 9.2. Device rotation processing

Rotation processing applies only to an active binding. When a pending binding
is used for the activation exchange, the device ignores `rotation_enc` and
attempts to open the request only with the pending `client_psk`. It must not
derive or adopt a rotation candidate for that binding.

For a candidate in an empty request slot, the device processes rotation in this
order:

1. It first tries to open the ordinary request using its current stored PSK.
   If this succeeds, it ignores the optional rotation value.
2. If step 1 fails and the immediately previous PSK is still within the bounded
   overlap described below, the device tries that PSK. If this succeeds, it
   authenticates an ordinary request from that older generation and ignores
   the optional rotation value. An older PSK must not authorize a rotation or
   become current again.
3. If the ordinary opens fail and `rotation_enc` is absent, the device rejects
   the request. Otherwise, it reconstructs a normal PSK-mode context used only
   for export:

   ```text
   rotation_context = SetupPSKR(
       enc    = rotation_enc,
       skR    = skD,
       info   = version_info || device_id || zero(16),
       psk    = current_psk,
       psk_id = client_id
   )

   candidate_psk = rotation_context.Export(
       exporter_context = ASCII("agentknock-v1 psk"),
       length           = 32
   )
   ```

4. It tries to open the ordinary request using `candidate_psk` in the normal
   request context.
5. It accepts the rotation only if that ordinary request authenticates
   successfully. A bare, malformed, or substituted `rotation_enc` must not
   change device state.
6. Acceptance of the request and replacement of the current PSK with
   `candidate_psk` must be one serialized, crash-safe transition and must occur
   before the terminal response is released.

If the device already adopted `new_psk`, step 1 succeeds and the still-present
`rotation_enc` is harmless. This permits recovery from a lost rotation
confirmation.

`rotation_enc` is not direct AEAD associated data. Its derivation is instead
authenticated indirectly: the device commits `candidate_psk` only after the
ordinary request opens under that candidate. Removing or replacing the value
can make a request fail, but cannot cause adoption of an attacker-chosen PSK.

The device must retain the exact PSK generation or reconstructed HPKE receiver
state for every request it has accepted until that request no longer needs a
response or completion. A later rotation must not change the context used by an
already accepted request.

The device retains the immediately previous PSK for a bounded,
implementation-defined overlap so step 2 can accept delayed ordinary requests.
The previous PSK cannot authorize rotation, become current, or extend its
overlap through use. This necessarily preserves its authority for the same
period; cryptography cannot distinguish a delayed request from a newly created
one.

Only one previous generation is retained. Its overlap ends at the fixed
deadline or upon a later rotation, whichever comes first.

The trigger and application semantics for invalidating or removing an active
binding are outside this document. Rotation overlap exists only while the
binding remains active: after invalidation, neither the current nor previous
PSK can authenticate a new request. Previously accepted records remain governed
by their retained exchange and idempotency state, and invalidation cannot
retract ciphertext already released. Whether an accepted but unresolved
operation produces a response is application policy.

### 9.3. Rotation confirmation

Successfully opening an authenticated response to a request that carried the
pending `rotation_enc` confirms that the device derived the same `new_psk`.
The client then removes that pending `rotation_enc`, but only if it still
matches the value carried by that request.

The application result inside the response does not affect cryptographic
confirmation. Relay delivery, a clear error, or an undecryptable response is
not confirmation.

Each endpoint should erase a retired PSK when practical, but only after no live
request state or permitted overlap depends on it. A client may erase the raw
`old_psk` after its atomic transition if every live request retains a
self-contained sender context. Rotation scheduling and the overlap duration are
product policy, not cryptographic constants.

## 10. Cryptographic state

The cryptosystem requires the following state:

| State | Required contents |
| --- | --- |
| Device identity | Stable `device_id`, secret `skD`, and matching `pkD` |
| Device pairing attempt | Its Section 7.4 state and the fixed values needed to return the pairing response, validate the completion, calculate the SAS, and activate or reject the binding |
| Device binding | `client_id`, current `client_psk`, status, and any previous PSK with its overlap deadline |
| Client pairing attempt | The live transcript needed through safe handoff and SAS calculation, followed by the pending binding needed for activation |
| Client binding | `device_id`, `pkD`, `client_id`, current `client_psk`, status, and any pending `rotation_enc` |
| Client paired exchange | `request_id`, fixed request and sender context, accepted response, and any fixed completion |
| Device paired exchange | `request_id`, accepted request and receiver context, its PSK generation, processing state, any fixed response, and accepted completion |
| Idempotency | Accepted identifiers and enough disposition or response state to handle redelivery under Section 5.6 |

Secret keys and PSKs require confidentiality and integrity. Public keys,
identifiers, and pending-rotation state require integrity. Transitions described
as serialized and crash-safe must not expose partially updated state after
concurrency or a crash. This does not prescribe a storage format or platform
mechanism.

Pending-slot accounting and idempotency retention are separate. Explicit
rejection or successful device activation releases a pairing's pending slot,
but Section 5.6 can require its idempotency state to remain longer.

Request-local contexts, response secrets, derived response keys and nonces,
retired PSKs, and protected plaintext should be erased when no live request or
allowed rotation overlap requires them. An endpoint must not reuse an abandoned
request context for a new identifier or a new application operation.

## 11. Validation and failure handling

An implementation must fail closed on any of the following:

- an unsupported protocol version;
- a malformed or noncanonical identifier;
- a Base64 or hexadecimal decoding failure;
- a decoded identifier, random value, key, encapsulation, or nonce of the
  wrong length;
- HPKE setup, open, seal, or export failure;
- ChaCha20Poly1305 authentication failure;
- a record presented in the wrong sequence before cryptographic acceptance.

These checks apply before cryptographic acceptance. Later transport delivery
for an accepted slot follows Section 5.6 without validating the new envelope.

Every X25519 public key and encapsulated key must decode to exactly 32 bytes.
When processing an X25519 input u-coordinate, the implementation follows RFC
7748, Section 5: it masks the most significant bit of the final byte, accepts
non-canonical values, and processes the resulting integer modulo
`2^255 - 19`. It must not reject an input merely because the encoding is
non-canonical. If an X25519 operation used by DHKEM produces an all-zero shared
secret, the implementation must detect that result without leaking secret
information and abort, as required for X25519 input validation by HPKE-bis,
Section 7.1.4.

When Section 9.2 ignores `rotation_key`, the device does not decode or validate
that member. If rotation fallback is needed, it must decode to an exactly
32-byte HPKE encapsulated key.

Unauthenticated data must not be interpreted as an authenticated endpoint
decision. In particular, a clear error fabricated by the relay is not proof
that the device rejected a request and must not, by itself, authorize release
of protected data, activate a pairing, confirm a rotation, or otherwise change
trusted cryptographic state.

On authentication failure, an implementation must not expose the failed
plaintext or use any partially derived application value. Error reporting and
recovery guidance are outside this document.

## 12. Security considerations

### 12.1. Properties after verified pairing

Subject to the assumptions of HPKE, X25519, HKDF-SHA256, ChaCha20Poly1305, and
secure endpoint state:

- A paired request is confidential to the holder of `skD` and is
  authenticated as coming from a holder of `client_psk` for `client_id`.
- A response is confidential and authenticated to the client through the
  exporter secret of the authenticated request context. Against the relay, this
  proves possession of that context, not which endpoint performed the
  encryption.
- A completion is confidential and authenticated as HPKE record sequence
  number 1 in the original request context.
- `version`, `device_id`, and `request_id` are bound through HPKE `info`, while
  `client_id` is bound through `psk_id`.
- Modification or cross-context substitution of a protected record causes
  authentication failure and no trusted state transition. After acceptance,
  later envelopes for that slot are ignored and cannot replace the accepted
  record or repeat its effects.

HPKE PSK mode proves possession of a shared secret; it does not create a
digital signature or non-repudiable client identity. Either endpoint that
possesses the relevant secrets can construct protocol messages consistent with
its role. In particular, responses and completions are not signatures or
third-party proof of which endpoint generated them.

### 12.2. Initial pairing and SAS

The initial request and device response are clear and unauthenticated. A relay
can replace `device_id`, `pkD`, or `device_random`, causing the client to
encrypt both pairing records to an attacker-selected key. The attacker can open
both `client_secret` and `application_plaintext`, and can supply different
application metadata on its separate leg toward the real device, before a
later SAS mismatch is detected. SAS verification does not retroactively give
these records confidentiality, and application metadata remains untrusted
before SAS acceptance. HPKE base mode alone does not authenticate the intended
device; SAS confirmation is mandatory.

The client commits to `client_secret` before learning the device contribution,
and the device fixes its response before learning `client_secret`. Commitment
verification binds the revealed secret to the initial request; the SAS binds
both random contributions, both identifiers, and `pkD`. A relay impersonating
the device must fix its substituted key and random value before the completion
reveals `client_secret`. The commitment then prevents it from presenting a
different client contribution to the real device. It therefore cannot choose
either substituted contribution after learning the corresponding honest
contribution.

For full confirmation of the 12-digit SAS, one independent incorrect value
matches with probability approximately `10^-12` (about 39.9 bits); the modulo
bias is negligible. Partial confirmation or repeated attempts reduce this
security. With at most `n` pending attempts, the relay's best chance from those
candidates is at most approximately `n * 10^-12`. The finite limit in Section
7.4 bounds this amplification but not denial of service.

The address-derived values do not replace SAS verification. A low-entropy or
public pairing address can be recovered by offline enumeration. Even a
high-entropy address does not make the clear device response authenticated to
the client.

### 12.3. Replay and state rollback

Authenticated encryption does not invalidate a ciphertext replay. Section 5.6
maps each slot to one operation and handles later envelopes from retained state.
A modified protected record fails authentication and causes no trusted state
transition.

Senders must still generate only one record per slot. Cloned or rolled-back
HPKE state could otherwise seal different plaintexts at one sequence number. A
fixed response must not be replaced; changing its plaintext while retaining
`response_random` would reuse the derived key and nonce. Sections 7.5, 8.2, and
8.4 prohibit these cases.

Rollback or cloning of endpoint state can fork a PSK lineage. Atomic writes
prevent partial local transitions but cannot distinguish two independently
running copies of the same valid state. A holder of a copied current PSK can
impersonate the client and race a competing rotation. PSK rotation is routine
key evolution, not a mechanism for recovering from a known compromise.

### 12.4. Key compromise and forward secrecy

Compromise of the current `client_psk` permits future client impersonation and
rotation attempts until the device state changes. The PSK alone does not
decrypt previously recorded HPKE exchanges without the corresponding device
private key or sender ephemeral state.

Compromise of `skD` has a wider retrospective effect. If an attacker recorded
the initial base-mode pairing exchange, `skD` lets it reconstruct that context
and its exported `client_psk`. Recorded rotation encapsulations then reveal the
successor PSKs in sequence, allowing recorded paired traffic to be opened.
Agentknock v1 therefore does not provide forward secrecy against later
compromise of the long-term device private key when the pairing transcript was
recorded.

Agentknock v1 is not post-quantum secure because its fixed HPKE suite uses
X25519. The construction can also be instantiated with a post-quantum or hybrid
HPKE suite by substituting that suite and adjusting every algorithm-dependent
length. Such an instantiation is a separate protocol version, not an extension
or negotiated variant of `agentknock-v1`.

A malicious client can exercise its own binding and disclose its own secrets as
described in Section 2, but that does not relax the device-side safety
requirements. Compromise of the device, weak random-number generation, and
side-channel leakage are outside the protection of this cryptosystem.

### 12.5. Relay visibility and availability

The relay can observe at least the values carried outside encryption,
including routing identifiers, `version`, the pairing commitment, `device_id`,
`pkD`, `device_random`, HPKE encapsulated keys, whether a rotation is pending,
the public response random value, ciphertext lengths, timing, and traffic
relationships. ULID timestamps are also visible wherever the identifiers are
visible.

The cryptosystem does not hide message length or traffic patterns. Padding is
not defined. The relay can suppress all traffic or fabricate unauthenticated
errors, so no availability guarantee is possible.

## 13. Test vectors

Unless stated otherwise, every byte string in this section is hexadecimal.
Production implementations must generate fresh randomness; the `ikmE` values
below are deterministic inputs to the DHKEM `DeriveKeyPair` procedure and are
only for reproducible tests.

`client_secret` and every `ikmE` value below are independent protocol inputs and
must be generated independently. None is derived from another.

### 13.1. Pairing address

```text
address = yup-its-free

address_id =
  9e6f33bf47382846903dffa0962ea313
```

### 13.2. Common pairing inputs and SAS

```text
ULID-Encode(device_id) = 01K2ENXDTW1P3XAR4J7V7C9D0H
device_id =
  01989d5eb75c0d87d560923ecec4b411

ULID-Encode(client_id) = 01K2EP16NWNAGJYF8J1Q2V6P3X
client_id =
  01989d609abcaaa12f3d120dc5b3587d

device private key =
  42424242424242424242424242424242
  42424242424242424242424242424242

pkD =
  132c442be010fbd57e72603328aa76e7
  1fccc1503aae219327d14d9c9993f472

client_secret =
  606162636465666768696a6b6c6d6e6f
  707172737475767778797a7b7c7d7e7f

commitment =
  8d455348112298bcfa39d7d7000e2ac5
  e9a6e211f2cf3739c8e8f565dcc7b2ae

B64(commitment) =
  jUVTSBEimLz6OdfXAA4qxemm4hHyzzc5yOj1ZdzHsq4=

device_random =
  a0a1a2a3a4a5a6a7a8a9aaabacadaeaf
  b0b1b2b3b4b5b6b7b8b9babbbcbdbebf

SAS HKDF info =
  6167656e746b6e6f636b2d7631207361
  7301989d5eb75c0d87d560923ecec4b4
  1101989d609abcaaa12f3d120dc5b358
  7d132c442be010fbd57e72603328aa76
  e71fccc1503aae219327d14d9c9993f4
  72

sas_bytes = f8ec5b7b6afd9de4
sas_integer = 1543953892
displayed SAS = 0015 4395 3892
```

The v1 JSON envelope encodings of `pairing_request` and `pairing_response`
are:

```json
{
  "version": "agentknock-v1",
  "commitment": "jUVTSBEimLz6OdfXAA4qxemm4hHyzzc5yOj1ZdzHsq4="
}
```

```json
{
  "device_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "device_key": "EyxEK+AQ+9V+cmAzKKp25x/MwVA6riGTJ9FNnJmT9HI=",
  "device_random": "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8="
}
```

### 13.3. Initial pairing and PSK export

```text
version_info =
  6167656e746b6e6f636b2d7631000000

pairing HPKE info = version_info || device_id || client_id =
  6167656e746b6e6f636b2d7631000000
  01989d5eb75c0d87d560923ecec4b411
  01989d609abcaaa12f3d120dc5b3587d

ikmE =
  000102030405060708090a0b0c0d0e0f
  101112131415161718191a1b1c1d1e1f

enc =
  b1f1b840de7a3241b02748cf9b05b74d
  c8c5e8451298738817bd76aa8ebe8c2b

secret_ciphertext =
  1fc4998009b2f274e37a7805cebc7368
  af8cc1d37f3a08458224071eeb96da80
  7a97f1c9a67a4b18ad924f0182d182b7

application_plaintext, as UTF-8 = application
application_plaintext = 6170706c69636174696f6e

application_ciphertext =
  0c0c8a15fd6ec95a39002878958e409c
  e5a9c765f1ebc774290d45

client_psk =
  b208e67b262c76f1bffb13acdabf3467
  4a1e41deb1bb4fff9dbdb8a31e218bd8
```

The string `application` is a test-only opaque application plaintext. It does
not define an application message schema.

The v1 JSON envelope encoding of `pairing_completion` is:

```json
{
  "key": "sfG4QN56MkGwJ0jPmwW3TcjF6EUSmHOIF712qo6+jCs=",
  "secret": "H8SZgAmy8nTjengFzrxzaK+MwdN/OghFgiQHHuuW2oB6l/HJpnpLGK2STwGC0YK3",
  "ciphertext": "DAyKFf1uyVo5ACh4lY5AnOWpx2Xx68d0KQ1F"
}
```

### 13.4. Paired request, response, and completion

This vector uses `client_psk` from Section 13.3.

```text
ULID-Encode(request_id) = 01ARZ3NDEKTSV4RRFFQ69G5FAX
request_id =
  01563e3ab5d3d6764c61efb99302bd5d

paired-exchange HPKE info = version_info || device_id || request_id =
  6167656e746b6e6f636b2d7631000000
  01989d5eb75c0d87d560923ecec4b411
  01563e3ab5d3d6764c61efb99302bd5d

psk_id =
  01989d609abcaaa12f3d120dc5b3587d

ikmE =
  202122232425262728292a2b2c2d2e2f
  303132333435363738393a3b3c3d3e3f

request_plaintext, as UTF-8 = request
request_plaintext = 72657175657374

enc =
  693658254630f73ad8da78fb331bf976
  cd42f90e0e9c9e83f40c51072a6f7417

request_ciphertext =
  2ea6b00a2a368e88fa4e7c8a9812871d
  762e1ca79690e7

response_secret =
  7c74ea99133595bf8bde52676eddba3b
  adb86495e024ccdab714cceba5d69791

response_random =
  c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
  d0d1d2d3d4d5d6d7d8d9dadbdcdddedf

response_salt = enc || response_random =
  693658254630f73ad8da78fb331bf976
  cd42f90e0e9c9e83f40c51072a6f7417
  c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
  d0d1d2d3d4d5d6d7d8d9dadbdcdddedf

response_key =
  ba62e9d298f8cd6440991d2e728b8599
  98d31d4f3102b215b86420ac35c32059

response_aead_nonce =
  2f514dfcfff4606cfcefb725

response_plaintext, as UTF-8 = response
response_plaintext = 726573706f6e7365

response_ciphertext =
  e3ad78eea1e4e69741089c0ecffa88b8
  a820547ae46b2029

completion_plaintext, as UTF-8 = completion
completion_plaintext = 636f6d706c6574696f6e

completion_ciphertext =
  d04b4a1ccbb6b9330f8c6a1a392ddb4b
  bf4b9d92ffae0dc1b08a
```

The plaintexts `request`, `response`, and `completion` are test-only opaque
values; they are not application methods.

The v1 JSON envelope encodings of `paired_request`, `paired_response`, and
`paired_completion` are:

```json
{
  "version": "agentknock-v1",
  "key": "aTZYJUYw9zrY2nj7Mxv5ds1C+Q4OnJ6D9AxRBypvdBc=",
  "ciphertext": "LqawCio2joj6TnyKmBKHHXYuHKeWkOc="
}
```

```json
{
  "nonce": "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t8=",
  "ciphertext": "46147qHk5pdBCJwOz/qIuKggVHrkayAp"
}
```

```json
{
  "ciphertext": "0EtKHMu2uTMPjGoaOS3bS79LnZL/rg3BsIo="
}
```

### 13.5. PSK rotation

This vector rotates `client_psk` from Section 13.3.

```text
rotation HPKE info = version_info || device_id || zero(16) =
  6167656e746b6e6f636b2d7631000000
  01989d5eb75c0d87d560923ecec4b411
  00000000000000000000000000000000

psk_id =
  01989d609abcaaa12f3d120dc5b3587d

ikmE =
  404142434445464748494a4b4c4d4e4f
  505152535455565758595a5b5c5d5e5f

rotation_enc =
  b259f6ee92dcba0111850b13b3f6dccc
  827726f9b08235ab62922b6b3f3f2a19

B64(rotation_enc) =
  sln27pLcugERhQsTs/bczIJ3JvmwgjWrYpIraz8/Khk=

new_psk =
  b0ca03f5aea63fe0810516db0bd966c1
  e5ae73744d3bbfdb3a9139571b1ddb9b
```

## 14. References

- [RFC 4648: The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
- [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 6189, §4.4.1.1: ZRTP Hash Commitment in Diffie-Hellman Mode](https://www.rfc-editor.org/rfc/rfc6189.html#section-4.4.1.1)
- [RFC 7748: Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748.html)
- [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439.html)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [HPKE-bis: Hybrid Public Key Encryption, draft-ietf-hpke-hpke-04 (work in progress)](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-hpke-04)
- [ULID canonical specification, revision `d0c7170`](https://github.com/ulid/spec/blob/d0c7170df4517939e70129b4d6462cc162f2d5bf/README.md)
