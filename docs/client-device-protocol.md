# Agentknock v1 client-device protocol

This document defines the end-to-end application messages exchanged by an
Agentknock client and device. It defines their JSON representation and their
application meaning. The relay carries these messages as opaque values.

The [Agentknock v1 cryptosystem](cryptosystem.md) defines how the endpoints
protect the messages. The [Agentknock v1 client-relay
protocol](client-relay-protocol.md) defines how a client transfers the
resulting envelopes through a relay. Neither adjacent protocol changes the
application meaning defined here.

## Roles and exchanges

The term **device** identifies the protocol endpoint that owns the device
identity, controls secrets, and decides how to answer client requests. It does
not imply a physical device or a particular user interface. A device can be a
mobile application, a local service, or a cloud service.

The client initiates every exchange. The device accepts, rejects, or answers
the request. An exchange has the following logical messages:

1. The client sends one request.
2. The device can send one terminal response.
3. The client can send one completion.

The initial pairing exchange is different: its request and response are clear,
and its completion contains the HPKE base-mode records that establish the
pairing. All later exchanges use the paired request, response, and completion
construction.

Transport acknowledgement is not an application response. A relay
acknowledgement means only that the relay accepted responsibility for a
message. A response in this document comes from the device, although an
unprotected error report can be forged by the relay.

## JSON representation

Each message is a UTF-8 JSON object. Member names and string values are
case-sensitive.

A sender includes every required member and omits an optional member when it
has no value. A receiver rejects a missing required member or a member of the
wrong JSON type. A receiver ignores unknown members.

JSON object member order and insignificant whitespace have no meaning. This
protocol does not require a canonical JSON serialization. Handling of
duplicate member names is implementation-defined.

### Binary values

Binary values use the standard Base64 alphabet from RFC 4648. Senders include
terminal `=` padding. Receivers must accept that representation but can use a
decoder that also accepts noncanonical forms. Every fixed-size value must have
the decoded length required by the cryptosystem.

ULIDs use their canonical 26-character uppercase Crockford Base32 form:

```text
[0-7][0-9A-HJKMNP-TV-Z]{25}
```

The `address_id` path value uses exactly 32 lowercase hexadecimal characters.

## Cryptographic envelopes

The JSON objects in this section serialize the abstract tuples defined by the
cryptosystem. The relay uses each complete object as the `payload` value of a
client-relay `message` frame.

### Initial pairing request

The clear initial pairing request serializes
`(version, commitment)`:

```json
{
  "version": "agentknock-v1",
  "commitment": "base64 commitment"
}
```

The decoded commitment is 32 bytes.

### Initial pairing response

The clear initial pairing response serializes
`(device_id, pkD, device_random)`:

```json
{
  "device_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "device_key": "base64 X25519 public key",
  "device_random": "base64 device random"
}
```

The decoded device key and device random are each 32 bytes. This response is
not authenticated until the complete pairing short authentication string
(SAS) is confirmed through a trusted out-of-band interaction.

### Initial pairing completion

The initial pairing completion serializes
`(enc, secret_ciphertext, application_ciphertext)`:

```json
{
  "key": "base64 HPKE encapsulated key",
  "secret": "base64 client-secret ciphertext",
  "ciphertext": "base64 application ciphertext"
}
```

The `secret` member protects only the 32-byte client secret. The `ciphertext`
member protects the pairing metadata defined in [Initial pairing
metadata](#initial-pairing-metadata).

### Paired request

A paired request serializes
`(version, enc, request_ciphertext, rotation_enc?)`:

```json
{
  "version": "agentknock-v1",
  "key": "base64 HPKE encapsulated key",
  "ciphertext": "base64 request ciphertext"
}
```

When a client pre-shared key (PSK) rotation is pending, the client adds the
following member:

```json
{
  "version": "agentknock-v1",
  "key": "base64 HPKE encapsulated key",
  "ciphertext": "base64 request ciphertext",
  "rotation_key": "base64 rotation encapsulated key"
}
```

Despite its name, `rotation_key` contains the HPKE encapsulated key
`rotation_enc`, not the successor PSK. The client repeats the same value in
each new request until it authenticates a response that used the successor
PSK.

### Paired response

A paired response serializes `(response_random, response_ciphertext)`:

```json
{
  "nonce": "base64 response random",
  "ciphertext": "base64 response ciphertext"
}
```

The `nonce` member contains the 32-byte public response random. It does not
contain the 12-byte ChaCha20Poly1305 nonce derived by the cryptosystem.

### Paired completion

A paired completion serializes `(completion_ciphertext)`:

```json
{
  "ciphertext": "base64 completion ciphertext"
}
```

The completion uses the original request context. It does not repeat the
protocol version or encapsulated key.

## Client software information

Every protected plaintext sent by a client contains `app_info` and
`lib_info` members:

```json
{
  "app_info": {
    "name": "agentknock",
    "version": "0.1.0"
  },
  "lib_info": {
    "name": "agentknock",
    "version": "0.1.0"
  }
}
```

`app_info` identifies the application that initiated the operation.
`lib_info` identifies the Agentknock protocol library embedded by that
application. Each `name` and `version` value is an opaque string. These values
do not replace the outer `agentknock-v1` protocol selector.

The examples in the following sections omit these two members for brevity.
They remain required in every protected client request and completion,
including the protected metadata in initial pairing. Device responses do not
contain them.

## Initial pairing

Initial pairing creates a pending cryptographic relationship. The pairing
request has no application `method`; its clear shape distinguishes it from
paired requests.

The client performs the following sequence:

1. Generate a fresh `client_id`, client token, and client secret.
2. Derive the address ID and commitment as defined by the cryptosystem.
3. Send the clear initial request with `client_id = request_id`.
4. Validate the clear response and construct the base-mode completion.
5. Store the resulting pairing as pending.
6. Send the base-mode completion. If delivery fails, remove the pending
   pairing.
7. Present the complete 12-digit SAS for confirmation through a trusted
   out-of-band interaction.

If the exchange is abandoned before the SAS is presented, the client discards
its in-memory transcript and starts any later attempt with fresh values.

### Initial pairing metadata

The application plaintext in the pairing completion has this form:

```json
{
  "app_info": {
    "name": "agentknock",
    "version": "0.1.0"
  },
  "lib_info": {
    "name": "agentknock",
    "version": "0.1.0"
  },
  "platform": "linux",
  "architecture": "x86_64",
  "hostname": "workstation",
  "machine_id": "host identifier",
  "os_version": "Example Linux 1"
}
```

`platform` and `architecture` are required client-reported strings. The
`hostname`, `machine_id`, and `os_version` members are optional. All metadata
is unauthenticated until the full SAS is confirmed and the pairing is
accepted.

### Pairing activation

After the full SAS is confirmed and the device accepts the pairing, the client
activates its pending pairing through an ordinary paired exchange. Only this
method is valid for a pending pairing.

The request plaintext is:

```json
{
  "method": "PairingFinish"
}
```

The device responds with one of the following plaintexts:

```json
{
  "result": "ACCEPTED"
}
```

```json
{
  "result": "REJECTED"
}
```

An authenticated `ACCEPTED` response guarantees that the device activated the
pairing before releasing that response. Repeated delivery of the same request
returns the same result. The client marks its local pairing active only after
it authenticates `ACCEPTED` and durably records the active state.

After local activation, the client sends this completion plaintext:

```json
{
  "result": "ACCEPTED"
}
```

The completion tells the device that the client activated its local pairing.
It does not gate device activation. A `REJECTED` response leaves the client
pairing pending and has no completion.

## Paired operations

An active client selects an operation with the protected request's `method`
member. Version 1 defines the following methods:

| Method | Purpose |
| --- | --- |
| `Invocation` | Prepare one or more secrets for a command invocation. |
| `GitSign` | Request a Git SSH signature for an existing invocation. |
| `SecretList` | List secret metadata without secret values. |
| `SecretUpload` | Deliver a secret proposal for separate acceptance. |
| `PairingRemove` | Remove the relationship between the client and device. |

The device returns one terminal response for an accepted request. The client
then sends the method-specific completion where defined. Repeated deliveries
of an accepted request, response, or completion do not create another
application operation or another terminal result.

## Secret representation

A secret has one name and one type. Secret names share one flat namespace on
the device. Version 1 defines the `environment` and `ssh` types.

Environment-secret metadata represents environment variables as a list of
names:

```json
{
  "description": "GitHub API access",
  "type": "environment",
  "variables": ["GH_TOKEN"]
}
```

The optional `description` member contains human-readable text. The
`variables` array contains no values. A sender emits each name at most once.

Environment-secret contents represent environment variables as a map:

```json
{
  "description": "GitHub API access",
  "type": "environment",
  "variables": {
    "GH_TOKEN": {
      "value": "secret value"
    }
  }
}
```

The map key is the environment variable name. The `value` string is its exact
UTF-8 value.

SSH-secret metadata and invocation contents contain only the public key:

```json
{
  "description": "Release signing key",
  "type": "ssh",
  "public_key": "ssh-ed25519 AAAA..."
}
```

The `public_key` member contains one public key in OpenSSH format. The private
key remains on the device.

## Invocation

The `Invocation` method asks the device to prepare a set of named secrets for
one command invocation. Environment secrets can release values in the
response. SSH secrets release only their public keys; later `GitSign`
exchanges request individual signatures.

### Invocation request

An `exec` request has this plaintext shape:

```json
{
  "method": "Invocation",
  "secrets": ["cloudflare", "github"],
  "reason": "Publish the release",
  "operation": {
    "type": "exec",
    "command": "wrangler",
    "arguments": ["deploy"],
    "working_directory": "/work/project",
    "executable_path": "/usr/bin/wrangler",
    "executable_hash": "base64 SHA-256 digest",
    "executable_mode": "BINARY",
    "stdin": "TERMINAL",
    "stdout": "TERMINAL",
    "stderr": "TERMINAL"
  },
  "launcher_chain": ["/usr/bin/bash"],
  "invocation_token": "base64 invocation token"
}
```

The `secrets` array is nonempty, sorted lexicographically, and contains no
duplicates or empty names. The optional `reason` is untrusted text supplied by
the client. The `invocation_token` is a fresh 32-byte random value. The device
associates it with the request identifier and selected secrets for later
operations belonging to this invocation.

For an `exec` operation:

- `command` is the original executable name or path supplied by the caller.
- `arguments` contains each argument after argument zero as a separate string.
- `working_directory` is the directory captured before the request.
- `executable_path` is the resolved path reported by the client.
- `executable_hash` is optional. When present, it is the Base64 encoding of a
  32-byte SHA-256 digest of the selected top-level executable.
- `executable_mode` is `BINARY` or `SCRIPT`.
- `stdin`, `stdout`, and `stderr` are `TERMINAL`, `NULL_DEVICE`, `PIPE`,
  `SOCKET`, `REGULAR_FILE`, or `UNKNOWN`.
- `launcher_chain` contains up to four client-reported executable paths, from
  the oldest reported ancestor to the direct launcher of Agentknock.

The metadata is approval context, not remote attestation. The device treats it
as client-supplied data.

### Approved invocation response

An approval response contains the requested secret contents:

```json
{
  "result": "APPROVED",
  "secrets": {
    "cloudflare": {
      "type": "environment",
      "variables": {
        "CLOUDFLARE_API_TOKEN": {
          "value": "secret value"
        }
      }
    },
    "github": {
      "description": "GitHub API access",
      "type": "environment",
      "variables": {
        "GH_TOKEN": {
          "value": "secret value"
        }
      }
    },
    "release-signing": {
      "description": "Release signing key",
      "type": "ssh",
      "public_key": "ssh-ed25519 AAAA..."
    }
  }
}
```

The `secrets` map contains exactly the names in the request. If more than one
secret provides the same environment variable, every provided value must be
identical. The client rejects the response and does not start the operation if
either condition fails. A client invocation supports at most one SSH secret
and rejects a response containing more than one.

The approval completion omits secret contents:

```json
{
  "result": "APPROVED"
}
```

### Denied invocation response

A denial response has this form:

```json
{
  "result": "DENIED",
  "reason": "USER_DENIED",
  "message": "The request was denied."
}
```

`reason` is one of the following values:

| Reason | Meaning |
| --- | --- |
| `USER_DENIED` | The user denied the request. |
| `POLICY_DENIED` | Device policy denied the request. |
| `INVALID_REQUEST` | The requested secrets or operation were invalid. |
| `OTHER` | No more specific denial reason applies. |

The `message` member contains diagnostic text. The denial completion repeats
the complete denial plaintext, including `reason` and `message`.

### Aborted invocation completion

`ABORTED` is a client completion result. A device must not send it as a secret
invocation response.

```json
{
  "result": "ABORTED",
  "reason": "CANCELLED",
  "message": "The request was interrupted."
}
```

`reason` is one of the following values:

| Reason | Meaning |
| --- | --- |
| `CANCELLED` | The client received an explicit cancellation or termination signal. |
| `TIMED_OUT` | Consecutive relay or network failures exceeded the client's retry policy. |
| `INVALID_RESPONSE` | The client received a response that it could not validate or use. |
| `CLIENT_ERROR` | A local client error prevented the operation from continuing. |
| `OTHER` | No more specific abort reason applies. |

If the client has sent the request but cannot obtain a usable response, it
sends an aborted completion when it still has the live cryptographic context.
This handoff is best effort and does not delay termination indefinitely.

## Git signing

The `GitSign` method requests one SSHSIG signature in the `git` namespace. It
uses a new paired exchange related to an earlier `Invocation` exchange. The
device makes a separate decision for every Git signature request; accepting
the invocation does not approve later signatures.

### Git signing request

```json
{
  "method": "GitSign",
  "invocation_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "invocation_token": "base64 invocation token",
  "secret": "release-signing",
  "message": "base64 Git signing payload"
}
```

`invocation_id` is the request identifier of the related `Invocation`.
`invocation_token` is the same decoded 32-byte value supplied in that
invocation. `secret` names the SSH secret selected by the invocation.
`message` is the Base64 encoding of the exact bytes that Git asks the signing
program to sign. The SSHSIG namespace is fixed to `git` and is not transmitted.

The device rejects the request unless the invocation identifier, token, and
secret are consistent with one another.

### Git signing response and completion

An approved response contains an ASCII-armored SSHSIG signature:

```json
{
  "result": "APPROVED",
  "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----\n"
}
```

The signature covers the decoded `message` bytes with namespace `git` and the
SSH key named by `secret`. An RSA key uses `rsa-sha2-512` or `rsa-sha2-256` as
the SSH signature algorithm, not the legacy RSA-SHA1 `ssh-rsa` signature
algorithm. The approval completion omits the signature:

```json
{
  "result": "APPROVED"
}
```

A denied response uses the same `DENIED` form and denial reasons as an
invocation response. Its completion repeats the denial. Before a usable
response, cancellation or failure uses the same client-only `ABORTED` form and
abort reasons defined for invocation completion. An invalid response also
produces an aborted completion. After the client authenticates a terminal
response, later cancellation does not change its completion result. Each
signature uses its own request identifier and paired cryptographic context.

## Secret list

The `SecretList` request contains only the method and client software
information:

```json
{
  "method": "SecretList"
}
```

The response maps each available secret name to its metadata:

```json
{
  "secrets": {
    "github": {
      "description": "GitHub API access",
      "type": "environment",
      "variables": ["GH_TOKEN"]
    },
    "release-signing": {
      "description": "Release signing key",
      "type": "ssh",
      "public_key": "ssh-ed25519 AAAA..."
    }
  }
}
```

The response contains no secret values. An empty device result uses an empty
`secrets` object.

The completion contains only the required client software information. It has
no method-specific members.

## Secret upload

The `SecretUpload` method delivers a proposal to the device. A successful
response confirms that the device durably accepted responsibility for the
proposal. Acceptance or application of the proposed change is a separate
decision and is not reported by this exchange.

### Secret upload request

An environment-secret upload has this form:

```json
{
  "method": "SecretUpload",
  "mode": "CREATE",
  "secret": {
    "name": "github",
    "description": "GitHub API access",
    "type": "environment",
    "variables": {
      "GH_TOKEN": {
        "value": "secret value"
      }
    }
  }
}
```

The `mode` member defines the proposed change if it is accepted:

| Mode | Effect if accepted |
| --- | --- |
| `CREATE` | Create a secret. Its final name can differ from the proposed name. |
| `UPDATE` | Change the supplied fields and retain unspecified content. |
| `REPLACE` | Replace the complete secret and remove unspecified content. |

For `UPDATE`, an absent `description` retains the existing description. An
empty string proposes removing it. For `CREATE` and `REPLACE`, an absent
description means that the resulting secret has no description.

The `variables` map is nonempty. In `UPDATE`, omitted environment variables
are retained. In `REPLACE`, omitted environment variables are removed.

An SSH-secret upload has this form:

```json
{
  "method": "SecretUpload",
  "mode": "CREATE",
  "secret": {
    "name": "release-signing",
    "description": "Release signing key",
    "type": "ssh",
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
  }
}
```

`private_key` contains an unencrypted SSH private key in OpenSSH format. The
key algorithm is encoded by that format and does not have a separate JSON
member. It is required for every SSH-secret upload. In `UPDATE`, accepting the
proposal replaces the existing private key. Description handling is the same
for both secret types.

### Secret upload response and completion

The device confirms that it accepted responsibility for the proposal with:

```json
{
  "result": "RECEIVED"
}
```

The device can reject the proposal immediately:

```json
{
  "result": "REJECTED",
  "message": "The upload cannot be accepted."
}
```

`REJECTED` is an immediate protocol result, not a later decision about the
proposed change. The client completion repeats the response `result` and, for
`REJECTED`, its `message`.

## Pairing removal

The `PairingRemove` method removes an active pairing. The request is:

```json
{
  "method": "PairingRemove"
}
```

An accepted response is an empty object:

```json
{}
```

An authenticated response guarantees that the device removed the pairing
before releasing that response. The client then deletes its local pairing and
sends a best-effort completion. The completion contains only the required
client software information.

Because local and device state cannot be deleted atomically, either endpoint
can retain an unmatched pairing after a crash or forced local removal. A later
normal operation then fails authentication or client authorization. Recovery
uses a fresh pairing.

## Authenticated errors

For any paired method, the device can return an authenticated error plaintext
instead of the method-specific response:

```json
{
  "error": "INVALID_REQUEST",
  "message": "The request could not be understood."
}
```

Version 1 defines these common codes:

| Code | Meaning |
| --- | --- |
| `INVALID_REQUEST` | The protected request is malformed or inconsistent. |
| `UNSUPPORTED_METHOD` | The device does not implement the requested method. |
| `INVALID_STATE` | The method is not valid for the pairing's current state. |

The code set is extensible. A client reports an unknown code without assigning
it another meaning. After an authenticated error, the client can send an
`ABORTED` completion with reason `CLIENT_ERROR` when it has a valid completion
context. It does not apply a method-specific success or denial transition.

## Unprotected error reports

When an endpoint cannot construct a protected response, the response payload
can instead contain:

```json
{
  "error": "UNSUPPORTED_PROTOCOL_VERSION",
  "message": "The protocol version is not supported."
}
```

This object occupies the same relay response position as a cryptographic
response envelope, but it is not encrypted or authenticated. The relay can
fabricate, replace, or suppress it. A client uses it only as diagnostic
information. It must not change pairing keys, pairing state, rotation state,
or invocation results because of an unprotected report.

The code set is extensible. `UNSUPPORTED_PROTOCOL_VERSION` indicates that the
receiver cannot process the selected cryptosystem version. Other codes have no
trusted meaning unless a later protocol defines them.

## Compatibility

The outer `version` member selects the cryptosystem and its envelope format.
The protected `method` member selects the application operation. Client
software versions identify implementations but do not select protocol rules.

A compatible revision of v1 can add optional members. Receivers ignore members
that the revision does not define, and senders cannot assume that an unknown
member is authenticated merely because it appears next to a cryptographic
envelope. New protected behavior belongs inside protected plaintext.

An incompatible cryptographic or application change uses a new client-device
protocol version. Relay protocol compatibility is versioned separately. An
implementation must not infer v1 compatibility from an application or library
version string.

## References

- [Agentknock v1 cryptosystem](cryptosystem.md)
- [Agentknock v1 client-relay protocol](client-relay-protocol.md)
- [RFC 4648: The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648.html)
