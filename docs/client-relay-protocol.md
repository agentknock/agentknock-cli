# Agentknock v1 client-relay protocol

This document defines the WebSocket protocol between an Agentknock client and
a relay. It covers initial-pairing connections, authenticated client
connections, message transfer, acknowledgement, reconnection, and the relay
state visible to a client.

The device-facing relay protocol is outside this document. The
[Agentknock v1 client-device protocol](client-device-protocol.md) defines the
opaque payloads carried through the relay. The [Agentknock v1
cryptosystem](cryptosystem.md) defines their cryptographic protection.

## Delivery model

The relay provides store-and-forward delivery. The client and device do not
need to be online at the same time.

Each client-originated message crosses two separate handoffs:

```text
Client -> relay -> device
```

The relay sends an `ack` frame after it accepts responsibility for a message.
It sends a `receipt` frame after the device accepts responsibility. Neither
frame means that a user saw the request or that application processing
succeeded.

The relay provides at-least-once transfer while an exchange is active.
Duplicate frames and messages are normal. Stable message identities and
first-value retention make retries idempotent; endpoint application logic
remains responsible for processing each message once.

The relay treats every application `payload` as an opaque JSON value. It does
not interpret cryptographic envelope members, protected methods, results,
errors, or secret contents.

## Identifiers

The client-facing protocol uses the following identifiers:

| Identifier | Representation | Purpose |
| --- | --- | --- |
| `address_id` | 32 lowercase hexadecimal characters | Selects the discovery alias used to start pairing. |
| `device_id` | Canonical uppercase ULID | Selects the paired device's relay mailbox. |
| `client_id` | Canonical uppercase ULID | Selects one client record within a device mailbox. |
| `request_id` | Canonical uppercase ULID | Selects one application exchange. |

The canonical ULID form matches:

```text
[0-7][0-9A-HJKMNP-TV-Z]{25}
```

For initial pairing, `client_id` and `request_id` contain the same fresh ULID.
After pairing, the client retains that `client_id` and generates a fresh
`request_id` for each exchange. Request IDs are globally unique values, not
sequence numbers. A client must not intentionally reuse one for another
exchange.

The relay validates a previously unseen request ID's embedded timestamp. The
hosted v1 relay accepts an ID at most five minutes old and at most one minute
in the future. It applies this check only when the identifier first creates
state. Retries continue to use retained state after the timestamp leaves the
admission window.

## Client token

Before initial pairing, the client generates a 32-byte random `client_token`
with a cryptographically secure random-number generator. It encodes the token
as unpadded base64url and sends it only in an HTTP authorization header:

```http
Authorization: Bearer CLIENT_TOKEN
```

The token authenticates the client to the relay. It is independent of the
end-to-end client PSK and is never included in an application payload. The
relay can store a one-way hash instead of the raw token.

The client uses the same token for every reconnect of the pairing attempt and,
after enrollment, for every authenticated connection belonging to that
`client_id`. A client token does not authorize another client ID.

## WebSocket connections

The relay URL uses `wss`. Clients perform normal WebSocket upgrade over TLS,
including certificate-chain and hostname validation. Version 1 does not
negotiate a WebSocket subprotocol.

### Initial-pairing connection

A new client connects to:

```text
GET /v1/address/{address_id}/request/{request_id}
```

The client sends its new client token as a bearer token. Every frame on this
connection uses `client_id = request_id`.

The first successful admission fixes the address ID, client ID, client token,
and resolved device for the pairing attempt. Reconnecting with the same
address ID, request ID, and token resumes that attempt. Another address or
token cannot replace the admitted values.

The relay can reject a fresh pairing attempt when the address is unavailable,
new-pairing admission is disabled, the request ID is inadmissible, or pending
pairing capacity is exhausted. An already admitted attempt remains resumable
until it expires or becomes active.

### Authenticated client connection

An enrolled client connects to:

```text
GET /v1/device/{device_id}/client/{client_id}
```

The bearer token must match the active client record selected by the URL. A
`client_id` inside a frame must match the authenticated connection identity;
the frame cannot select another client.

An active client can create and resume exchanges. A suspended or revoked
client cannot connect. The relay can also suspend service independently of the
device-controlled client state.

### Upgrade failures

An unsuccessful upgrade returns a JSON object with an `error` and `message`
string:

```json
{
  "error": "UNAUTHORIZED",
  "message": "Authentication failed."
}
```

Clients use the HTTP status code as the primary classification. Common status
codes are:

| Status | Meaning |
| --- | --- |
| `400 Bad Request` | The identifier or upgrade request is malformed or inadmissible. |
| `401 Unauthorized` | The bearer token is missing or invalid. |
| `403 Forbidden` | The client exists but is not active, or service policy denies it. |
| `404 Not Found` | The address, device, or client route is unavailable. |
| `409 Conflict` | An identifier is already bound incompatibly. |
| `426 Upgrade Required` | The request is not a WebSocket upgrade. |
| `429 Too Many Requests` | A temporary connection or admission limit was exceeded. |
| `500 Internal Server Error` | The relay failed to process the upgrade. |

A retryable HTTP error can also contain `retryable: true` and a
`retry_after_ms` integer. An HTTP `429` response can include a standard
`Retry-After` header. A client honors the supplied delay before retrying.

## Frame encoding

Each application frame is a UTF-8 JSON object with a string `type` member.
Binary WebSocket frames are invalid. A sender includes every required member.
A receiver ignores unknown object members but rejects an unknown frame type,
a missing required member, a member of the wrong type, or a frame that the
peer role cannot send.

The maximum encoded WebSocket frame size is 256 KiB. The `payload` member can
contain any JSON value, including `null`; its presence is significant.

Every exchange-bearing frame contains `client_id` and `request_id`. The client
rejects a received frame whose identifier does not match the active exchange.

## Message kinds and client role

Version 1 defines three message kinds:

| Kind | Client action | Device action visible to the client |
| --- | --- | --- |
| `request` | Publish. | Accept for delivery. |
| `response` | Accept and acknowledge. | Publish one response. |
| `completion` | Publish. | Accept for best-effort delivery. |

The normal order is request, response, completion. A client can publish a
completion without receiving a response when it aborts an exchange. If it
receives a response, it acknowledges that response before publishing the
completion.

The complete identity of an application message is
`(client_id, request_id, kind)`. The first payload accepted for that identity
wins. The relay accepts later duplicates without comparing their payloads and
does not replace the stored value.

## Message frame

The client publishes a request or completion with a `message` frame:

```json
{
  "type": "message",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
  "kind": "request",
  "payload": {
    "opaque": "application value"
  }
}
```

The relay delivers a device response to the client with the same frame shape
and `kind: "response"`. Application payloads are defined by the client-device
protocol.

The origin retains the fixed frame values until the relay acknowledges them.
If the connection fails first, the origin sends those values again after
reconnecting. The JSON byte serialization does not need to be identical.

## Acknowledgement frame

The relay acknowledges an accepted client message with:

```json
{
  "type": "ack",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
  "kind": "request"
}
```

An `ack` means that the relay accepted responsibility and durably applied any
related relay state transition. After receiving it, the client no longer
needs to retain the payload for relay retransmission.

The client sends the same frame with `kind: "response"` after it accepts a
response into its live exchange state. Application rejection does not delay
this transport acknowledgement: repeating the same payload cannot repair an
invalid application message.

Acknowledgements are not themselves acknowledged. A repeated acknowledgement
is harmless and cannot revive an inactive message.

The relay acknowledges every accepted completion. For an unknown or inactive
exchange, it can discard the completion while acknowledging its terminal
intent. Completion acknowledgement therefore does not guarantee device
delivery.

## Receipt frame

After the eventual recipient accepts a client-originated message, the relay
sends:

```json
{
  "type": "receipt",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
  "kind": "request"
}
```

The relay sends an origin's `ack` before its `receipt` on one socket. Receipts
are informational and are not acknowledged. A later state snapshot provides
the same delivery fact while relay state is retained.

A request receipt means that the device accepted responsibility for the
request. It does not mean that the device produced a response. A client does
not need to wait for a completion receipt and can stop after receiving the
completion acknowledgement.

## Resume frame

After reconnecting, a client associates its new socket with one accepted
exchange by sending:

```json
{
  "type": "resume",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X"
}
```

The client sends `resume` only after the relay has acknowledged its request.
If it did not receive that acknowledgement, it resends the retained request
instead.

Authentication alone does not associate a new socket with every exchange for
that client. The client resumes each live exchange separately.

## State frame

The relay answers a valid resume with one authoritative snapshot:

```json
{
  "type": "state",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
  "exchange": "open",
  "request": "delivered",
  "response": "accepted",
  "completion": "absent"
}
```

`exchange` has one of the following values:

| State | Meaning |
| --- | --- |
| `open` | The request is accepted; a response or completion can still arrive. |
| `closing` | A completion is accepted; only remaining delivery can continue. |
| `settled` | Completion delivery finished and only recovery state remains. |
| `expired` | A deadline or client-state transition ended delivery. |

Each message state has one of the following values:

| State | Meaning |
| --- | --- |
| `absent` | The relay has not accepted the message. |
| `accepted` | The relay retains the payload for delivery. |
| `delivered` | The recipient accepted it and the relay deleted the payload. |
| `discarded` | A terminal event stopped delivery and the relay deleted the payload. |

The valid state combinations are:

| Exchange | Request | Response | Completion |
| --- | --- | --- | --- |
| `open` | `accepted` or `delivered` | `absent`, `accepted`, or `delivered` | `absent` |
| `closing` | `accepted` or `delivered` | `absent`, `delivered`, or `discarded` | `accepted` |
| `settled` | `delivered` | `absent`, `delivered`, or `discarded` | `delivered` |
| `expired` | `delivered` or `discarded` | `absent`, `delivered`, or `discarded` | `absent` or `discarded` |

Any response state other than `absent` implies that the request is
`delivered`.

The client reconciles its local state from the snapshot. The relay then sends
any pending response for that client. A `state` frame is not acknowledged; the
client resumes again if the snapshot is lost.

## Inactive frame

If an exchange has no live or replayable state, the relay sends:

```json
{
  "type": "inactive",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X"
}
```

An `inactive` reply to a failed message can also contain `kind`. With `kind`,
only that message can no longer be accepted or delivered. Without `kind`, the
whole exchange is inactive.

The client stops the affected retry. An `inactive` frame does not confirm
delivery and is not acknowledged. A message already in flight can arrive
after an inactive or terminal state; the client discards it.

## Error frame

The relay reports a frame or admission error with:

```json
{
  "type": "error",
  "client_id": "01K2ENXDTW1P3XAR4J7V7C9D0H",
  "request_id": "01K2EP16NWNAGJYF8J1Q2V6P3X",
  "kind": "request",
  "error": "RATE_LIMITED",
  "message": "The client created too many new exchanges.",
  "retryable": true,
  "retry_after_ms": 60000
}
```

`error`, `message`, and `retryable` are required. The relay includes
`client_id`, `request_id`, and `kind` when they are relevant and known. A
retryable error can include `retry_after_ms`.

The error code set is extensible. Version 1 codes include:

| Code | Retry behavior |
| --- | --- |
| `INVALID_FRAME` | Do not retry the frame unchanged. |
| `INVALID_REQUEST_ID` | Do not retry the operation with that request ID. |
| `REQUEST_ID_CONFLICT` | Do not retry the operation with that request ID. |
| `CLIENT_INACTIVE` | Stop; the pairing is not active at the relay. |
| `RATE_LIMITED` | Retry after the supplied delay. |
| `CAPACITY_EXCEEDED` | Retry after the supplied delay. |
| `INTERNAL_ERROR` | Reconnect and retry according to local policy. |

When `retryable` is false, the client stops the affected exchange. When it is
true, the client closes or abandons the current socket, waits at least the
specified delay, and follows the reconnect rules. A valid nonretryable frame
does not become retryable because its code is unknown.

## Reconnection and recovery

The client retains only the state needed for its live process. It uses the
following recovery rules after a connection failure:

| Local state | Retained payload | Reconnect action |
| --- | --- | --- |
| No relay acknowledgement | Yes | Resend the fixed `message` frame values. |
| Relay acknowledgement, no receipt | No | Send `resume` if onward delivery still matters. |
| Receipt | No | Continue to wait for the next application message, or finish. |
| Inactive | No | Stop the affected operation. |

A healthy WebSocket does not need application-level polling. The client waits
for relay frames and uses WebSocket Ping and Pong control frames to detect a
dead connection. The reference client sends a Ping after 30 seconds without a
frame and requires a Pong within 10 seconds.

Connection, I/O, and retryable relay failures are consecutive failures. A
valid relay frame resets the client's failure budget. Pending application work
does not expire merely because no response arrives on a healthy connection.
The user or embedding application can cancel the operation explicitly.

## Exchange transitions

The relay applies these client-visible rules atomically:

- The first admissible request creates an open exchange and receives an
  acknowledgement.
- A duplicate request receives an acknowledgement. If the device already
  accepted it, the client also observes a receipt or delivered state.
- A device response implies request delivery. The client accepts at most one
  response payload and acknowledges every duplicate of that accepted message.
- An accepted completion moves an open exchange to closing and discards an
  undelivered response.
- A completion for an unknown or inactive exchange is acknowledged and
  discarded. The relay retains enough state to stop a reordered request from
  recreating the operation while its request ID remains admissible.
- Completion delivery settles the exchange. The client can stop after the
  relay acknowledges completion.

If request and completion are both pending for device delivery, the relay
preserves request-before-completion order.

## Client-visible lifetime

The hosted v1 relay uses these retention periods:

| State | Lifetime |
| --- | --- |
| Pending pairing | 24 hours after admission unless activated first. |
| Active exchange with an associated client socket | No fixed protocol deadline. |
| Active exchange after its last associated client socket closes | Five minutes to reconnect and resume. |
| Accepted completion awaiting delivery | Up to 24 hours after relay acceptance. |
| Settled or expired exchange | Five-minute recovery grace and at least through the request ID admission cutoff. |

After recovery state is removed, `resume` returns `inactive`. These periods do
not change the end-to-end cryptographic freshness requirements.

Rate and capacity limits can change independently of the wire format. A relay
rejects work before acknowledgement when a temporary limit applies and returns
a retryable error with an appropriate delay.

## WebSocket closure

The relay uses standard WebSocket closure codes for common protocol failures:

| Code | Meaning |
| --- | --- |
| `1008` | Invalid or peer-forbidden frame. |
| `1009` | Frame exceeds 256 KiB. |
| `1011` | Transient relay failure. |
| `1013` | Temporary rate limit. |
| `4002` | The client was suspended. |
| `4003` | The client was revoked. |
| `4004` | Relay service for the client or device was suspended. |

The client does not reconnect immediately after a deliberate inactive or
service-policy closure. An unexpected closure follows the recovery table based
on whether the relay acknowledged the message in progress.

## Security properties

The client token authenticates the client to the relay. It does not make the
relay a trusted endpoint for application data. A compromised relay can read
identifiers, tokens presented to it, timing, message sizes, and traffic
relationships. It can delay, reorder, replay, suppress, or fabricate transport
traffic and unprotected error reports.

End-to-end security comes from the client-device cryptosystem. A client must
not treat an `ack`, `receipt`, `state`, or relay `error` frame as proof of a
device decision. Only an authenticated client-device response can authorize a
secret use or a pairing-state change.

## References

- [Agentknock v1 client-device protocol](client-device-protocol.md)
- [Agentknock v1 cryptosystem](cryptosystem.md)
- [RFC 6455: The WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
