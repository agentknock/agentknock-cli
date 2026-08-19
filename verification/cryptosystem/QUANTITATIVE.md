# Quantitative obligations outside the symbolic models

Tamarin, ProVerif, and Verifpal reason with perfect symbolic terms. They can
prove the collision-free branch of SAS agreement and can exhibit a trace when
the SAS gate is removed, but they do not assign probabilities to a truncated
HKDF output. This file records the arithmetic that qualifies claim O02.

## Twelve-digit SAS

The specification interprets an 8-byte HKDF output as an integer and reduces
it modulo

```text
M = 1,000,000,000,000.
```

For a uniformly distributed 64-bit value,

```text
N = 2^64 = 18,446,744,073,709,551,616
q = floor(N / M) = 18,446,744
r = N mod M = 73,709,551,616.
```

Consequently, `r` displayed strings have `q + 1` preimages and the other
`M - r` strings have `q` preimages. The greatest probability of one fixed
incorrect SAS matching is therefore

```text
(q + 1) / N = 1.0000000502143058e-12,
```

or 39.8631370662 bits. The smallest is

```text
q / N = 9.999999960041972e-13.
```

The maximum relative increase over exactly `10^-12` is about
`5.02143e-8`, which justifies the specification's statement that the modulo
bias is negligible. For `n` candidates each fixed under the protocol's
commit-before-peer-contribution condition, the union bound is

```text
min(1, n * 1.0000000502143058e-12).
```

The union bound itself does not require the candidate events to be mutually
independent.

This relies on the cryptographic assumptions that the HKDF result is
pseudorandom for the adversary at the time each contribution must be fixed,
that the commitment cannot be opened to a different client secret, and that
the full 12 digits are compared. It does not cover partial comparison,
human-interface mistakes, or attempts outside the device's pending-attempt
limit. Enforcement of that finite operational limit is an assumption about
the deployed state machine, not a conclusion of any symbolic model here.

## ULID uniqueness

The symbolic models use fresh names for accepted `client_id` and ordinary
`request_id` values. Concretely, two generated ULIDs can collide only when
their 48-bit millisecond timestamps are equal and their independent 80-bit
random fields collide. For `m` identifiers generated in one millisecond, the
usual birthday upper bound is approximately

```text
m * (m - 1) / 2^81.
```

The specification additionally requires actual uniqueness checks and an
implementation-defined freshness policy. Those requirements, claimed clock
correctness, and rollback resistance are not established by the probability
bound or by the symbolic models.
