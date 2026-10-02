# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2](https://github.com/agentknock/agentknock-cli/compare/v0.6.1...v0.6.2) - 2026-09-23

### Fixed

- name protocol enums without serde mirrors
- list SSH agent identities without copying them
- validate the Git signing key through the key comparison
- detect standard stream kinds with std metadata
- read script contents without a byte-by-byte prefix tracker
- simplify executable selection
- simplify invocation service startup and dispatch
- carry invocation service options as one value
- simplify reading secret upload sources
- dispatch CLI operations from the parsed commands
- print prefixed and plain diagnostics through one printer
- serialize the pending pairing directly
- report a missing Agentknock home as no pairing
- lock and sync the pairing directory through one type
- share pairing file error mapping
- share relay reconnection between request and completion
- give relay reads one disconnect path
- simplify proxy setting lookup
- share the cancellable completion handoff
- share sealing and device-error handling across requests
- build key derivation inputs with concat
- shorten secret option validation
- define approved secret messages where they are read
- remove unused address identifier serialization
- convert crypto and device errors with ?
- build every aborted completion the same way
- share protocol envelope messages
- move request errors into their own module
- keep scp-style remotes with @ in the path
- print a shell-safe chmod suggestion
- suggest converting PKCS#8 SSH private keys
- keep uploaded secret values zeroized
- hand off the abort completion briefly after the request fails
- stop sending a second pong for each relay ping

### Other

- pin the wire names of public protocol enums
- package npm launcher test with package-npm
- isolate integration tests from the caller's Git repository
- cover installer argument, platform, and release validation
- fail the procfs check when a test filter matches nothing
- wait on Tokio channels in async relay tests
- wrap invocation service lines that rustfmt skips
- share SSH agent framing helpers
- use the fake device helpers in the pairing tests
- use the fake device helpers in the invocation service tests
- use the fake device helpers in the run command tests
- use the fake device helpers in the secret upload tests
- add fake device helpers for relay exchanges
- share process helpers between integration tests
- isolate invocation service tests from proxy settings
- run the run command tests through the hermetic command helper
- run secret upload tests through the hermetic command helper
- run pairing tests through the hermetic command helper
- add a hermetic agentknock command helper

## [0.6.1](https://github.com/agentknock/agentknock-cli/compare/v0.6.0...v0.6.1) - 2026-09-14

### Fixed

- allow SSH and Git signing without procfs
- resolve the service executable before approval
- symlink Git signing helpers to the executable path
- *(deps)* refresh project dependencies and build tools
- preserve relative invocation-service launch paths
- start invocation services using executable launch paths
- inspect executables through retained readable descriptors
- resolve executable paths without procfs
- resolve the working directory without procfs
- collect Git repository context through PATH

### Other

- simplify the early release notice

## [0.6.0](https://github.com/agentknock/agentknock-cli/compare/v0.5.0...v0.6.0) - 2026-09-12

### Added

- include shebang source in invocation requests

### Fixed

- explain secret requirements in reason examples
- simplify script contents in invocation requests

### Other

- define script contents as a protocol field

## [0.5.0](https://github.com/agentknock/agentknock-cli/compare/v0.4.1...v0.5.0) - 2026-09-09

### Added

- support a configurable Agentknock home

### Fixed

- require UTF-8 Agentknock home paths
- prefix every line of Git signing errors
- preserve punctuation in error messages
- complete canceled and invalid exchanges consistently
- preserve replacement pairings during delayed operations
- explain legacy PEM key conversion

### Other

- pass Agentknock home through the service environment
- show reasons and configured signing in README examples
- cover relay errors across approval exchanges
- borrow invocation service state for connection handlers
- share approval exchanges for commands and signing
- unify request progress and CLI reporting
- simplify run validation and descriptor ownership
- centralize relay frame errors and remove unused state
- share pairing file reads and atomic writes
- use request errors for PSK rotation
- *(deps)* update dependencies and pinned build tools

## [0.4.1](https://github.com/agentknock/agentknock-cli/compare/v0.4.0...v0.4.1) - 2026-09-02

### Added

- decrypt SSH keys for secret uploads

### Other

- use stable installer URL

## [0.4.0](https://github.com/agentknock/agentknock-cli/compare/v0.3.0...v0.4.0) - 2026-08-30

### Added

- [**breaking**] add environment delivery controls

## [0.3.0](https://github.com/agentknock/agentknock-cli/compare/v0.2.1...v0.3.0) - 2026-08-29

### Added

- [**breaking**] rename exec to run and add shorthand
- add Git signing opt-out
- add SSH agent opt-out
- add SSH passthrough isolation
- support SSH authentication

### Fixed

- prefer XDG runtime directory for invocation state

## [0.2.1](https://github.com/agentknock/agentknock-cli/compare/v0.2.0...v0.2.1) - 2026-08-28

### Added

- support macOS on Apple Silicon
- identify relay connections with User-Agent
- add repository context to Git signing requests

## [0.2.0](https://github.com/agentknock/agentknock-cli/compare/v0.1.4...v0.2.0) - 2026-08-27

### Added

- support RSA keys for Git SSH signing
- [**breaking**] add SSH secret support and Git signing

### Fixed

- allow execution with closed standard streams

## [0.1.4](https://github.com/agentknock/agentknock-cli/compare/v0.1.3...v0.1.4) - 2026-08-24

### Other

- Use final documentation URL

## [0.1.3](https://github.com/agentknock/agentknock-cli/compare/v0.1.2...v0.1.3) - 2026-08-24

### Other

- Package Agentknock for npm
- Package Agentknock for Nix

## [0.1.2](https://github.com/agentknock/agentknock-cli/compare/v0.1.1...v0.1.2) - 2026-08-24

### Added

- Support relay proxies

## [0.1.1](https://github.com/agentknock/agentknock-cli/compare/v0.1.0...v0.1.1) - 2026-08-24

### Other

- *(deps)* Update dependencies

## [0.1.0](https://github.com/agentknock/agentknock-cli/releases/tag/v0.1.0) - 2026-08-24

### Added

- Initial release.
