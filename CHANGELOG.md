# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0](https://github.com/agentknock/agentknock-cli/compare/v0.4.1...v0.5.0) - 2026-09-05

### Fixed

- complete canceled and invalid exchanges consistently
- preserve replacement pairings during delayed operations
- explain legacy PEM key conversion

### Other

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
