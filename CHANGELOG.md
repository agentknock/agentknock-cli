# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/nakedible/agentknock-cli/releases/tag/v0.1.0) - 2026-08-23

### Other

- Add the release installer
- Mark Agentknock as an early preview
- Route readers through the project README
- Document the Rust library status
- Complete README contribution and license sections
- Document release verification and command execution
- Generalize the client-device protocol
- Focus relay protocol on client behavior
- Document Agentknock protocols and execution
- Add initial project README
- Complete crate package metadata
- Handle authenticated device protocol errors
- License project and verify release inputs
- Test supported Rust and musl targets
- Define published crate contents
- Mark project documentation as TODO
- Document the public library API
- Add local pairing status
- Add cancellation and software identity
- Introduce shared Agentknock client
- Represent requested secrets as a set
- Adopt secret terminology and protocol
- Make extensible public enums non-exhaustive
- Isolate the test relay override
- Simplify request pipeline errors
- Trim the library API
- Prefer post-quantum TLS key exchange
- Add local and continuous integration checks
- Expand command-line help
- Improve CLI guidance and wait reporting
- Add reproducible cryptosystem verification
- Clarify freshness and retained exchange state
- Rename AgentKnock to Agentknock
- Correct cryptosystem state invariants
- Clarify cryptographic record acceptance
- Document AgentKnock v1 cryptosystem
- Separate pairing secret from application payload
- Bind pairing commitment to client random
- Validate cryptographic input lengths
- Simplify profile metadata and terminology
- Add typed profile upload support
- Restructure CLI around subcommands
- Pin and hash executed commands on Linux
- Configure Rustls crypto provider
- Clarify CLI recovery guidance
- Align client naming with relay protocol
- Rename mailbox ID to device ID
- Revise pairing SAS derivation
- Migrate relay protocol to WebSockets
- Use empty completion responses
- Accept 202 completion responses
- Handle unauthenticated error reports
- Add platform details to pairing metadata
- Include CLI version in encrypted messages
- Add invocation context to credential requests
- Add profile listing
- Add unpairing support
- Bind messages to protocol version
- Improve command status and error output
- Report credential request progress
- Handle signals during credential requests
- Bound relay failure retries
- Rotate stale pairing PSKs automatically
- Implement local PSK rotation
- Simplify PSK rotation messages
- Make pairing config writes atomic
- Send pending PSK rotation
- Confirm pairing before activation
- Implement pairing flow
- Minimize credential completion messages
- Retry idempotent relay requests
- Separate credential protocol components
- Move credential requests into library
- Add request and result payloads
- Implement encrypted relay message exchange
- Load pairing configuration
- Version relay endpoints
- Add request-complete relay exchange
- Implement flat command-line operations
- Add JSON, HPKE, and REST scaffolding
- Add command-line parser
- Initialize Rust package
