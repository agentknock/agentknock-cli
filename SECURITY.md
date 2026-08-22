# Security

## Supported versions

Only the latest Agentknock CLI release receives security fixes. Before you
report a vulnerability, verify that it affects the latest release.

## Report a vulnerability

Do not report a suspected vulnerability in a public issue, discussion, or pull
request.

Use the private reporting channel that best matches the affected component:

- For Agentknock CLI, use [GitHub private vulnerability reporting][cli-report].
- For Agentknock for Android, use
  [GitHub private vulnerability reporting][android-report].
- For the Agentknock service, website, protocol, multiple components, or an
  uncertain component, email
  [security@fulldisclosure.fi](mailto:security@fulldisclosure.fi).

Full Disclosure operates Agentknock and receives reports sent to that address.
If a vulnerability affects more than one component, send one email instead of
creating separate reports.

Include the following information when it is available:

- The affected component and version.
- A description of the vulnerability and its security impact.
- The conditions and steps required to reproduce it.
- A minimal proof of concept, relevant logs, or both.
- A possible mitigation or fix.

Do not send credentials, pairing data, or personal data from a live system. Use
test data, and remove sensitive information from logs and screenshots.

## Test safely

Test only accounts, devices, systems, and data that you own or have permission
to use. Do not disrupt the service, degrade its availability, or access another
person's data. If you encounter another person's data, stop testing and report
the vulnerability.

## Coordinate disclosure

Give the maintainers reasonable time to investigate and fix a vulnerability
before you disclose it publicly. The maintainers will coordinate disclosure
with you and credit your contribution unless you ask to remain anonymous.

[android-report]: https://github.com/nakedible/agentknock-android/security/advisories/new
[cli-report]: https://github.com/nakedible/agentknock-cli/security/advisories/new
