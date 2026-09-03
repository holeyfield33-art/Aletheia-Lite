# Security Policy

## Supported line

The supported release line is Aletheia Lite `1.0.x`.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's
GitHub Security Advisories page:
[report a vulnerability privately](https://github.com/holeyfield33-art/Aletheia-Lite/security/advisories/new).

Include the affected version, reproduction steps, impact, and any proposed
mitigation. Do not include secrets or live credentials in a report.

Please do not publicly disclose a vulnerability before maintainers have had an
opportunity to investigate and remediate it. Security-sensitive components
include policy verification, capability gates, receipt signing and verification,
the audit ledger, dashboard authentication, and CLI/package release tooling.

## Scope

Reports are in scope when they demonstrate bypass of an enforced capability,
policy or receipt integrity failure, authentication bypass, or release artifact
tampering. Aletheia Lite only enforces actions routed through it; it cannot
prevent an agent or operator from bypassing Aletheia and invoking a tool
directly.
