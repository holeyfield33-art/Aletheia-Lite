# Threat Model

## Assets

- Signed policy manifests
- Signing keys
- Signed execution receipts
- The decision ledger
- Agent identity
- Declared and granted capabilities

## Trust boundaries

- Agent -> Aletheia Lite
- Policy -> enforcement pipeline
- Enforcement decision -> external executor
- Receipt store -> verifier
- Dashboard -> local operator

## Primary threats

- Undeclared capability use
- Confused deputy delegation
- Policy tampering
- Receipt tampering or reordering
- Obfuscated dangerous instructions
- Resource exhaustion
- Repeated low-signal coordinated behavior
- Signing-key compromise
- Bypassing Aletheia and invoking a tool directly

Aletheia Lite only enforces actions routed through its pipeline. It cannot
prevent actions performed through an unmediated execution path. The local
software signing fallback protects integrity against accidental or ordinary
tampering, but a compromised host or signing key can forge valid receipts.
Operators must protect the data directory and configure a trusted manifest key
when policy authenticity matters.
