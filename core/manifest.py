"""Signed policy manifest loading & verification (ported from
``manifest/signing.py``).

A *policy manifest* declares the rules aletheia-light enforces: which agents may
touch which resources, deny-listed intent categories, and per-agent token
budgets.  So the policy itself cannot be silently swapped, a manifest is
Ed25519-signed over its canonical JSON; loading verifies the signature against a
trusted public key before the policy is honored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


class ManifestError(Exception):
    """Raised when a manifest is malformed or fails signature verification."""


def _canonical_bytes(policy: dict[str, Any]) -> bytes:
    return json.dumps(policy, sort_keys=True, ensure_ascii=False).encode("utf-8")


@dataclass
class PolicyManifest:
    """A verified policy document."""

    version: int
    grants: dict[str, list[str]] = field(default_factory=dict)  # agent -> resources
    deny_categories: list[str] = field(default_factory=list)  # symbolic-narrowing cats
    token_budgets: dict[str, int] = field(default_factory=dict)  # agent -> budget
    metadata: dict[str, Any] = field(default_factory=dict)

    def policy_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "grants": self.grants,
            "deny_categories": self.deny_categories,
            "token_budgets": self.token_budgets,
            "metadata": self.metadata,
        }

    def granted_authority(self) -> dict[str, list[str]]:
        """Shape expected by :func:`core.receipts.confused_deputy_check`."""

        return dict(self.grants)

    def is_denied(self, category: str | None) -> bool:
        return category is not None and category in self.deny_categories


def sign_manifest(policy: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Return a signed manifest envelope for ``policy``."""

    signature = private_key.sign(_canonical_bytes(policy))
    pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "policy": policy,
        "signature": signature.hex(),
        "public_key": pub.hex(),
    }


def _verify_envelope(envelope: dict[str, Any], trusted_pubkey: str | None) -> dict[str, Any]:
    if "policy" not in envelope or "signature" not in envelope:
        raise ManifestError("manifest envelope missing 'policy' or 'signature'")

    policy = envelope["policy"]
    embedded = envelope.get("public_key")
    pubkey_hex = trusted_pubkey or embedded
    if pubkey_hex is None:
        raise ManifestError("no public key available to verify manifest")
    if trusted_pubkey is not None and embedded is not None and trusted_pubkey != embedded:
        raise ManifestError("manifest signed by an untrusted key")

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(envelope["signature"]), _canonical_bytes(policy))
    except Exception as exc:  # noqa: BLE001 - normalize to ManifestError
        raise ManifestError(f"manifest signature verification failed: {exc}") from exc
    return policy


def load_manifest(
    path: str | Path,
    trusted_pubkey: str | None = None,
) -> PolicyManifest:
    """Load and verify a manifest file, returning the parsed policy.

    If ``trusted_pubkey`` is provided the manifest must be signed by exactly
    that key; otherwise the embedded public key is used (integrity only).
    """

    p = Path(path)
    if not p.exists():
        raise ManifestError(f"manifest not found: {p}")
    try:
        envelope = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc

    policy = _verify_envelope(envelope, trusted_pubkey)
    return PolicyManifest(
        version=int(policy.get("version", 1)),
        grants=dict(policy.get("grants", {})),
        deny_categories=list(policy.get("deny_categories", [])),
        token_budgets=dict(policy.get("token_budgets", {})),
        metadata=dict(policy.get("metadata", {})),
    )


def default_manifest() -> PolicyManifest:
    """A permissive-but-sane default when no signed manifest is configured."""

    return PolicyManifest(
        version=1,
        grants={"*": ["*"]},
        deny_categories=["destroy", "exfil"],
        token_budgets={},
        metadata={"source": "built-in default"},
    )
