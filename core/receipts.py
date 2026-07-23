"""Signed, hash-chained receipts (ported from ``core/receipt_keys.py`` +
``crypto/chain_signer.py``).

Every decision the pipeline makes produces a *receipt*: a tamper-evident record
that is Ed25519-signed and chained to the previous receipt by hash, so that
removing or reordering a receipt is detectable.  The signing key is derived,
where possible, from a hardware identifier (DMI UUID or MAC) via HKDF so the
same machine reproduces the same key; if no hardware id is available we fall
back to an ephemeral key (the same behavior as aletheia-core's watcher).

This module also implements **Gate C1 — the confused-deputy check**: before a
receipt is signed for a privileged action, verify that the agent actually holds
the authority it is acting under, so a low-privilege caller cannot borrow a
high-privilege deputy's credentials.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from .tpm import TPMInterface

GENESIS_HASH = "0" * 64
_HKDF_INFO = b"aletheia-light/receipt-signing/v1"
_DEFAULT_EPHEMERAL_KEY_PATH = Path.home() / ".aletheia-light" / "ephemeral_key.pem"


# --------------------------------------------------------------------------- #
# Hardware-bound key derivation
# --------------------------------------------------------------------------- #
def _hardware_id() -> tuple[bytes, str]:
    """Return ``(seed_material, source)`` for key derivation.

    Tries the DMI product UUID first, then the interface MAC address, then a
    random ephemeral value.  ``source`` records which was used.
    """

    dmi = Path("/sys/class/dmi/id/product_uuid")
    try:
        if dmi.exists():
            data = dmi.read_text().strip()
            if data:
                return data.encode("utf-8"), "dmi-uuid"
    except OSError:
        pass

    node = uuid.getnode()
    # uuid.getnode sets the multicast bit when it had to invent a random MAC.
    if not (node >> 40) & 0x1:
        return node.to_bytes(6, "big"), "mac"

    return uuid.uuid4().bytes, "ephemeral"


def _ephemeral_key_path() -> Path:
    override = os.environ.get("ALETHEIA_LIGHT_KEY_PATH")
    return Path(override) if override else _DEFAULT_EPHEMERAL_KEY_PATH


def _load_or_create_ephemeral_key() -> Ed25519PrivateKey:
    """Persist the ephemeral fallback key to disk (same pattern as
    :class:`~core.tpm.TPMInterface`'s software-persistent backend), so a
    process restart on a machine with no stable hardware id reuses the same
    key instead of minting a new one and invalidating every previously
    signed receipt's verifiability.
    """

    path = _ephemeral_key_path()
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(path.read_bytes())

    key = Ed25519PrivateKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(raw)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
    return key


def derive_signing_key(salt: bytes | None = None) -> tuple[Ed25519PrivateKey, str]:
    """Derive an Ed25519 key from the hardware id via HKDF.

    Returns ``(key, source)``.  A stable machine yields a stable key.  If no
    stable hardware id is available, the ephemeral fallback key is persisted
    to disk (see :func:`_load_or_create_ephemeral_key`) so it is still stable
    across process restarts.
    """

    seed, source = _hardware_id()
    if source == "ephemeral":
        return _load_or_create_ephemeral_key(), source

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt or b"aletheia-light",
        info=_HKDF_INFO,
    )
    key_material = hkdf.derive(seed)
    key = Ed25519PrivateKey.from_private_bytes(key_material)
    return key, source


# --------------------------------------------------------------------------- #
# Confused-deputy check (Gate C1)
# --------------------------------------------------------------------------- #
@dataclass
class DeputyCheck:
    ok: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "reason": self.reason}


def confused_deputy_check(
    acting_agent: str,
    on_behalf_of: str | None,
    requested_resources: list[str],
    granted_authority: dict[str, list[str]],
) -> DeputyCheck:
    """Gate C1.

    ``granted_authority`` maps a principal -> the resources it may act on.  A
    request is a confused-deputy attempt when the acting agent claims to act on
    behalf of another principal but reaches for resources that principal was
    never granted, or when the acting agent itself lacks the resources it
    requests and no valid delegation covers them.
    """

    principal = on_behalf_of or acting_agent
    allowed = list(granted_authority.get(principal, []))
    # A wildcard grant short-circuits.
    if "*" in allowed:
        return DeputyCheck(True)

    def _permitted(resource: str) -> bool:
        return any(pat == "*" or fnmatch.fnmatch(resource, pat) for pat in allowed)

    overreach = sorted({r for r in requested_resources if not _permitted(r)})
    if overreach:
        who = f"{acting_agent} on behalf of {on_behalf_of}" if on_behalf_of else acting_agent
        return DeputyCheck(
            False,
            f"confused-deputy: {who} requested {overreach} "
            f"outside {principal}'s granted authority",
        )
    return DeputyCheck(True)


# --------------------------------------------------------------------------- #
# Receipts
# --------------------------------------------------------------------------- #
@dataclass
class Receipt:
    receipt_id: str
    request_id: str
    fingerprint: str
    agent: str
    verdict: str
    timestamp: float
    prev_hash: str
    violations: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    signer_pubkey: str = ""
    signer_source: str = ""
    receipt_hash: str = ""
    signature: str = ""

    def signable_payload(self) -> bytes:
        """The canonical bytes that get hashed and signed.

        Excludes ``receipt_hash`` and ``signature`` (which are derived from it).
        """

        payload = {
            "receipt_id": self.receipt_id,
            "request_id": self.request_id,
            "fingerprint": self.fingerprint,
            "agent": self.agent,
            "verdict": self.verdict,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "violations": self.violations,
            "metadata": self.metadata,
            "signer_pubkey": self.signer_pubkey,
            "signer_source": self.signer_source,
        }
        return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

    def compute_hash(self) -> str:
        return hashlib.sha256(self.signable_payload()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Receipt":
        return cls(**d)


class ReceiptSigner:
    """Produces signed, hash-chained receipts.

    The chain head is tracked in-process; on construction it can be seeded with
    the last known hash (e.g. loaded from the audit log) so a restart continues
    the same chain.
    """

    def __init__(
        self,
        key_path: str | Path | None = None,
        last_hash: str = GENESIS_HASH,
        use_hardware_derivation: bool = True,
    ) -> None:
        if use_hardware_derivation and key_path is None:
            self._key, self._source = derive_signing_key()
            self._tpm: TPMInterface | None = None
        else:
            self._tpm = TPMInterface(key_path)
            self._source = self._tpm.backend
            self._key = None
        self._last_hash = last_hash

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def public_key_hex(self) -> str:
        if self._tpm is not None:
            return self._tpm.public_key_hex()
        return (
            self._key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            .hex()
        )

    def _sign(self, message: bytes) -> bytes:
        if self._tpm is not None:
            return self._tpm.sign(message)
        return self._key.sign(message)

    def issue(
        self,
        request_id: str,
        fingerprint: str,
        agent: str,
        verdict: str,
        violations: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Receipt:
        """Create, hash, sign and chain a receipt."""

        receipt = Receipt(
            receipt_id=uuid.uuid4().hex,
            request_id=request_id,
            fingerprint=fingerprint,
            agent=agent,
            verdict=verdict,
            timestamp=time.time(),
            prev_hash=self._last_hash,
            violations=list(violations or []),
            metadata=dict(metadata or {}),
            signer_pubkey=self.public_key_hex(),
            signer_source=self._source,
        )
        receipt.receipt_hash = receipt.compute_hash()
        receipt.signature = self._sign(receipt.receipt_hash.encode("utf-8")).hex()
        self._last_hash = receipt.receipt_hash
        return receipt


def verify_receipt(receipt: Receipt) -> bool:
    """Verify a single receipt's hash integrity and signature."""

    if receipt.compute_hash() != receipt.receipt_hash:
        return False
    return TPMInterface.verify_with(
        receipt.signer_pubkey,
        receipt.receipt_hash.encode("utf-8"),
        bytes.fromhex(receipt.signature),
    )


def verify_chain(receipts: list[Receipt]) -> bool:
    """Verify a list of receipts links correctly and each is well-signed."""

    prev = GENESIS_HASH
    for r in receipts:
        if r.prev_hash != prev:
            return False
        if not verify_receipt(r):
            return False
        prev = r.receipt_hash
    return True
