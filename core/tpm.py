"""TPM interface with an Ed25519 software fallback (ported from
``crypto/tpm_interface.py``).

The upstream module talks to a real TPM when present but ships a working
software fallback that is usable today: an Ed25519 signing key persisted to disk
(or held in memory as an ephemeral key).  aletheia-light uses the fallback path
by default; the interface is kept identical so a hardware backend can be dropped
in later without touching callers.

Backed by :mod:`cryptography` (already a dependency) rather than pulling in a
separate binding.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class TPMKey:
    """A signing key handle plus its public half."""

    private: Ed25519PrivateKey
    backend: str  # "hardware" | "software-persistent" | "software-ephemeral"

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    def public_bytes(self) -> bytes:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_hex(self) -> str:
        return self.public_bytes().hex()


class TPMInterface:
    """Signing façade with a software Ed25519 fallback.

    Parameters
    ----------
    key_path:
        Where to persist / load the software key.  If ``None`` an ephemeral key
        is generated that lives only for the process lifetime.
    """

    def __init__(self, key_path: str | os.PathLike[str] | None = None) -> None:
        self._key = self._load_or_create(Path(key_path) if key_path else None)

    # -- key management ------------------------------------------------------
    @staticmethod
    def hardware_available() -> bool:
        """Whether a real TPM is usable.  Always False in the light build."""

        return False

    def _load_or_create(self, key_path: Path | None) -> TPMKey:
        if key_path is not None and key_path.exists():
            raw = key_path.read_bytes()
            private = Ed25519PrivateKey.from_private_bytes(raw)
            return TPMKey(private=private, backend="software-persistent")

        private = Ed25519PrivateKey.generate()
        if key_path is not None:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            raw = private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            key_path.write_bytes(raw)
            try:
                os.chmod(key_path, 0o600)
            except OSError:  # pragma: no cover - platform dependent
                pass
            return TPMKey(private=private, backend="software-persistent")
        return TPMKey(private=private, backend="software-ephemeral")

    # -- operations ----------------------------------------------------------
    @property
    def backend(self) -> str:
        return self._key.backend

    def public_key_hex(self) -> str:
        return self._key.public_hex()

    def sign(self, message: bytes) -> bytes:
        """Return an Ed25519 signature over ``message``."""

        return self._key.private.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature produced by this key's public half."""

        try:
            self._key.public.verify(signature, message)
            return True
        except Exception:
            return False

    @staticmethod
    def verify_with(public_key_hex: str, message: bytes, signature: bytes) -> bool:
        """Verify ``signature`` against an arbitrary public key (hex)."""

        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(signature, message)
            return True
        except Exception:
            return False
