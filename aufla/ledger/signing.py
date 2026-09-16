"""Ed25519 signing, in two tiers.

A single offline key cannot sign a Merkle root every second -- nobody is going
to present a hardware token 86,400 times a day. So signing is split:

**Batch tier** -- an online key signs every batch root as it is sealed. It has
to be reachable, so it is the one an attacker with host access could steal.

**Checkpoint tier** -- an offline root key signs a daily checkpoint over that
day's chain head. Stealing the online key therefore buys forgery only within
the current day; every earlier day is anchored by a signature made with a key
that was never on the machine.

The checkpoint is the artifact that goes to court.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = ["SigningError", "KeyPair", "load_or_create_keypair", "canonical_bytes"]


class SigningError(RuntimeError):
    """Raised when signing or verification cannot be performed."""


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic encoding of a payload for signing.

    Key order and whitespace must not change the bytes, or a re-serialised
    record would fail its own signature check.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(slots=True)
class KeyPair:
    """An Ed25519 key pair. The private half may be absent (verify-only)."""

    private: Ed25519PrivateKey | None
    public: Ed25519PublicKey
    label: str = "unnamed"

    # ---- construction -----------------------------------------------------

    @classmethod
    def generate(cls, label: str = "unnamed") -> "KeyPair":
        private = Ed25519PrivateKey.generate()
        return cls(private=private, public=private.public_key(), label=label)

    @classmethod
    def from_public_hex(cls, public_hex: str, label: str = "unnamed") -> "KeyPair":
        try:
            raw = bytes.fromhex(public_hex)
        except ValueError:
            raise SigningError(f"public key is not hex: {public_hex!r}") from None
        try:
            return cls(
                private=None,
                public=Ed25519PublicKey.from_public_bytes(raw),
                label=label,
            )
        except ValueError as exc:
            raise SigningError(f"invalid Ed25519 public key: {exc}") from None

    # ---- serialisation ----------------------------------------------------

    @property
    def public_hex(self) -> str:
        return self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    @property
    def can_sign(self) -> bool:
        return self.private is not None

    def save(self, path: str | Path) -> None:
        """Write the private key as PKCS#8 PEM, owner-readable where possible."""
        if self.private is None:
            raise SigningError(f"key {self.label!r} has no private half to save")

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            self.private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            target.chmod(0o600)
        except (OSError, NotImplementedError):  # pragma: no cover - Windows
            pass

    @classmethod
    def load(cls, path: str | Path, label: str = "unnamed") -> "KeyPair":
        data = Path(path).read_bytes()
        try:
            private = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError) as exc:
            raise SigningError(f"cannot load key from {path}: {exc}") from None
        if not isinstance(private, Ed25519PrivateKey):
            raise SigningError(
                f"{path} is not an Ed25519 key but {type(private).__name__}"
            )
        return cls(private=private, public=private.public_key(), label=label)

    # ---- operations -------------------------------------------------------

    def sign(self, payload: dict[str, Any]) -> str:
        if self.private is None:
            raise SigningError(f"key {self.label!r} is verify-only")
        return self.private.sign(canonical_bytes(payload)).hex()

    def verify(self, payload: dict[str, Any], signature_hex: str) -> bool:
        try:
            self.public.verify(bytes.fromhex(signature_hex), canonical_bytes(payload))
        except (InvalidSignature, ValueError):
            return False
        return True


def load_or_create_keypair(path: str | Path, label: str = "unnamed") -> KeyPair:
    """Load a key from ``path``, generating and saving one if absent."""
    target = Path(path)
    if target.exists():
        return KeyPair.load(target, label=label)
    keypair = KeyPair.generate(label=label)
    keypair.save(target)
    return keypair
