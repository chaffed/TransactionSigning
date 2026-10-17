"""Issuer signing keys and the bank-side keyring of enrolled public keys.

The private key lives with the check-printing system (in production: an HSM
or cloud KMS, never a PEM on disk). The issuer enrolls each public key with
its bank out-of-band, keyed by a KID that is printed in every QR so keys can
be rotated -- and revoked -- without reissuing outstanding checks.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class KeyEntry:
    kid: str
    public_key: Ed25519PublicKey
    status: str = "active"  # "active" | "revoked"
    owner: str = ""
    # "routing:account" pairs this key may authorize (payment mandates);
    # empty for issuer keys that only sign their own checks/entries.
    accounts: list[str] = field(default_factory=list)


class Keyring:
    def __init__(self, entries: dict[str, KeyEntry] | None = None):
        self.entries: dict[str, KeyEntry] = entries or {}

    def get(self, kid: str) -> KeyEntry | None:
        return self.entries.get(kid)

    def add(self, kid: str, public_key: Ed25519PublicKey, owner: str = "",
            accounts: list[str] | None = None) -> None:
        self.entries[kid] = KeyEntry(kid, public_key, "active", owner, list(accounts or []))

    def revoke(self, kid: str) -> None:
        self.entries[kid].status = "revoked"

    @classmethod
    def load(cls, path: str | Path) -> "Keyring":
        raw = json.loads(Path(path).read_text())
        entries = {}
        for kid, e in raw.items():
            pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(e["public_key"]))
            entries[kid] = KeyEntry(kid, pub, e.get("status", "active"), e.get("owner", ""),
                                    e.get("accounts", []))
        return cls(entries)

    def save(self, path: str | Path) -> None:
        out = {
            kid: {
                "public_key": base64.b64encode(
                    e.public_key.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw
                    )
                ).decode(),
                "status": e.status,
                "owner": e.owner,
                **({"accounts": e.accounts} if e.accounts else {}),
            }
            for kid, e in self.entries.items()
        }
        Path(path).write_text(json.dumps(out, indent=2) + "\n")


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    p = Path(path)
    p.write_bytes(pem)
    p.chmod(0o600)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key
