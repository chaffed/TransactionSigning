"""Signed payment records: the payer's mandate and the originator's entry.

Two clear-text records, each signed with its author's own Ed25519 private key:

  MD1 (mandate, signed once by the PAYER at setup)
    MD1;KID=<payer key>;MID=<mandate id>;OID=<originator id>;ONM=<originator name>;
        OPK=<originator public key>;RT=<payer routing>;ACCT=<payer account>;
        MAX=<max per debit>;FRQ=<ONCE|WEEK|MNTH|ADHC>;FROM=<date>;TO=<date>;SIG=<sig>

  PE1 (entry, signed by the ORIGINATOR for every debit)
    PE1;KID=<originator key>;TYP=DR;OID=<originator id>;RT=<routing>;ACCT=<account>;
        AMT=<dollars.cents>;EDT=<effective date>;ID=<entry id>;MH=<mandate hash>;SIG=<sig>

Design choices (same rules as the check QR, see checksign/payload.py):
* Signed bytes are everything before ";SIG=", verified exactly as received.
* One anchored regex per record type fixes field order and value syntax.
* The mandate carries the originator's public key (OPK), so the paying bank
  needs only its *own customer's* key: the payer vouches for the originator.
* MH (hash of the full signed mandate) binds each entry to one mandate.
* Uppercase-only alphabet with base32 signatures/keys: survives ACH systems
  that uppercase text, and stays inside the X12 basic character set (no
  '*', '~', or '\\', the usual X12 delimiters).
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from checksign.payload import PayloadError

SIG_SEP = ";SIG="
_B32 = "[A-Z2-7]"
_DATE = r"\d{4}-\d{2}-\d{2}"
_AMT = r"\d{1,10}\.\d{2}"
_NAME = r"[A-Z0-9 &.,'/-]{1,35}"


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def unb32(text: str) -> bytes:
    return base64.b32decode(text + "=" * (-len(text) % 8))


def public_key_b32(key: Ed25519PublicKey) -> str:
    return b32(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def public_key_from_b32(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(unb32(text))


@dataclass(frozen=True)
class Profile:
    tag: str
    name: str  # prefix for error codes, e.g. "MANDATE" -> MANDATE_SIG_INVALID
    fields: tuple[tuple[str, str], ...]

    @property
    def regex(self) -> re.Pattern:
        body = "".join(f";{k}=(?P<{k}>{v})" for k, v in self.fields)
        return re.compile(f"^{self.tag}{body};SIG=(?P<SIG>{_B32}{{103}})$")


MANDATE = Profile("MD1", "MANDATE", (
    ("KID", r"[A-Z0-9-]{1,20}"),
    ("MID", r"[A-Z0-9-]{1,35}"),
    ("OID", r"[A-Z0-9]{10}"),
    ("ONM", _NAME),
    ("OPK", f"{_B32}{{52}}"),
    ("RT", r"\d{9}"),
    ("ACCT", r"\d{4,17}"),
    ("MAX", _AMT),
    ("FRQ", "ONCE|WEEK|MNTH|ADHC"),
    ("FROM", _DATE),
    ("TO", _DATE),
))

ENTRY = Profile("PE1", "ENTRY", (
    ("KID", r"[A-Z0-9-]{1,20}"),
    ("TYP", "DR|CR"),
    ("OID", r"[A-Z0-9]{10}"),
    ("RT", r"\d{9}"),
    ("ACCT", r"\d{4,17}"),
    ("AMT", _AMT),
    ("EDT", _DATE),
    ("ID", r"[A-Z0-9-]{1,15}"),
    ("MH", f"{_B32}{{32}}"),
))


def sign_record(profile: Profile, key: Ed25519PrivateKey, values: dict[str, str]) -> str:
    if set(values) != {k for k, _ in profile.fields}:
        raise ValueError(f"{profile.tag} needs exactly {[k for k, _ in profile.fields]}")
    msg = profile.tag + "".join(f";{k}={values[k]}" for k, _ in profile.fields)
    text = msg + SIG_SEP + b32(key.sign(msg.encode("ascii")))
    if not profile.regex.match(text):
        raise ValueError(f"values do not fit the {profile.tag} format: {msg!r}")
    return text


def parse_unverified(profile: Profile, text: str) -> dict[str, str]:
    """Field values *before* signature checking -- only for choosing the key."""
    m = profile.regex.match(text)
    if not m:
        raise PayloadError(f"{profile.name}_MALFORMED", f"not a valid {profile.tag} record")
    return m.groupdict()


def verify_record(profile: Profile, text: str, public_key: Ed25519PublicKey) -> dict[str, str]:
    fields = parse_unverified(profile, text)
    message = text[: text.index(SIG_SEP)].encode("ascii")
    try:
        public_key.verify(unb32(fields["SIG"]), message)
    except InvalidSignature:
        raise PayloadError(f"{profile.name}_SIG_INVALID",
                           f"{profile.tag} signature does not match its contents") from None
    return fields


def mandate_hash(mandate_text: str) -> str:
    """160-bit SHA-256 prefix of the full signed mandate, base32 (32 chars)."""
    return b32(hashlib.sha256(mandate_text.encode("ascii")).digest()[:20])


def amount_str(cents: int) -> str:
    return f"{cents // 100}.{cents % 100:02d}"


def parse_amount(text: str) -> int:
    dollars, cents = text.split(".")
    return int(dollars) * 100 + int(cents)
