"""Signed check payload carried in the QR code.

Wire format (clear text, fixed field order, ASCII):

    CS1;KID=<key id>;RT=<routing>;ACCT=<account>;SN=<serial>;AMT=<dollars.cents>;DT=<YYYY-MM-DD>;PAYEE=<payee>;SIG=<sig>

* Everything before ";SIG=" is the signed message, verified byte-for-byte as
  received -- the verifier never re-serializes, so there is no
  canonicalization gap between what was signed and what is checked.
* SIG is an Ed25519 signature (64 bytes) as unpadded base64url (86 chars).
* The whole string is matched by one anchored regex with a fixed field order,
  so a payload with reordered, duplicated, or extra fields is rejected before
  any field is trusted.
* PAYEE is percent-encoded only for characters that would break the format
  (';', '=', '%', non-ASCII); ordinary names stay human-readable.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from datetime import date
from urllib.parse import quote, unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import Keyring

VERSION = "CS1"
SIG_SEP = ";SIG="

_PAYEE_SAFE = " &.,'-/#()!?:+@*"

_PAYLOAD_RE = re.compile(
    r"^CS1"
    r";KID=(?P<kid>[A-Za-z0-9._-]{1,32})"
    r";RT=(?P<rt>\d{9})"
    r";ACCT=(?P<acct>\d{4,17})"
    r";SN=(?P<sn>\d{1,15})"
    r";AMT=(?P<amt>\d{1,10}\.\d{2})"
    r";DT=(?P<dt>\d{4}-\d{2}-\d{2})"
    r";PAYEE=(?P<payee>[\x20-\x3a\x3c\x3e-\x7e]{1,120})"  # printable ASCII minus ';' and '='
    r";SIG=(?P<sig>[A-Za-z0-9_-]{86})$"
)


class PayloadError(Exception):
    """Raised when a QR payload cannot be trusted. `code` is a stable reason code."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CheckData:
    routing: str
    account: str
    serial: str
    amount_cents: int
    issue_date: date
    payee: str

    @property
    def amount_str(self) -> str:
        return f"{self.amount_cents // 100}.{self.amount_cents % 100:02d}"


@dataclass(frozen=True)
class VerifiedPayload:
    kid: str
    data: CheckData
    raw: str


def normalize_payee(payee: str) -> str:
    """Collapse whitespace and uppercase, so issuance and verification agree."""
    return " ".join(payee.split()).upper()


def signed_message(kid: str, data: CheckData) -> str:
    payee = quote(normalize_payee(data.payee), safe=_PAYEE_SAFE)
    return (
        f"{VERSION};KID={kid};RT={data.routing};ACCT={data.account};SN={data.serial}"
        f";AMT={data.amount_str};DT={data.issue_date.isoformat()};PAYEE={payee}"
    )


def sign(private_key: Ed25519PrivateKey, kid: str, data: CheckData) -> str:
    msg = signed_message(kid, data)
    sig = private_key.sign(msg.encode("ascii"))
    payload = msg + SIG_SEP + base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    # Fail at issuance, not at the bank, if the data can't round-trip the format.
    if not _PAYLOAD_RE.match(payload):
        raise ValueError(f"check data does not fit the payload format: {payload!r}")
    return payload


def verify(text: str, keyring: Keyring) -> VerifiedPayload:
    """Verify a scanned QR payload. Raises PayloadError; never returns unverified data."""
    m = _PAYLOAD_RE.match(text)
    if not m:
        raise PayloadError("QR_MALFORMED", "payload does not match the CS1 format")

    kid = m["kid"]
    entry = keyring.get(kid)
    if entry is None:
        raise PayloadError("KEY_UNKNOWN", f"no enrolled public key for KID={kid}")
    if entry.status == "revoked":
        raise PayloadError("KEY_REVOKED", f"key {kid} is revoked")

    message = text[: text.index(SIG_SEP)].encode("ascii")
    sig = base64.urlsafe_b64decode(m["sig"] + "==")
    try:
        entry.public_key.verify(sig, message)
    except InvalidSignature:
        raise PayloadError("SIG_INVALID", "signature does not match payload contents") from None

    try:
        issue_date = date.fromisoformat(m["dt"])
    except ValueError:
        raise PayloadError("QR_MALFORMED", f"invalid date {m['dt']}") from None
    dollars, cents = m["amt"].split(".")
    data = CheckData(
        routing=m["rt"],
        account=m["acct"],
        serial=m["sn"],
        amount_cents=int(dollars) * 100 + int(cents),
        issue_date=issue_date,
        payee=unquote(m["payee"]),
    )
    return VerifiedPayload(kid=kid, data=data, raw=text)
