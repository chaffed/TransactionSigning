"""Positive Pay / Reverse Positive Pay verification of presented items.

For each item in an image cash letter the engine:
  1. decodes the QR from the front image (exactly one expected),
  2. verifies the Ed25519 signature against the issuer's enrolled public key,
  3. compares the signed fields with the MICR data the BOFD encoded in the
     ICL check-detail record (routing, account, serial, amount),
  4. compares the signed payee with OCR of the printed payee line
     (the QR can't stop washing the paper -- this is what catches it),
  5. applies date rules (stale / post-dated),
  6. (Positive Pay) matches against the issuer's issue file, void status,
     and already-paid serials.

Reverse Positive Pay runs steps 1-5 at the bank, exports the presented items
with the raw QR text, and the *customer* independently re-verifies the
signature against its own key and register before deciding pay/return.
"""

from __future__ import annotations

import csv
import difflib
import json
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import date, timedelta
from pathlib import Path

from PIL import Image, ImageFilter, ImageOps

from .keys import Keyring
from .payload import CheckData, PayloadError, VerifiedPayload, normalize_payee, verify
from .qr import decode_qrs
from .render import PAYEE_BOX, from_tiff
from .x937 import IclItem

STALE_DAYS = 180
PAYEE_MATCH_THRESHOLD = 0.85


@dataclass
class Finding:
    code: str
    detail: str
    severity: str = "FAIL"  # FAIL -> exception; WARN -> informational


@dataclass
class ItemResult:
    sequence: str
    micr_routing: str
    micr_account: str
    micr_serial: str
    micr_amount_cents: int
    qr_text: str | None = None
    signed: CheckData | None = None
    kid: str | None = None
    ocr_payee: str | None = None
    findings: list[Finding] = field(default_factory=list)

    @property
    def decision(self) -> str:
        return "EXCEPTION" if any(f.severity == "FAIL" for f in self.findings) else "PAY"

    def fail(self, code: str, detail: str) -> None:
        self.findings.append(Finding(code, detail, "FAIL"))

    def warn(self, code: str, detail: str) -> None:
        self.findings.append(Finding(code, detail, "WARN"))


# ---------------------------------------------------------------------------
# Issue file (what the customer tells the bank it issued)
# ---------------------------------------------------------------------------

@dataclass
class IssueRecord:
    routing: str
    account: str
    serial: str
    amount_cents: int
    issue_date: date
    payee: str
    status: str = "ISSUED"  # ISSUED | VOID


ISSUE_FIELDS = ["routing", "account", "serial", "amount", "issue_date", "payee", "status"]


def serial_key(routing: str, account: str, serial: str) -> tuple[str, str, str]:
    """Lookup key for an item; serials compare without leading zeros."""
    return (routing, account, serial.lstrip("0") or "0")


def write_issue_file(path: str | Path, records: list[IssueRecord]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(ISSUE_FIELDS)
        for r in records:
            w.writerow([r.routing, r.account, r.serial, f"{r.amount_cents / 100:.2f}",
                        r.issue_date.isoformat(), r.payee, r.status])


def read_issue_file(path: str | Path) -> dict[tuple[str, str, str], IssueRecord]:
    out = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            dollars, cents = row["amount"].split(".")
            rec = IssueRecord(
                routing=row["routing"], account=row["account"], serial=row["serial"],
                amount_cents=int(dollars) * 100 + int(cents),
                issue_date=date.fromisoformat(row["issue_date"]),
                payee=row["payee"], status=row["status"].upper(),
            )
            out[serial_key(rec.routing, rec.account, rec.serial)] = rec
    return out


# ---------------------------------------------------------------------------
# OCR of the printed payee
# ---------------------------------------------------------------------------

def ocr_payee(front: Image.Image) -> str | None:
    """OCR the printed payee line with the tesseract CLI; None if unavailable."""
    if shutil.which("tesseract") is None:
        return None
    # Despeckle (capture noise reads as junk glyphs), then trim to the ink.
    crop = front.convert("L").crop(PAYEE_BOX).filter(ImageFilter.MedianFilter(3))
    bbox = ImageOps.invert(crop).point(lambda v: 255 if v > 128 else 0).getbbox()
    if bbox is None:
        return ""
    crop = ImageOps.expand(crop.crop(bbox), border=12, fill=255)
    crop = crop.resize((crop.width * 2, crop.height * 2), Image.Resampling.LANCZOS)
    with tempfile.NamedTemporaryFile(suffix=".png") as tmp:
        crop.save(tmp.name)
        res = subprocess.run(
            ["tesseract", tmp.name, "-", "--psm", "7"],
            capture_output=True, text=True, timeout=30,
        )
    return " ".join(res.stdout.split()) if res.returncode == 0 else None


def _payee_similarity(a: str, b: str) -> float:
    norm = lambda s: "".join(ch for ch in normalize_payee(s) if ch.isalnum())  # noqa: E731
    return difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()


# ---------------------------------------------------------------------------
# Core checks shared by Positive Pay and Reverse Positive Pay
# ---------------------------------------------------------------------------

def verify_item(
    item: IclItem,
    keyring: Keyring,
    *,
    today: date,
    use_ocr: bool = True,
) -> ItemResult:
    r = ItemResult(item.sequence, item.routing, item.account, item.serial, item.amount_cents)
    front = from_tiff(item.front_tiff)

    qrs = decode_qrs(front)
    if not qrs:
        r.fail("QR_MISSING", "no signed QR code found on the front image")
        return r
    if len(qrs) > 1:
        r.fail("QR_MULTIPLE", f"{len(qrs)} different QR codes on one item")
        return r
    r.qr_text = qrs[0]

    try:
        vp: VerifiedPayload = verify(r.qr_text, keyring)
    except PayloadError as e:
        r.fail(e.code, e.detail)
        return r
    r.signed, r.kid = vp.data, vp.kid
    s = vp.data

    # Signed data vs. the MICR line as encoded in the cash letter
    if s.routing != item.routing:
        r.fail("MICR_ROUTING_MISMATCH", f"signed {s.routing}, MICR {item.routing}")
    if s.account != item.account:
        r.fail("MICR_ACCOUNT_MISMATCH", f"signed {s.account}, MICR {item.account}")
    if s.serial.lstrip("0") != item.serial.lstrip("0"):
        r.fail("MICR_SERIAL_MISMATCH", f"signed {s.serial}, MICR {item.serial}")
    if s.amount_cents != item.amount_cents:
        r.fail("AMOUNT_MISMATCH",
               f"signed ${s.amount_cents / 100:,.2f}, encoded ${item.amount_cents / 100:,.2f}")

    # Signed payee vs. what is physically printed on the item
    if use_ocr:
        r.ocr_payee = ocr_payee(front)
        if r.ocr_payee is None:
            r.warn("OCR_UNAVAILABLE", "printed payee not checked")
        else:
            score = _payee_similarity(s.payee, r.ocr_payee)
            if score < PAYEE_MATCH_THRESHOLD:
                r.fail("PAYEE_ALTERED",
                       f"signed {s.payee!r}, printed {r.ocr_payee!r} (similarity {score:.2f})")

    if s.issue_date > today:
        r.fail("POST_DATED", f"issued {s.issue_date}")
    elif s.issue_date < today - timedelta(days=STALE_DAYS):
        r.fail("STALE_DATED", f"issued {s.issue_date}, older than {STALE_DAYS} days")
    return r


# ---------------------------------------------------------------------------
# Positive Pay (bank decides, using the customer's issue file)
# ---------------------------------------------------------------------------

def positive_pay(
    items: list[IclItem],
    keyring: Keyring,
    issue_register: dict[tuple[str, str, str], IssueRecord] | None,
    *,
    today: date,
    paid: set[tuple[str, str, str]] | None = None,
    use_ocr: bool = True,
) -> list[ItemResult]:
    paid = set(paid or ())
    results = []
    for item in items:
        r = verify_item(item, keyring, today=today, use_ocr=use_ocr)
        key = serial_key(item.routing, item.account, item.serial)

        if key in paid:
            r.fail("DUPLICATE_PRESENTMENT", f"serial {item.serial} already presented/paid")

        if issue_register is not None:
            rec = issue_register.get(key)
            if rec is None:
                r.fail("NOT_ISSUED", f"serial {item.serial} not in issue file")
            else:
                if rec.status == "VOID":
                    r.fail("ISSUE_VOID", f"serial {item.serial} was voided by the issuer")
                if rec.amount_cents != item.amount_cents:
                    r.fail("ISSUE_AMOUNT_MISMATCH",
                           f"issued ${rec.amount_cents / 100:,.2f}, encoded ${item.amount_cents / 100:,.2f}")
                if r.signed and normalize_payee(rec.payee) != normalize_payee(r.signed.payee):
                    r.fail("ISSUE_PAYEE_MISMATCH", f"issued {rec.payee!r}, signed {r.signed.payee!r}")

        if r.decision == "PAY":
            paid.add(key)
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# Reverse Positive Pay (bank exports, customer decides)
# ---------------------------------------------------------------------------

def export_presented_items(path: str | Path, results: list[ItemResult]) -> None:
    """Bank -> customer file: MICR data, raw QR text, and the bank's findings."""
    rows = []
    for r in results:
        rows.append({
            "sequence": r.sequence,
            "micr": {"routing": r.micr_routing, "account": r.micr_account,
                     "serial": r.micr_serial, "amount_cents": r.micr_amount_cents},
            "qr_text": r.qr_text,
            "ocr_payee": r.ocr_payee,
            "bank_findings": [asdict(f) for f in r.findings],
        })
    Path(path).write_text(json.dumps(rows, indent=2) + "\n")


def customer_review(
    presented_path: str | Path,
    keyring: Keyring,
    register: dict[tuple[str, str, str], IssueRecord],
    *,
    today: date,
) -> list[dict]:
    """Customer side: trust nothing the bank says except the raw evidence.
    Re-verify each QR signature with the customer's own keyring, compare to
    the customer's own register, and return a PAY/RETURN decision per item."""
    decisions = []
    seen: set[tuple[str, str, str]] = set()
    for row in json.loads(Path(presented_path).read_text()):
        micr = row["micr"]
        reasons = [f["code"] for f in row["bank_findings"] if f["severity"] == "FAIL"
                   and f["code"] in ("PAYEE_ALTERED", "AMOUNT_MISMATCH", "MICR_SERIAL_MISMATCH",
                                     "MICR_ACCOUNT_MISMATCH", "MICR_ROUTING_MISMATCH")]
        if row["qr_text"] is None:
            reasons.append("QR_MISSING")
        else:
            try:
                vp = verify(row["qr_text"], keyring)
                if vp.data.amount_cents != micr["amount_cents"] and "AMOUNT_MISMATCH" not in reasons:
                    reasons.append("AMOUNT_MISMATCH")
            except PayloadError as e:
                reasons.append(e.code)

        key = serial_key(micr["routing"], micr["account"], micr["serial"])
        rec = register.get(key)
        if rec is None:
            reasons.append("NOT_IN_REGISTER")
        else:
            if rec.status == "VOID":
                reasons.append("VOID")
            if rec.amount_cents != micr["amount_cents"]:
                reasons.append("REGISTER_AMOUNT_MISMATCH")
            if rec.issue_date < today - timedelta(days=STALE_DAYS):
                reasons.append("STALE_DATED")
        if key in seen:
            reasons.append("DUPLICATE_PRESENTMENT")

        decision = "RETURN" if reasons else "PAY"
        if decision == "PAY":
            seen.add(key)
        decisions.append({
            "sequence": row["sequence"], "serial": micr["serial"],
            "amount": f"{micr['amount_cents'] / 100:.2f}",
            "decision": decision, "reasons": ";".join(dict.fromkeys(reasons)),
        })
    return decisions
