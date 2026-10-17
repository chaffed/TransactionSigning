"""Paying-bank debit filter (RDFI / debtor agent), rail-neutral.

For each incoming debit:
  1. Mandate present, signed by a key the bank enrolled for THIS account.
  2. Mandate covers this originator, is in its date window, and not revoked.
  3. Entry signed by the originator key the payer put in the mandate (OPK).
  4. Signed entry matches the rail fields (amount, date, account, IDs) and
     references this exact mandate (MH).
  5. Amount within the mandate limit; frequency and replay checks against
     the bank's ledger of accepted entries.

Mandates on file: the payer registers each mandate it signs with its own
bank (as with today's ACH debit-filter authorization lists). If a debit
arrives without its in-band mandate -- ACH addenda stripped -- the filter
falls back to the on-file copy, re-verifying its signature like any other.

Missing entry signature with a valid mandate is REVIEW, not RETURN:
intermediaries do strip addenda / SplmtryData, and that alone is not fraud.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from checksign.keys import Keyring
from checksign.payload import PayloadError

from .model import RailDebit
from .payload import (
    ENTRY,
    MANDATE,
    amount_str,
    mandate_hash,
    parse_amount,
    parse_unverified,
    public_key_from_b32,
    verify_record,
)

# Indicative return-reason mapping. CTX is a corporate SEC code, so the ACH
# authorization return is R29; consumer debits would use R05/R07/R10/R11.
ACH_RETURN = {"DUPLICATE_ENTRY": "R24"}
ACH_DEFAULT = "R29"
ISO_RETURN = {
    "DUPLICATE_ENTRY": "AM05",
    "AMOUNT_MISMATCH": "AM09",
    "EXCEEDS_MANDATE_LIMIT": "AM09",
}
ISO_DEFAULT = "MD01"


@dataclass
class Finding:
    code: str
    detail: str
    severity: str = "FAIL"  # FAIL -> RETURN; REVIEW -> manual review


@dataclass
class FilterResult:
    debit: RailDebit
    findings: list[Finding] = field(default_factory=list)
    mandate_id: str | None = None
    mandate_text: str | None = None
    mandate_source: str = ""  # "IN_BAND" | "ON_FILE"

    @property
    def decision(self) -> str:
        sev = {f.severity for f in self.findings}
        return "RETURN" if "FAIL" in sev else "REVIEW" if "REVIEW" in sev else "ACCEPT"

    def return_code(self, rail: str) -> str:
        fails = [f.code for f in self.findings if f.severity == "FAIL"]
        if not fails:
            return ""
        table, default = (ACH_RETURN, ACH_DEFAULT) if rail == "ACH" else (ISO_RETURN, ISO_DEFAULT)
        return next((table[c] for c in fails if c in table), default)

    def fail(self, code: str, detail: str) -> None:
        self.findings.append(Finding(code, detail))


@dataclass
class Ledger:
    """What the paying bank has already accepted."""
    seen_ids: set[tuple[str, str]] = field(default_factory=set)  # (originator, entry id)
    collections: dict[str, list[date]] = field(default_factory=dict)  # mandate id -> dates


class DebitFilter:
    def __init__(self, payer_keys: Keyring, *, revoked_mandates: set[str] | None = None,
                 ledger: Ledger | None = None, mandates_on_file: list[str] | None = None):
        self.payer_keys = payer_keys
        self.revoked = revoked_mandates or set()
        self.ledger = ledger or Ledger()
        self.on_file: dict[tuple[str, str, str], list[str]] = {}
        for text in mandates_on_file or []:
            f = parse_unverified(MANDATE, text)
            self.on_file.setdefault((f["OID"], f["RT"], f["ACCT"]), []).append(text)

    def check(self, d: RailDebit) -> FilterResult:
        r = FilterResult(d)
        mandate = self._check_mandate(d, r)
        if mandate is not None:
            self._check_entry(d, mandate, r)
            if r.decision != "RETURN":  # replay/frequency only matter for otherwise-good debits
                self._check_history(d, mandate, r)
        if r.decision == "ACCEPT":
            self.ledger.seen_ids.add((d.originator_id, d.entry_id))
            self.ledger.collections.setdefault(mandate["MID"], []).append(d.effective_date)
        return r

    # -- 1 & 2: the payer's authorization ----------------------------------
    def _find_mandate(self, d: RailDebit) -> tuple[str | None, str]:
        if d.mandate_text:
            return d.mandate_text, "IN_BAND"
        candidates = self.on_file.get((d.originator_id, d.routing, d.account), [])
        if d.entry_text:  # prefer the mandate the signed entry points at
            try:
                mh = parse_unverified(ENTRY, d.entry_text)["MH"]
                candidates = [c for c in candidates if mandate_hash(c) == mh] or candidates
            except PayloadError:
                pass
        if d.mandate_id:
            candidates = [c for c in candidates
                          if parse_unverified(MANDATE, c)["MID"] == d.mandate_id]
        return (candidates[0], "ON_FILE") if len(candidates) == 1 else (None, "")

    def _check_mandate(self, d: RailDebit, r: FilterResult) -> dict | None:
        r.mandate_text, r.mandate_source = self._find_mandate(d)
        if not r.mandate_text:
            r.fail("MANDATE_MISSING", "no signed mandate in the message or on file")
            return None
        try:
            kid = parse_unverified(MANDATE, r.mandate_text)["KID"]
            entry = self.payer_keys.get(kid)
            if entry is None:
                raise PayloadError("KEY_UNKNOWN", f"no payer key enrolled as {kid}")
            if entry.status == "revoked":
                raise PayloadError("KEY_REVOKED", f"payer key {kid} is revoked")
            m = verify_record(MANDATE, r.mandate_text, entry.public_key)
        except PayloadError as e:
            r.fail(e.code, e.detail)
            return None
        r.mandate_id = m["MID"]

        account = f"{d.routing}:{d.account}"
        if account not in entry.accounts:
            r.fail("MANDATE_SIGNER_NOT_ACCOUNT_HOLDER",
                   f"key {kid} ({entry.owner}) is not enrolled for account {d.account}")
        if (m["RT"], m["ACCT"]) != (d.routing, d.account):
            r.fail("MANDATE_ACCOUNT_MISMATCH", f"mandate is for {m['RT']}:{m['ACCT']}")
        if m["OID"] != d.originator_id:
            r.fail("ORIGINATOR_NOT_AUTHORIZED",
                   f"mandate authorizes {m['OID']}, debit is from {d.originator_id}")
        if d.mandate_id and d.mandate_id != m["MID"]:
            r.fail("MANDATE_ID_MISMATCH", f"message says {d.mandate_id}, signed {m['MID']}")
        if m["MID"] in self.revoked:
            r.fail("MANDATE_REVOKED", f"payer revoked {m['MID']}")
        if d.effective_date < date.fromisoformat(m["FROM"]):
            r.fail("MANDATE_NOT_YET_VALID", f"valid from {m['FROM']}")
        if d.effective_date > date.fromisoformat(m["TO"]):
            r.fail("MANDATE_EXPIRED", f"expired {m['TO']}")
        return m

    # -- 3 & 4: the originator's signed entry ------------------------------
    def _check_entry(self, d: RailDebit, m: dict, r: FilterResult) -> None:
        if not d.entry_text:
            r.findings.append(Finding("ENTRY_SIGNATURE_MISSING",
                                      "mandate valid but entry signature absent (stripped in transit?)",
                                      "REVIEW"))
            self._check_limit(d.amount_cents, m, r)
            return
        try:
            e = verify_record(ENTRY, d.entry_text, public_key_from_b32(m["OPK"]))
        except PayloadError as err:
            r.fail(err.code, err.detail + " (key from mandate OPK)")
            return

        expected = {
            "TYP": "DR", "OID": d.originator_id, "RT": d.routing, "ACCT": d.account,
            "AMT": amount_str(d.amount_cents), "EDT": d.effective_date.isoformat(),
            "ID": d.entry_id, "MH": mandate_hash(r.mandate_text),
        }
        codes = {"AMT": "AMOUNT_MISMATCH", "EDT": "DATE_MISMATCH", "ID": "ENTRY_ID_MISMATCH",
                 "MH": "MANDATE_HASH_MISMATCH"}
        for k, v in expected.items():
            if e[k] != v:
                r.fail(codes.get(k, f"{k}_MISMATCH"), f"signed {k}={e[k]}, message has {v}")
        self._check_limit(parse_amount(e["AMT"]), m, r)

    @staticmethod
    def _check_limit(cents: int, m: dict, r: FilterResult) -> None:
        if cents > parse_amount(m["MAX"]):
            r.fail("EXCEEDS_MANDATE_LIMIT", f"${amount_str(cents)} > mandate max ${m['MAX']}")

    # -- 5: replay and frequency -------------------------------------------
    def _check_history(self, d: RailDebit, m: dict, r: FilterResult) -> None:
        if (d.originator_id, d.entry_id) in self.ledger.seen_ids:
            r.fail("DUPLICATE_ENTRY", f"entry {d.entry_id} already accepted")
            return
        prior = self.ledger.collections.get(m["MID"], [])
        eff = d.effective_date
        same_period = {
            "ONCE": lambda p: True,
            "MNTH": lambda p: (p.year, p.month) == (eff.year, eff.month),
            "WEEK": lambda p: p.isocalendar()[:2] == eff.isocalendar()[:2],
            "ADHC": lambda p: False,
        }[m["FRQ"]]
        if any(same_period(p) for p in prior):
            r.fail("FREQUENCY_EXCEEDED", f"{m['FRQ']} mandate already collected this period")
