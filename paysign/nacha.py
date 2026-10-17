"""NACHA ACH file (CTX debits) with signed records in the X12 820 addenda.

File layout: 94-character records, blocked to multiples of 10 with '9' fill.
  1 File Header
    5 Batch Header (one per originator + effective date, SEC = CTX)
      6 Entry Detail (transaction code 27 = checking debit)
        7 Addenda type 05 x N  -- 80 chars each, together one X12 820 stream
    8 Batch Control
  9 File Control

The 820 carried in the addenda (minimal, illustrative -- no ISA/GS envelope):
  ST*820*0001\\ BPR*C*<amt>*D*ACH*CTX\\ TRN*1*<entry id>*<originator id>\\
  REF*ZZ*MD1-01-05*<80 chars of mandate>\\ ... REF*ZZ*PE1-01-03*<entry chunk>\\
  RMR*...\\ SE*<n>*0001\\

Signed records are split into 80-char chunks (the X12 REF03 maximum) with
REF02 = "<tag>-<part>-<total>" so the receiver can reassemble and detect
missing parts. Element separator '*', segment terminator '\\'; neither can
appear in a signed record's alphabet.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

from .model import RailDebit
from .payload import amount_str

ELEM, SEG = "*", "\\"
CHUNK = 80
DEBIT_CODES = {"27", "37"}  # checking / savings debit


def _an(v: str, n: int) -> str:
    v = str(v)
    if len(v) > n:
        raise ValueError(f"{v!r} longer than {n}")
    return v.ljust(n)


def _n(v: int | str, n: int) -> str:
    v = str(v)
    if len(v) > n or not v.isdigit():
        raise ValueError(f"{v!r} is not a {n}-digit number")
    return v.zfill(n)


def _rec(*parts: str) -> str:
    r = "".join(parts)
    if len(r) != 94:
        raise AssertionError(f"record type {r[0]} is {len(r)} chars, expected 94")
    return r


# ---------------------------------------------------------------------------
# X12 820 payload inside the addenda
# ---------------------------------------------------------------------------

def _ref_chunks(tag: str, text: str) -> list[str]:
    parts = [text[i : i + CHUNK] for i in range(0, len(text), CHUNK)]
    return [ELEM.join(["REF", "ZZ", f"{tag}-{i:02d}-{len(parts):02d}", p])
            for i, p in enumerate(parts, start=1)]


def build_820(d: RailDebit) -> str:
    segs = [
        ELEM.join(["ST", "820", "0001"]),
        ELEM.join(["BPR", "C", amount_str(d.amount_cents), "D", "ACH", "CTX"]),
        ELEM.join(["TRN", "1", d.entry_id, d.originator_id]),
    ]
    if d.mandate_text:
        segs += _ref_chunks("MD1", d.mandate_text)
    if d.entry_text:
        segs += _ref_chunks("PE1", d.entry_text)
    segs.append(ELEM.join(["RMR", "IV", f"INV-{d.entry_id}", "", amount_str(d.amount_cents)]))
    segs.append(ELEM.join(["SE", str(len(segs) + 1), "0001"]))
    return SEG.join(segs) + SEG


def extract_signed(x12: str) -> dict[str, str]:
    """Reassemble REF*ZZ chunks into {'MD1': text, 'PE1': text}. Records with
    missing or out-of-range parts are dropped (they would not verify anyway)."""
    parts: dict[str, dict[int, str]] = defaultdict(dict)
    totals: dict[str, int] = {}
    for seg in x12.split(SEG):
        el = seg.split(ELEM)
        if len(el) == 4 and el[0] == "REF" and el[1] == "ZZ" and el[2].count("-") == 2:
            tag, part, total = el[2].split("-")
            parts[tag][int(part)] = el[3]
            totals[tag] = int(total)
    out = {}
    for tag, chunks in parts.items():
        if sorted(chunks) == list(range(1, totals[tag] + 1)):
            out[tag] = "".join(chunks[i] for i in sorted(chunks))
    return out


# ---------------------------------------------------------------------------
# File writer
# ---------------------------------------------------------------------------

def write_ach(
    path: str | Path,
    debits: list[RailDebit],
    *,
    odfi_routing: str,
    rdfi_routing: str,
    odfi_name: str = "ODFI SIM BANK",
    rdfi_name: str = "RDFI SIM BANK",
    created: datetime | None = None,
    drop_addenda: set[str] | None = None,
) -> None:
    """drop_addenda: entry ids whose addenda are stripped in transit (simulates
    an ODFI/RDFI system that discards CTX payment-related information)."""
    now = created or datetime.now()
    drop_addenda = drop_addenda or set()
    lines = [_rec(
        "1", "01", " " + rdfi_routing, " " + odfi_routing, now.strftime("%y%m%d"),
        now.strftime("%H%M"), "A", "094", "10", "1", _an(rdfi_name, 23), _an(odfi_name, 23),
        _an("", 8),
    )]

    batches: dict[tuple, list[RailDebit]] = defaultdict(list)
    for d in debits:
        batches[(d.originator_id, d.originator_name, d.effective_date)].append(d)

    total_entries = total_hash = total_debit = 0
    trace = 0
    for bno, ((oid, oname, eff), items) in enumerate(batches.items(), start=1):
        lines.append(_rec(
            "5", "225", _an(oname[:16], 16), _an("", 20), _an(oid, 10), "CTX",
            _an("INVOICES", 10), _an("", 6), eff.strftime("%y%m%d"), "   ", "1",
            odfi_routing[:8], _n(bno, 7),
        ))
        count = bhash = bdebit = 0
        for d in items:
            trace += 1
            trace_no = odfi_routing[:8] + _n(trace, 7)
            x12 = "" if d.entry_id in drop_addenda else build_820(d)
            addenda = [x12[i : i + CHUNK] for i in range(0, len(x12), CHUNK)]
            lines.append(_rec(
                "6", "27", d.routing[:8], d.routing[8], _an(d.account, 17),
                _n(d.amount_cents, 10), _an(d.entry_id, 15), _n(len(addenda), 4),
                _an(d.payer_name[:16], 16), "  ", "  ", "1" if addenda else "0", trace_no,
            ))
            for seq, text in enumerate(addenda, start=1):
                lines.append(_rec("7", "05", _an(text, 80), _n(seq, 4), trace_no[-7:]))
            count += 1 + len(addenda)
            bhash += int(d.routing[:8])
            bdebit += d.amount_cents
        lines.append(_rec(
            "8", "225", _n(count, 6), _n(bhash % 10**10, 10), _n(bdebit, 12), _n(0, 12),
            _an(oid, 10), _an("", 19), _an("", 6), odfi_routing[:8], _n(bno, 7),
        ))
        total_entries += count
        total_hash += bhash
        total_debit += bdebit

    n_records = len(lines) + 1
    blocks = -(-n_records // 10)
    lines.append(_rec(
        "9", _n(len(batches), 6), _n(blocks, 6), _n(total_entries, 8),
        _n(total_hash % 10**10, 10), _n(total_debit, 12), _n(0, 12), _an("", 39),
    ))
    lines += ["9" * 94] * (blocks * 10 - len(lines))
    Path(path).write_text("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# File reader (paying bank side)
# ---------------------------------------------------------------------------

def read_ach(path: str | Path) -> list[RailDebit]:
    out: list[RailDebit] = []
    batch: dict = {}
    current: RailDebit | None = None
    addenda: list[str] = []

    def flush():
        nonlocal current, addenda
        if current is not None:
            signed = extract_signed("".join(addenda).rstrip())
            current.mandate_text = signed.get("MD1")
            current.entry_text = signed.get("PE1")
            out.append(current)
        current, addenda = None, []

    for line in Path(path).read_text().splitlines():
        kind = line[:1]
        if kind == "5":
            flush()
            yy = line[69:75]
            batch = {
                "originator_name": line[4:20].strip(),
                "originator_id": line[40:50].strip(),
                "effective_date": date(2000 + int(yy[:2]), int(yy[2:4]), int(yy[4:6])),
            }
        elif kind == "6":
            flush()
            if line[1:3] not in DEBIT_CODES:
                continue
            current = RailDebit(
                routing=line[3:12], account=line[12:29].strip(), amount_cents=int(line[29:39]),
                entry_id=line[39:54].strip(), payer_name=line[58:74].strip(), **batch,
            )
        elif kind == "7" and current is not None:
            addenda.append(line[3:83])
        elif kind in "89":
            flush()
    flush()
    return out
