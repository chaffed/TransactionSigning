"""Minimal X9.37-style image cash letter (ICL) writer/reader.

Record layout follows DSTU X9.37-2003: each record is a 4-byte big-endian
length prefix followed by EBCDIC (cp037) fixed-width fields; type 52 carries
binary TIFF image data after its fixed portion. Only what this PoC needs is
populated -- this is NOT a certified X9.100-187 implementation and should
not be fed to a real clearing system.

Structure written:
  01 File Header
    10 Cash Letter Header
      20 Bundle Header
        25 Check Detail          (MICR: aux on-us/serial, routing, on-us/account, amount)
          50 Image View Detail   (front)  52 Image View Data (front TIFF G4)
          50 Image View Detail   (back)   52 Image View Data (back TIFF G4)
        ...
      70 Bundle Control
    90 Cash Letter Control
  99 File Control
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ENC = "cp037"


@dataclass
class IclItem:
    """One presented item as the paying bank sees it in the cash letter."""

    routing: str  # 9 digits, as encoded in the MICR transit field
    account: str  # MICR on-us field (account portion)
    serial: str  # MICR auxiliary on-us (check serial)
    amount_cents: int  # MICR amount field, encoded by the BOFD
    sequence: str  # ECE institution item sequence number
    front_tiff: bytes
    back_tiff: bytes


def _an(value: str, size: int) -> str:
    v = str(value)
    if len(v) > size:
        raise ValueError(f"{v!r} exceeds field size {size}")
    return v.ljust(size)


def _n(value: int | str, size: int) -> str:
    v = str(value)
    if len(v) > size or not v.isdigit():
        raise ValueError(f"{v!r} is not a {size}-digit numeric field")
    return v.zfill(size)


def _record(*fields: str, expected: int = 80) -> bytes:
    body = "".join(fields)
    if len(body) != expected:
        raise AssertionError(f"record type {body[:2]} is {len(body)} bytes, expected {expected}")
    return body.encode(ENC)


def _framed(rec: bytes) -> bytes:
    return struct.pack(">I", len(rec)) + rec


def write_icl(
    path: str | Path,
    items: list[IclItem],
    *,
    origin_routing: str,
    destination_routing: str,
    origin_name: str = "BOFD SIM BANK",
    destination_name: str = "PAYING SIM BANK",
    created: datetime | None = None,
) -> None:
    now = created or datetime.now()
    d8, t4 = now.strftime("%Y%m%d"), now.strftime("%H%M")
    total = sum(i.amount_cents for i in items)
    out: list[bytes] = []

    out.append(_record(
        "01", "03", "T", _n(destination_routing, 9), _n(origin_routing, 9), d8, t4, "N",
        _an(destination_name, 18), _an(origin_name, 18), "A", "US", _an("", 4), " ",
    ))
    out.append(_record(
        "10", "01", _n(destination_routing, 9), _n(origin_routing, 9), d8, d8, t4, "I", "G",
        _an("CL000001", 8), _an("PoC Operator", 14), _n("5555550100", 10), " ", _an("", 2), " ",
    ))
    out.append(_record(
        "20", "01", _n(destination_routing, 9), _n(origin_routing, 9), d8, d8,
        _an("B000000001", 10), _n(1, 4), "01", _n(origin_routing, 9), _an("", 5), _an("", 12),
    ))
    for item in items:
        routing = item.routing
        out.append(_record(
            "25",
            _an(item.serial, 15),          # auxiliary on-us (serial)
            " ",                           # external processing code
            routing[:8], routing[8],       # payor bank routing + check digit
            _an(item.account + "/", 20),   # on-us; '/' represents the on-us symbol
            _n(item.amount_cents, 10),     # item amount, in cents
            _n(item.sequence, 15),         # ECE institution item sequence number
            "G", " ", "1", "Y", "02", "0", " ",
        ))
        for side, tiff in (("0", item.front_tiff), ("1", item.back_tiff)):
            out.append(_record(
                "50", "1", _n(origin_routing, 9), d8, "00", "00", _n(len(tiff), 7), side, "00",
                "0", "  ", _n(0, 5), _n(0, 7), _n(0, 7), "0", _an("", 8), _an("", 15),
            ))
            fixed = _record(
                "52", _n(origin_routing, 9), d8, "01", _n(item.sequence, 15),
                _an("", 16), _an("", 16), _an("", 16), "0", _n(0, 4), _n(0, 4), _n(0, 4), _n(0, 4),
                _n(0, 4),               # length of image reference key (none)
                _n(0, 5),               # length of digital signature (none)
                _n(len(tiff), 7),       # length of image data
                expected=117,
            )
            out.append(fixed + tiff)
    out.append(_record(
        "70", _n(len(items), 4), _n(total, 12), _n(total, 12), _n(2 * len(items), 5),
        _an("", 20), _an("", 25),
    ))
    out.append(_record(
        "90", _n(1, 6), _n(len(items), 8), _n(total, 14), _n(2 * len(items), 9),
        _an(origin_name, 18), d8, _an("", 15),
    ))
    record_count = len(out) + 1
    out.append(_record(
        "99", _n(1, 6), _n(record_count, 8), _n(len(items), 8), _n(total, 16),
        _an("PoC Operator", 14), _n("5555550100", 10), _an("", 16),
    ))
    Path(path).write_bytes(b"".join(_framed(r) for r in out))


def _iter_records(data: bytes):
    pos = 0
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos : pos + 4])
        rec = data[pos + 4 : pos + 4 + length]
        if len(rec) != length:
            raise ValueError(f"truncated record at offset {pos}")
        yield rec
        pos += 4 + length


def read_icl(path: str | Path) -> list[IclItem]:
    items: list[dict] = []
    current: dict | None = None
    pending_side: str | None = None

    for rec in _iter_records(Path(path).read_bytes()):
        rtype = rec[:2].decode(ENC)
        if rtype == "25":
            f = rec.decode(ENC)
            onus = f[27:47].strip()
            current = {
                "serial": f[2:17].strip(),
                "routing": f[18:26] + f[26],
                "account": onus.split("/")[0],
                "amount_cents": int(f[47:57]),
                "sequence": f[57:72],
                "front_tiff": b"",
                "back_tiff": b"",
            }
            items.append(current)
        elif rtype == "50" and current is not None:
            pending_side = rec[:80].decode(ENC)[31]  # view side indicator
        elif rtype == "52" and current is not None:
            # variable-length fields: image reference key, then digital signature
            pos = 101
            ref_len = int(rec[pos : pos + 4].decode(ENC))
            pos += 4 + ref_len
            sig_len = int(rec[pos : pos + 5].decode(ENC))
            pos += 5 + sig_len
            img_len = int(rec[pos : pos + 7].decode(ENC))
            pos += 7
            image = rec[pos : pos + img_len]
            current["front_tiff" if pending_side == "0" else "back_tiff"] = image

    return [IclItem(**i) for i in items]
