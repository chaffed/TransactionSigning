"""CLI: python -m checksign <command> ..."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import date
from pathlib import Path

from .keys import Keyring, generate_private_key, load_private_key, save_private_key
from .payload import CheckData, PayloadError, sign, verify
from .qr import decode_qrs
from .render import Issuer, render_front
from .verify import IssueRecord, customer_review, export_presented_items, positive_pay, \
    read_issue_file, write_issue_file
from .x937 import read_icl


def cmd_keygen(a):
    key = generate_private_key()
    save_private_key(key, a.private_out)
    kr = Keyring.load(a.keyring) if Path(a.keyring).exists() else Keyring()
    kr.add(a.kid, key.public_key(), owner=a.owner)
    kr.save(a.keyring)
    print(f"wrote {a.private_out} and enrolled {a.kid} in {a.keyring}")


def cmd_issue(a):
    """Issue checks from a CSV: serial,amount,issue_date,payee"""
    key = load_private_key(a.key)
    issuer = Issuer(a.issuer_name, a.issuer_address, a.bank_name, a.bank_address)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    records = []
    with open(a.checks, newline="") as f:
        for row in csv.DictReader(f):
            dollars, cents = row["amount"].split(".")
            c = CheckData(a.routing, a.account, row["serial"], int(dollars) * 100 + int(cents),
                          date.fromisoformat(row["issue_date"]), row["payee"])
            render_front(issuer, c, sign(key, a.kid, c)).save(out / f"{c.serial}_front.png")
            records.append(IssueRecord(c.routing, c.account, c.serial, c.amount_cents,
                                       c.issue_date, c.payee))
    write_issue_file(out / "issue_file.csv", records)
    print(f"issued {len(records)} checks to {out}/ (+ issue_file.csv)")


def cmd_scan(a):
    """Decode and verify the QR on a check image."""
    from PIL import Image

    kr = Keyring.load(a.keyring)
    texts = decode_qrs(Image.open(a.image))
    if not texts:
        raise SystemExit("no QR found")
    for t in texts:
        print(t)
        try:
            vp = verify(t, kr)
            print(f"  VALID  kid={vp.kid}  {vp.data}")
        except PayloadError as e:
            print(f"  INVALID  {e}")


def _today(a) -> date:
    return date.fromisoformat(a.today) if a.today else date.today()


def cmd_positive_pay(a):
    results = positive_pay(read_icl(a.icl), Keyring.load(a.keyring),
                           read_issue_file(a.issue_file) if a.issue_file else None,
                           today=_today(a), use_ocr=not a.no_ocr)
    for r in results:
        codes = ", ".join(f"{f.code}" for f in r.findings) or "-"
        print(f"{int(r.sequence):>4}  {r.micr_serial:<8} {r.micr_amount_cents / 100:>12,.2f}  "
              f"{r.decision:<9} {codes}")


def cmd_rpp_export(a):
    results = positive_pay(read_icl(a.icl), Keyring.load(a.keyring), None,
                           today=_today(a), use_ocr=not a.no_ocr)
    export_presented_items(a.out, results)
    print(f"wrote {len(results)} presented items to {a.out}")


def cmd_rpp_review(a):
    decisions = customer_review(a.presented, Keyring.load(a.keyring),
                                read_issue_file(a.register), today=_today(a))
    print(json.dumps(decisions, indent=2))


def cmd_demo(a):
    from .demo import run

    run(Path(a.out), use_ocr=not a.no_ocr)


def main(argv=None):
    p = argparse.ArgumentParser(prog="checksign", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("demo", help="run the end-to-end fraud-scenario demo")
    s.add_argument("--out", default="out")
    s.add_argument("--no-ocr", action="store_true")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("keygen", help="generate an Ed25519 signing key and enroll its public key")
    s.add_argument("--kid", required=True)
    s.add_argument("--private-out", required=True)
    s.add_argument("--keyring", required=True)
    s.add_argument("--owner", default="")
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("issue", help="print signed checks from a CSV and write the issue file")
    s.add_argument("--checks", required=True, help="CSV: serial,amount,issue_date,payee")
    s.add_argument("--key", required=True)
    s.add_argument("--kid", required=True)
    s.add_argument("--routing", required=True)
    s.add_argument("--account", required=True)
    s.add_argument("--issuer-name", default="Northbridge Widget Works LLC")
    s.add_argument("--issuer-address", default="77 Foundry Rd, Ashfield, VT 05099")
    s.add_argument("--bank-name", default="Meridian Trust & Savings")
    s.add_argument("--bank-address", default="4400 Harbor Ridge Pkwy, Fictionville, OH 44100")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_issue)

    s = sub.add_parser("scan", help="decode + verify the QR on a check image")
    s.add_argument("image")
    s.add_argument("--keyring", required=True)
    s.set_defaults(fn=cmd_scan)

    for name, fn, help_ in (("positive-pay", cmd_positive_pay, "verify an ICL against keys + issue file"),
                            ("rpp-export", cmd_rpp_export, "bank: export presented items for reverse positive pay")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("--icl", required=True)
        s.add_argument("--keyring", required=True)
        s.add_argument("--today")
        s.add_argument("--no-ocr", action="store_true")
        if name == "positive-pay":
            s.add_argument("--issue-file")
        else:
            s.add_argument("--out", required=True)
        s.set_defaults(fn=fn)

    s = sub.add_parser("rpp-review", help="customer: decide pay/return on presented items")
    s.add_argument("--presented", required=True)
    s.add_argument("--keyring", required=True)
    s.add_argument("--register", required=True)
    s.add_argument("--today")
    s.set_defaults(fn=cmd_rpp_review)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
