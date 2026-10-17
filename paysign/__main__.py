"""CLI: python -m paysign <command> ..."""

from __future__ import annotations

import argparse
from pathlib import Path

from checksign.keys import Keyring

from .filter import DebitFilter
from .iso import parse_pacs003
from .nacha import read_ach


def cmd_demo(a):
    from .demo import run

    run(Path(a.out))


def cmd_filter(a):
    debits = read_ach(a.file) if a.rail == "ach" else parse_pacs003(Path(a.file).read_bytes())
    on_file = [ln for ln in Path(a.mandates_on_file).read_text().splitlines() if ln.strip()] if a.mandates_on_file else []
    f = DebitFilter(Keyring.load(a.keyring), revoked_mandates=set(a.revoked or []),
                    mandates_on_file=on_file)
    rail = "ACH" if a.rail == "ach" else "ISO"
    for d in debits:
        r = f.check(d)
        codes = ", ".join(x.code for x in r.findings) or "-"
        print(f"{d.entry_id:<16} {d.originator_id:<11} {d.amount_cents / 100:>12,.2f}  "
              f"{r.decision:<7} {r.return_code(rail):<5} {codes}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="paysign", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("demo", help="run ACH + ISO 20022 debit scenarios")
    s.add_argument("--out", default="out/paysign")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("filter", help="run the paying-bank debit filter over a received file")
    s.add_argument("rail", choices=["ach", "pacs003"])
    s.add_argument("file")
    s.add_argument("--keyring", required=True, help="payer keys enrolled at this bank")
    s.add_argument("--revoked", nargs="*", help="revoked mandate ids")
    s.add_argument("--mandates-on-file", help="file of signed MD1 mandates, one per line")
    s.set_defaults(fn=cmd_filter)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
