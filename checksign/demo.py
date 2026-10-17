"""End-to-end demo: issue signed checks, present genuine + fraudulent items in
an image cash letter, and run Positive Pay and Reverse Positive Pay."""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
from datetime import date, timedelta
from pathlib import Path

from .keys import Keyring, generate_private_key, save_private_key
from .payload import CheckData, sign
from .render import Issuer, render_back, render_front, simulate_capture, to_tiff_g4
from .verify import (
    IssueRecord,
    customer_review,
    export_presented_items,
    positive_pay,
    read_issue_file,
    write_issue_file,
)
from .x937 import IclItem, read_icl, write_icl

KID = "nbw-2026a"
ISSUER = Issuer(
    name="Northbridge Widget Works LLC",
    address="77 Foundry Rd, Ashfield, VT 05099",
    bank_name="Meridian Trust & Savings",
    bank_address="4400 Harbor Ridge Pkwy, Fictionville, OH 44100",
)
ACCOUNT = "4471902385"
BOFD_ROUTING = "021000089"  # fictional depositary bank (fails ABA checksum)


def fictional_routing(prefix8: str) -> str:
    """Complete an 8-digit prefix with a check digit that FAILS the ABA
    checksum, so the number can never collide with a real bank."""
    w = (3, 7, 1, 3, 7, 1, 3, 7)
    good = (10 - sum(int(c) * k for c, k in zip(prefix8, w)) % 10) % 10
    return prefix8 + str((good + 1) % 10)


ROUTING = fictional_routing("04400012")


@dataclass
class Presentment:
    label: str
    expected: str
    check: CheckData  # what the BOFD encodes into the MICR / ICL record
    qr_text: str | None
    printed_payee: str | None = None
    printed_amount_cents: int | None = None


def run(out: Path, *, use_ocr: bool = True) -> list:
    today = date.today()
    out.mkdir(parents=True, exist_ok=True)
    for sub in ("issuer", "bank", "customer", "printed", "captured"):
        (out / sub).mkdir(exist_ok=True)

    # --- Issuer: key generation and enrollment of the public key with the bank
    issuer_key = generate_private_key()
    save_private_key(issuer_key, out / "issuer" / f"{KID}.private.pem")
    keyring = Keyring()
    keyring.add(KID, issuer_key.public_key(), owner=ISSUER.name)
    keyring.save(out / "bank" / "keyring.json")
    keyring.save(out / "customer" / "keyring.json")

    # --- Issuer: print checks with signed QR, and send the issue file
    def chk(serial, cents, payee, days_ago=2):
        return CheckData(ROUTING, ACCOUNT, str(serial), cents, today - timedelta(days=days_ago), payee)

    issued = {
        5001: chk(5001, 125_000, "Riverstone Landscaping LLC"),
        5002: chk(5002, 48_210, "Priya K. Chandran"),
        5003: chk(5003, 9_850, "Golden Hour Bakery"),
        5004: chk(5004, 312_575, "Ferro Industrial Parts Inc."),
        5005: chk(5005, 72_000, "Bluepeak Consulting Group"),
        5006: chk(5006, 15_000, "Linda R. Osei"),
        5007: chk(5007, 260_000, "Acme Widget Supply Co."),
        5008: chk(5008, 41_999, "Marcus D. Whitfield"),
        5009: chk(5009, 22_500, "Sasha M. Novak", days_ago=200),
    }
    qr = {sn: sign(issuer_key, KID, c) for sn, c in issued.items()}
    for sn, c in issued.items():
        render_front(ISSUER, c, qr[sn]).save(out / "printed" / f"{sn}_front.png")

    register = [IssueRecord(c.routing, c.account, c.serial, c.amount_cents, c.issue_date,
                            c.payee, "VOID" if sn == 5008 else "ISSUED")
                for sn, c in issued.items()]
    write_issue_file(out / "customer" / "issue_file.csv", register)

    # --- Fraudster capabilities
    attacker_key = generate_private_key()  # can sign, but isn't enrolled
    forged_5005 = replace(issued[5005], payee="Mallory Q. Fraudster")
    tampered_qr = qr[5005].replace("PAYEE=BLUEPEAK CONSULTING GROUP", "PAYEE=MALLORY Q. FRAUDSTER")
    counterfeit_5006 = replace(issued[5006], amount_cents=1_500_000)
    counterfeit_5011 = replace(issued[5002], serial="5011")

    items = [
        Presentment("Genuine check", "PAY", issued[5001], qr[5001]),
        Presentment("Genuine check", "PAY", issued[5002], qr[5002]),
        Presentment("Raised amount ($98.50 -> $9,850.00)", "EXCEPTION",
                    replace(issued[5003], amount_cents=985_000), qr[5003],
                    printed_amount_cents=985_000),
        Presentment("Washed payee, QR left intact", "EXCEPTION",
                    issued[5004], qr[5004], printed_payee="Mallory Q. Fraudster"),
        Presentment("QR text edited to new payee", "EXCEPTION",
                    forged_5005, tampered_qr, printed_payee=forged_5005.payee),
        Presentment("Counterfeit, QR signed by attacker key", "EXCEPTION",
                    counterfeit_5006, sign(attacker_key, KID, counterfeit_5006)),
        Presentment("Counterfeit #5011 with QR copied from #5002", "EXCEPTION",
                    counterfeit_5011, qr[5002]),
        Presentment("Duplicate presentment of #5001", "EXCEPTION", issued[5001], qr[5001]),
        Presentment("Counterfeit with no QR", "EXCEPTION", issued[5007], None),
        Presentment("Check voided by issuer", "EXCEPTION", issued[5008], qr[5008]),
        Presentment("Stale-dated (200 days)", "EXCEPTION", issued[5009], qr[5009]),
        Presentment("Counterfeit, unenrolled KID", "EXCEPTION", chk(5010, 50_000, "Cash"),
                    sign(attacker_key, "nbw-2027x", chk(5010, 50_000, "Cash"))),
    ]

    # --- BOFD: capture items and build the image cash letter
    icl_items = []
    for seq, p in enumerate(items, start=1):
        face = render_front(ISSUER, p.check, p.qr_text,
                            printed_payee=p.printed_payee,
                            printed_amount_cents=p.printed_amount_cents)
        captured = simulate_capture(face, seed=seq)
        captured.save(out / "captured" / f"{seq:02d}_{p.check.serial}_front.png")
        icl_items.append(IclItem(
            routing=p.check.routing, account=p.check.account, serial=p.check.serial,
            amount_cents=p.check.amount_cents, sequence=f"{seq:015d}",
            front_tiff=to_tiff_g4(captured),
            back_tiff=to_tiff_g4(simulate_capture(render_back(), seed=1000 + seq)),
        ))
    icl_path = out / "bank" / "presentment.x937"
    write_icl(icl_path, icl_items, origin_routing=BOFD_ROUTING, destination_routing=ROUTING)

    # --- Paying bank: Positive Pay over the received cash letter
    received = read_icl(icl_path)
    bank_keyring = Keyring.load(out / "bank" / "keyring.json")
    issue_file = read_issue_file(out / "customer" / "issue_file.csv")
    results = positive_pay(received, bank_keyring, issue_file, today=today, use_ocr=use_ocr)

    with open(out / "bank" / "positive_pay_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["seq", "serial", "micr_amount", "decision", "findings", "qr_text"])
        for r in results:
            w.writerow([int(r.sequence), r.micr_serial, f"{r.micr_amount_cents / 100:.2f}",
                        r.decision, "; ".join(f"{x.code}: {x.detail}" for x in r.findings),
                        r.qr_text or ""])

    # --- Reverse Positive Pay: bank exports, customer decides independently
    rpp_bank = positive_pay(received, bank_keyring, None, today=today, use_ocr=use_ocr)
    export_presented_items(out / "bank" / "presented_items.json", rpp_bank)
    decisions = customer_review(out / "bank" / "presented_items.json",
                                Keyring.load(out / "customer" / "keyring.json"),
                                read_issue_file(out / "customer" / "issue_file.csv"),
                                today=today)
    with open(out / "customer" / "rpp_decisions.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(decisions[0]))
        w.writeheader()
        w.writerows(decisions)

    _report(items, results, decisions)
    print(f"\nArtifacts written to {out.resolve()}")
    return results


def _report(items, results, decisions) -> None:
    print(f"{'#':>2}  {'Serial':<6} {'Scenario':<44} {'PosPay':<9} {'RevPP':<7} OK  Findings")
    print("-" * 130)
    mismatches = 0
    for i, (p, r, d) in enumerate(zip(items, results, decisions), start=1):
        ok = r.decision == p.expected and (d["decision"] == "PAY") == (p.expected == "PAY")
        mismatches += not ok
        codes = ", ".join(f.code for f in r.findings if f.severity == "FAIL") or "-"
        print(f"{i:>2}  {r.micr_serial:<6} {p.label:<44} {r.decision:<9} {d['decision']:<7} "
              f"{'✓' if ok else '✗'}   {codes}")
    print("-" * 130)
    print(f"{len(items) - mismatches}/{len(items)} scenarios produced the expected decision")
