"""End-to-end demo: a payer signs mandates, originators sign debit entries,
the same debits travel as ACH CTX and as ISO 20022 pain.008 -> pacs.003, and
the paying bank's debit filter decides each one on both rails."""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
from datetime import date, timedelta
from pathlib import Path

from checksign.keys import Keyring, generate_private_key

from .filter import DebitFilter
from .iso import build_pain008, pain008_to_pacs003, parse_pacs003
from .model import RailDebit
from .nacha import read_ach, write_ach
from .payload import (ENTRY, MANDATE, amount_str, mandate_hash, parse_unverified, public_key_b32,
                      sign_record)

PAYER_RT, PAYER_ACCT, PAYER_NAME = "044000122", "4471902385", "NORTHBRIDGE WIDGET WORKS LLC"
OTHER_ACCT = "9988776655"  # another customer of the same bank
ODFI_RT = "021000089"  # originators' bank (fictional; fails ABA checksum)
CREDITOR_ACCT = "7700112233"


@dataclass
class Originator:
    oid: str
    name: str
    kid: str

    def __post_init__(self):
        self.key = generate_private_key()


@dataclass
class Scenario:
    label: str
    expected: str  # ACCEPT | RETURN | REVIEW
    debit: RailDebit
    strip_entry_signature: bool = False


def sign_mandate(payer_key, payer_kid, mid, orig: Originator, *, max_cents, frq, start, end,
                 rt=PAYER_RT, acct=PAYER_ACCT) -> str:
    return sign_record(MANDATE, payer_key, {
        "KID": payer_kid, "MID": mid, "OID": orig.oid, "ONM": orig.name,
        "OPK": public_key_b32(orig.key.public_key()), "RT": rt, "ACCT": acct,
        "MAX": amount_str(max_cents), "FRQ": frq, "FROM": start.isoformat(), "TO": end.isoformat(),
    })


def make_debit(orig: Originator, mandate: str | None, cents: int, eff: date, entry_id: str,
               *, signer=None, mid: str | None = None) -> RailDebit:
    entry = None
    if mandate is not None:
        mid = mid or parse_unverified(MANDATE, mandate)["MID"]
        entry = sign_record(ENTRY, signer or orig.key, {
            "KID": orig.kid, "TYP": "DR", "OID": orig.oid, "RT": PAYER_RT, "ACCT": PAYER_ACCT,
            "AMT": amount_str(cents), "EDT": eff.isoformat(), "ID": entry_id,
            "MH": mandate_hash(mandate),
        })
    return RailDebit(orig.oid, orig.name, PAYER_RT, PAYER_ACCT, PAYER_NAME, cents, eff, entry_id,
                     mandate_id=mid, mandate_text=mandate, entry_text=entry)


def build_scenarios(today: date):
    eff = today + timedelta(days=1)

    # Payer (account holder) and another customer, both enrolled at the RDFI
    payer_key, payer_kid = generate_private_key(), "NBW-PAY-1"
    other_key, other_kid = generate_private_key(), "GHB-PAY-1"
    keyring = Keyring()
    keyring.add(payer_kid, payer_key.public_key(), PAYER_NAME, [f"{PAYER_RT}:{PAYER_ACCT}"])
    keyring.add(other_kid, other_key.public_key(), "GOLDEN HOUR BAKERY", [f"{PAYER_RT}:{OTHER_ACCT}"])

    ferro = Originator("1987654321", "FERRO INDUSTRIAL PARTS INC", "FERRO-2026A")
    bluepeak = Originator("1555000111", "BLUEPEAK CONSULTING GROUP", "BLUEPEAK-1")
    river = Originator("1222333444", "RIVERSTONE LANDSCAPING LLC", "RSL-1")
    acme = Originator("1999888777", "ACME WIDGET SUPPLY CO", "ACME-1")
    attacker_key = generate_private_key()

    window = dict(start=today - timedelta(days=30), end=today + timedelta(days=335))
    m_ferro = sign_mandate(payer_key, payer_kid, "FERRO-NBW-0001", ferro,
                           max_cents=500_000, frq="MNTH", **window)
    m_blue = sign_mandate(payer_key, payer_kid, "BLUE-NBW-0001", bluepeak,
                          max_cents=200_000, frq="ADHC", **window)
    m_river = sign_mandate(payer_key, payer_kid, "RIVER-NBW-0001", river, max_cents=100_000,
                           frq="MNTH", start=today - timedelta(days=400), end=today - timedelta(days=35))
    m_forged = sign_mandate(other_key, other_kid, "ACME-NBW-0001", acme,
                            max_cents=10_000_000, frq="ADHC", **window)
    revoked = {"BLUE-NBW-0001"}
    on_file = [m_ferro, m_blue, m_river]  # mandates the payer registered with its bank

    good = make_debit(ferro, m_ferro, 312_575, eff, "FERRO-0001", mid="FERRO-NBW-0001")
    scenarios = [
        Scenario("Amount altered in transit ($3,125.75 -> $31,257.50)", "RETURN",
                 replace(good, entry_id="FERRO-0002", amount_cents=3_125_750,
                         entry_text=make_debit(ferro, m_ferro, 312_575, eff, "FERRO-0002").entry_text)),
        Scenario("Originator signs debit over mandate max", "RETURN",
                 make_debit(ferro, m_ferro, 750_000, eff, "FERRO-0003", mid="FERRO-NBW-0001")),
        Scenario("Valid monthly debit within mandate", "ACCEPT", good),
        Scenario("Replay of accepted entry FERRO-0001", "RETURN", good),
        Scenario("Second debit in same month (MNTH mandate)", "RETURN",
                 make_debit(ferro, m_ferro, 100_000, eff, "FERRO-0004", mid="FERRO-NBW-0001")),
        Scenario("Spoofed originator: real mandate, attacker-signed entry", "RETURN",
                 make_debit(ferro, m_ferro, 480_000, eff, "FERRO-0005", signer=attacker_key)),
        Scenario("Mandate for this account signed by another customer", "RETURN",
                 make_debit(acme, m_forged, 2_500_000, eff, "ACME-0001")),
        Scenario("Unauthorized debit with no mandate", "RETURN",
                 make_debit(acme, None, 99_000, eff, "ACME-0002")),
        Scenario("Mandate revoked by payer", "RETURN",
                 make_debit(bluepeak, m_blue, 50_000, eff, "BLUE-0001")),
        Scenario("Mandate expired", "RETURN", make_debit(river, m_river, 25_000, eff, "RIVER-0001")),
        Scenario("Entry re-attached to a looser mandate (hash binding)", "RETURN",
                 replace(make_debit(ferro, m_ferro, 120_000, eff + timedelta(days=31), "FERRO-0006"),
                         mandate_id="FERRO-NBW-0002",
                         mandate_text=sign_mandate(payer_key, payer_kid, "FERRO-NBW-0002", ferro,
                                                   max_cents=900_000, frq="ADHC", **window))),
        Scenario("Signed data stripped in transit", "REVIEW",
                 make_debit(ferro, m_ferro, 200_000, eff + timedelta(days=31), "FERRO-0007",
                            mid="FERRO-NBW-0001"), strip_entry_signature=True),
    ]
    return scenarios, keyring, revoked, on_file


def run(out: Path, today: date | None = None) -> dict:
    today = today or date.today()
    out.mkdir(parents=True, exist_ok=True)
    scenarios, keyring, revoked, on_file = build_scenarios(today)
    keyring.save(out / "rdfi_payer_keyring.json")
    (out / "rdfi_mandates_on_file.txt").write_text("\n".join(on_file) + "\n")
    debits = [s.debit for s in scenarios]
    stripped = {s.debit.entry_id for s in scenarios if s.strip_entry_signature}

    # ACH: each scenario in its own file, in order, so the replay arrives after the original
    ach_filter = DebitFilter(keyring, revoked_mandates=revoked, mandates_on_file=on_file)
    ach_results = []
    for i, d in enumerate(debits, start=1):
        path = out / "ach" / f"{i:02d}_{d.entry_id}.ach"
        path.parent.mkdir(exist_ok=True)
        write_ach(path, [d], odfi_routing=ODFI_RT, rdfi_routing=PAYER_RT,
                  drop_addenda=stripped & {d.entry_id})
        (received,) = read_ach(path)
        ach_results.append(ach_filter.check(received))

    # ISO 20022: pain.008 from originator, pacs.003 forwarded by creditor agent
    iso_filter = DebitFilter(keyring, revoked_mandates=revoked, mandates_on_file=on_file)
    iso_results = []
    for i, d in enumerate(debits, start=1):
        base = out / "iso" / f"{i:02d}_{d.entry_id}"
        base.parent.mkdir(exist_ok=True)
        pain = build_pain008([d], creditor_routing=ODFI_RT, creditor_account=CREDITOR_ACCT,
                             msg_id=f"PAIN-{i:04d}")
        base.with_suffix(".pain008.xml").write_bytes(pain)
        pacs = pain008_to_pacs003(pain, creditor_routing=ODFI_RT, creditor_account=CREDITOR_ACCT,
                                  msg_id=f"PACS-{i:04d}", settlement_date=d.effective_date,
                                  drop_supplementary=stripped & {d.entry_id})
        base.with_suffix(".pacs003.xml").write_bytes(pacs)
        (received,) = parse_pacs003(pacs)
        iso_results.append(iso_filter.check(received))

    with open(out / "filter_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n", "scenario", "expected", "ach_decision", "ach_return", "iso_decision",
                    "iso_return", "findings"])
        for i, (s, a, b) in enumerate(zip(scenarios, ach_results, iso_results), start=1):
            w.writerow([i, s.label, s.expected, a.decision, a.return_code("ACH"), b.decision,
                        b.return_code("ISO"), "; ".join(f"{x.code}: {x.detail}" for x in a.findings)])

    _report(scenarios, ach_results, iso_results)
    print(f"\nArtifacts written to {out.resolve()}")
    return {"ach": ach_results, "iso": iso_results, "scenarios": scenarios}


def _report(scenarios, ach, iso) -> None:
    print(f"{'#':>2}  {'Scenario':<56} {'ACH':<13} {'ISO 20022':<13} OK  Findings")
    print("-" * 140)
    bad = 0
    for i, (s, a, b) in enumerate(zip(scenarios, ach, iso), start=1):
        ok = a.decision == b.decision == s.expected and [f.code for f in a.findings] == \
            [f.code for f in b.findings]
        bad += not ok
        codes = ", ".join(f.code for f in a.findings) or "-"
        ach_col = f"{a.decision} {a.return_code('ACH')}".strip()
        iso_col = f"{b.decision} {b.return_code('ISO')}".strip()
        print(f"{i:>2}  {s.label:<56} {ach_col:<13} {iso_col:<13} {'✓' if ok else '✗'}   {codes}")
    print("-" * 140)
    print(f"{len(scenarios) - bad}/{len(scenarios)} scenarios produced the expected decision on both rails")
