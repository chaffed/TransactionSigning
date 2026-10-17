from datetime import date, timedelta

import pytest

from checksign.keys import Keyring, generate_private_key
from checksign.payload import PayloadError
from paysign.demo import run
from paysign.iso import build_pain008, pain008_to_pacs003, parse_pacs003
from paysign.model import RailDebit
from paysign.nacha import build_820, extract_signed, read_ach, write_ach
from paysign.payload import (ENTRY, MANDATE, amount_str, mandate_hash, public_key_b32,
                             sign_record, verify_record)

TODAY = date(2026, 10, 17)


@pytest.fixture
def signed():
    payer, orig = generate_private_key(), generate_private_key()
    mandate = sign_record(MANDATE, payer, {
        "KID": "PAYER-1", "MID": "M-1", "OID": "1987654321", "ONM": "FERRO INDUSTRIAL PARTS INC",
        "OPK": public_key_b32(orig.public_key()), "RT": "044000122", "ACCT": "4471902385",
        "MAX": "5000.00", "FRQ": "MNTH", "FROM": "2026-01-01", "TO": "2026-12-31",
    })
    entry = sign_record(ENTRY, orig, {
        "KID": "ORIG-1", "TYP": "DR", "OID": "1987654321", "RT": "044000122",
        "ACCT": "4471902385", "AMT": "3125.75", "EDT": "2026-10-18", "ID": "FERRO-0001",
        "MH": mandate_hash(mandate),
    })
    debit = RailDebit("1987654321", "FERRO INDUSTRIAL PARTS INC", "044000122", "4471902385",
                      "NORTHBRIDGE WIDGET WORKS LLC", 312_575, date(2026, 10, 18), "FERRO-0001",
                      "M-1", mandate, entry)
    return payer, orig, mandate, entry, debit


def test_records_use_x12_safe_uppercase_alphabet(signed):
    _, _, mandate, entry, _ = signed
    for text in (mandate, entry):
        assert text == text.upper()
        assert not set(text) & set("*~\\")


@pytest.mark.parametrize("old,new", [("AMT=3125.75", "AMT=3125.76"), ("ID=FERRO-0001", "ID=FERRO-0002")])
def test_entry_tamper_detected(signed, old, new):
    _, orig, _, entry, _ = signed
    with pytest.raises(PayloadError, match="ENTRY_SIG_INVALID"):
        verify_record(ENTRY, entry.replace(old, new), orig.public_key())


def test_mandate_wrong_key_rejected(signed):
    _, _, mandate, _, _ = signed
    with pytest.raises(PayloadError, match="MANDATE_SIG_INVALID"):
        verify_record(MANDATE, mandate, generate_private_key().public_key())


def test_x12_chunking_roundtrip(signed):
    *_, debit = signed
    assert extract_signed(build_820(debit)) == {"MD1": debit.mandate_text, "PE1": debit.entry_text}


def test_x12_missing_chunk_drops_record(signed):
    *_, debit = signed
    x12 = "\\".join(s for s in build_820(debit).split("\\") if "MD1-02-" not in s)
    assert "MD1" not in extract_signed(x12)


def test_ach_file_roundtrip_and_format(signed, tmp_path):
    *_, debit = signed
    path = tmp_path / "f.ach"
    write_ach(path, [debit], odfi_routing="021000089", rdfi_routing="044000122")
    lines = path.read_text().splitlines()
    assert all(len(line) == 94 for line in lines) and len(lines) % 10 == 0
    (got,) = read_ach(path)
    assert (got.amount_cents, got.entry_id, got.originator_id, got.effective_date) == \
        (debit.amount_cents, debit.entry_id, debit.originator_id, debit.effective_date)
    assert (got.mandate_text, got.entry_text) == (debit.mandate_text, debit.entry_text)


def test_iso_pain008_to_pacs003_roundtrip(signed):
    *_, debit = signed
    pain = build_pain008([debit], creditor_routing="021000089", creditor_account="77",
                         msg_id="P1")
    (got,) = parse_pacs003(pain008_to_pacs003(pain, creditor_routing="021000089",
                                              creditor_account="77", msg_id="X1",
                                              settlement_date=debit.effective_date))
    assert got == debit


def test_demo_all_scenarios_match_on_both_rails(tmp_path, capsys):
    run(tmp_path, today=TODAY)
    assert "12/12 scenarios produced the expected decision on both rails" in capsys.readouterr().out
