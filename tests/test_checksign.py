import shutil
from datetime import date

import pytest

from checksign.demo import run
from checksign.keys import Keyring, generate_private_key
from checksign.payload import CheckData, PayloadError, sign, verify
from checksign.render import Issuer, render_back, render_front, simulate_capture, to_tiff_g4, from_tiff
from checksign.qr import decode_qrs
from checksign.x937 import IclItem, read_icl, write_icl

KID = "test-1"
CHECK = CheckData("044000123", "4471902385", "5001", 125_000, date(2026, 10, 15), "Riverstone Landscaping LLC")


@pytest.fixture
def key():
    return generate_private_key()


@pytest.fixture
def keyring(key):
    kr = Keyring()
    kr.add(KID, key.public_key())
    return kr


def test_sign_verify_roundtrip(key, keyring):
    vp = verify(sign(key, KID, CHECK), keyring)
    assert vp.data.amount_cents == 125_000
    assert vp.data.payee == "RIVERSTONE LANDSCAPING LLC"


@pytest.mark.parametrize("old,new", [
    ("AMT=1250.00", "AMT=9250.00"),
    ("SN=5001", "SN=5002"),
    ("ACCT=4471902385", "ACCT=4471902386"),
    ("RT=044000123", "RT=044000124"),
    ("DT=2026-10-15", "DT=2026-10-16"),
    ("PAYEE=RIVERSTONE", "PAYEE=RIVERST0NE"),
])
def test_any_field_change_breaks_signature(key, keyring, old, new):
    tampered = sign(key, KID, CHECK).replace(old, new)
    with pytest.raises(PayloadError) as e:
        verify(tampered, keyring)
    assert e.value.code == "SIG_INVALID"


@pytest.mark.parametrize("mutate", [
    lambda t: t.replace(";SN=5001;AMT=1250.00", ";AMT=1250.00;SN=5001"),  # reordered
    lambda t: t.replace(";SN=5001", ";SN=5001;SN=9999"),                 # duplicated field
    lambda t: t.replace("CS1;", "CS2;"),                                  # unknown version
    lambda t: t + " ",                                                    # trailing junk
])
def test_malformed_payload_rejected_before_crypto(key, keyring, mutate):
    with pytest.raises(PayloadError) as e:
        verify(mutate(sign(key, KID, CHECK)), keyring)
    assert e.value.code == "QR_MALFORMED"


def test_unknown_and_revoked_keys(key, keyring):
    with pytest.raises(PayloadError, match="KEY_UNKNOWN"):
        verify(sign(key, "other", CHECK), keyring)
    keyring.revoke(KID)
    with pytest.raises(PayloadError, match="KEY_REVOKED"):
        verify(sign(key, KID, CHECK), keyring)


def test_payee_with_reserved_characters_roundtrips(key, keyring):
    c = CheckData(**{**CHECK.__dict__, "payee": "Smith; Jones = 100% Partners"})
    assert verify(sign(key, KID, c), keyring).data.payee == "SMITH; JONES = 100% PARTNERS"


def test_qr_survives_bitonal_capture_and_icl_roundtrip(key, tmp_path):
    issuer = Issuer("Test Issuer LLC", "1 Test St", "Fictional Bank", "2 Bank St")
    qr_text = sign(key, KID, CHECK)
    front = to_tiff_g4(simulate_capture(render_front(issuer, CHECK, qr_text)))
    item = IclItem(CHECK.routing, CHECK.account, CHECK.serial, CHECK.amount_cents,
                   "1".zfill(15), front, to_tiff_g4(render_back()))
    write_icl(tmp_path / "f.x937", [item], origin_routing="021000089", destination_routing=CHECK.routing)
    (got,) = read_icl(tmp_path / "f.x937")
    assert (got.routing, got.account, got.serial, got.amount_cents) == \
        (CHECK.routing, CHECK.account, CHECK.serial, CHECK.amount_cents)
    assert decode_qrs(from_tiff(got.front_tiff)) == [qr_text]


@pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract not installed")
def test_demo_scenarios_all_decided_correctly(tmp_path, capsys):
    run(tmp_path)
    assert "12/12 scenarios produced the expected decision" in capsys.readouterr().out
