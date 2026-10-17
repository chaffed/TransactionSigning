# TransactionSigning — signed-QR checks for Positive Pay (PoC)

The issuer prints each check with a QR code. The QR holds the payee, amount,
serial, account, routing number, and issue date in clear text, plus an
Ed25519 signature made with the issuer's private key. The paying bank runs
Positive Pay, or the customer runs Reverse Positive Pay. Either one decodes
the QR from the image in the X9.37 image cash letter, verifies the signature
with the enrolled public key, and cross-checks the signed data against:

- the MICR data in the ICL check-detail record (type 25),
- the printed payee, read with OCR, and
- the issue file, voids, paid history, and date rules.

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
brew install tesseract          # optional; enables the printed-payee check
.venv/bin/python -m checksign demo --out out
.venv/bin/python -m pytest -q
```

The demo issues 9 checks, presents 12 items (2 genuine and 10 attacks or
policy failures) in an ICL, and decides each one under both models:

| Scenario | Caught by |
|---|---|
| Raised amount (printed and encoded) | `AMOUNT_MISMATCH` (signed vs. ICL amount) |
| Payee washed, QR left intact | `PAYEE_ALTERED` (signed vs. OCR of the printed payee) |
| QR text edited to a new payee | `SIG_INVALID` |
| Counterfeit with a QR signed by the attacker's key | `SIG_INVALID` |
| Counterfeit serial carrying a genuine QR copied from another check | `MICR_SERIAL_MISMATCH` |
| Same item deposited twice | `DUPLICATE_PRESENTMENT` |
| Counterfeit with no QR | `QR_MISSING` |
| Unknown key ID | `KEY_UNKNOWN` |
| Voided check, stale-dated check | `ISSUE_VOID`, `STALE_DATED` |

Outputs go to `out/`:

- `printed/` holds the checks as issued.
- `captured/` holds the bitonal 200 DPI images the bank of first deposit (BOFD) sees.
- `bank/presentment.x937` is the image cash letter.
- `bank/positive_pay_results.csv` holds the bank's Positive Pay decisions.
- `bank/presented_items.json` is the bank's reverse positive pay export.
- `customer/rpp_decisions.csv` holds the customer's pay/return decisions.

## QR payload

```
CS1;KID=nbw-2026a;RT=044000122;ACCT=4471902385;SN=5001;AMT=1250.00;DT=2026-10-15;PAYEE=RIVERSTONE LANDSCAPING LLC;SIG=<86 chars base64url>
```

- **Signed bytes = everything before `;SIG=`, exactly as scanned.** The verifier never
  re-serializes the fields, so what it checks is always exactly what was signed.
- **Strict grammar.** A single anchored regex fixes the field order. A reordered,
  duplicated, or extra field is rejected (`QR_MALFORMED`) before any field is used.
- **The routing number is signed** even though it wasn't in the original field list,
  because an account number is only unique within a bank.
- **`KID`** selects the enrolled public key. This allows key rotation, and revocation
  (`KEY_REVOKED`) without reissuing checks that are already outstanding.
- **Size.** About 205 bytes fits a version-10 QR at ECC level M. With 15-mil modules
  that is about 1 inch square, and it decodes reliably from the 200 DPI bitonal G4 TIFF
  used in X9 image exchange.

## What the signature does and doesn't prove

The signature proves the *data* came from the key holder. It says nothing about the
*paper*. That is why the other cross-checks are required:

- **Washing.** An attacker can change the printed payee and leave the QR untouched.
  Only comparing the signed payee with the printed one catches this. The PoC uses OCR.
  In production, use the CAR/LAR and payee-recognition engines that check processors
  already run, or show the signed payee next to the image in exception review.
- **Replay.** A genuine QR can be photocopied onto a counterfeit. The signed serial and
  amount bind it to one item: the MICR comparison catches a different serial, and the
  paid ledger catches a second presentment.
- **Raised amount.** The amount the BOFD encodes in the ICL comes from the altered
  courtesy amount, so it no longer matches the signed amount.

## Gaps between this PoC and production

- **Key custody.** The private key is a PEM file on disk. Use an HSM or KMS on the
  check-printing system, enroll public keys with the bank out-of-band, and define a
  revocation process.
- **ICL format.** The X9.37 support is minimal: just enough records for the PoC, with
  no addenda, return records, or X9.100-187 certification.
- **Payee location.** The OCR crop uses fixed coordinates. A real system has to locate
  the payee relative to the QR or by form recognition, and handle skew and other
  check stocks.
- **Policy choice.** If a check has a valid signature but the issue file arrived late,
  you could treat it as a soft exception instead of `NOT_ISSUED`. The signed QR is
  effectively its own issue record.
- **Image quality.** On real capture devices, test against X9.100-181 image quality
  standards. Smudged or partially printed QRs should go to review, not auto-return.

Synthetic data only: the issuers and banks are fictional, the routing numbers fail the
ABA checksum on purpose, and every image is marked SPECIMEN.
