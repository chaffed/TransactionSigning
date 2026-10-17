# TransactionSigning — signed checks and payments (PoC)

Two proofs of concept that share one signing approach: Ed25519 signatures over
clear-text records. `checksign` puts a signed QR code on printed checks;
`paysign` adds signed mandates and entries to ACH CTX and ISO 20022 debits.

## Checks: signed QR for Positive Pay (`checksign`)

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

---

# Signed debits over ACH CTX and ISO 20022 (`paysign`)

The same idea applied to electronic debits, with signatures from both parties.
Each party signs with **its own private key**:

| Record | Signed by | Proves | Verified with |
|---|---|---|---|
| `MD1` mandate | **payer**, once at setup | "I authorize originator X to debit my account, up to $Y, at frequency Z, until date D" | the payer's public key, enrolled at the payer's own bank for that account |
| `PE1` entry | **originator**, for each debit | "I sent this debit for this amount, date and ID, under that mandate" | the originator's public key, **embedded in the payer-signed mandate** (`OPK`) |

The mandate carries the originator's public key, so the paying bank needs only its own
customer's key. There is no directory of originator keys: the payer vouches for the
originator. Each entry includes `MH`, a hash of the exact signed mandate, so an entry
can't be moved under a different mandate.

```bash
.venv/bin/python -m paysign demo                 # writes to out/paysign/
.venv/bin/python -m paysign filter ach out/paysign/ach/03_FERRO-0001.ach \
    --keyring out/paysign/rdfi_payer_keyring.json \
    --mandates-on-file out/paysign/rdfi_mandates_on_file.txt
```

## Where the signed records go

| Rail | Mandate (`MD1`) | Entry (`PE1`) |
|---|---|---|
| **ACH CTX** | X12 820 in the type 05 addenda, split into `REF*ZZ*MD1-nn-NN*<80 chars>` segments | same, `REF*ZZ*PE1-nn-NN*…` |
| **ISO 20022** pain.008 → pacs.003 | `DrctDbtTx/MndtRltdInf/ElctrncSgntr` (Max1025Text, which ISO defines for the debtor's digital signature) | `SplmtryData/Envlp/ps:SgndNtry` |

The records use only uppercase letters and base32 signatures. That survives ACH
software that uppercases text, and stays inside the X12 basic character set.
Neither `*` nor `\` (the X12 delimiters) can appear in a record.

## Paying-bank debit filter

The filter is the same code for both rails. It runs these checks:

1. **Mandate.** Signed by a key enrolled *for this account*, so another customer of the
   bank can't sign a mandate for your account. It must name this originator, be inside
   its date window, and not be revoked.
2. **Entry.** Its signature verifies against the `OPK` in the mandate. Its amount, date,
   account, originator ID and entry ID match the message, and its `MH` matches the
   mandate.
3. **Limits and history.** The amount is within `MAX`. Frequency (`ONCE`, `WEEK`, `MNTH`,
   `ADHC`) and replay are checked against a ledger of accepted entries.

Demo results (identical on both rails):

| Scenario | Decision | Finding |
|---|---|---|
| Valid debit within mandate | ACCEPT | — |
| Amount altered in transit | RETURN (R29 / AM09) | `AMOUNT_MISMATCH` |
| Originator signs a debit over the mandate maximum | RETURN (R29 / AM09) | `EXCEEDS_MANDATE_LIMIT` |
| Replay of an accepted entry | RETURN (R24 / AM05) | `DUPLICATE_ENTRY` |
| Second debit in the same month on a monthly mandate | RETURN | `FREQUENCY_EXCEEDED` |
| Spoofed originator: real mandate, attacker-signed entry | RETURN | `ENTRY_SIG_INVALID` |
| Mandate for this account signed by a *different* customer | RETURN | `MANDATE_SIGNER_NOT_ACCOUNT_HOLDER` |
| No mandate | RETURN (R29 / MD01) | `MANDATE_MISSING` |
| Revoked mandate, expired mandate | RETURN | `MANDATE_REVOKED`, `MANDATE_EXPIRED` |
| Entry moved under a looser mandate | RETURN | `MANDATE_HASH_MISMATCH` |
| Signed data stripped in transit | **REVIEW** | `ENTRY_SIGNATURE_MISSING` |

**Mandates on file.** When ACH addenda are stripped, the mandate is lost *and* so is
the entry signature, because ACH has nowhere else to put them. ISO keeps the mandate
in a core field and loses only the `SplmtryData`. The filter therefore falls back to
mandates the payer registered with its own bank, much like an ACH debit-filter
authorization list today, and re-verifies their signatures. A stripped debit then goes
to REVIEW instead of being returned as unauthorized.

## Gaps between this PoC and production

- **Return codes.** The mapping is indicative. CTX is a corporate SEC code, so returns
  use R29; consumer debits would use R05, R07, R10 or R11.
- **Message formats.**
  - The X12 820 is minimal, with no ISA/GS envelope. The segment and qualifier
    choices need to be agreed with the banks' 820 implementation guides.
  - The ISO XML follows the .001.08 element order but has **not been validated against
    the official XSDs**.
  - CCD has only one 80-character addendum, which is too small for this scheme. Use
    CTX, or rely on mandates on file.
- **Originator key rotation.** The originator key is fixed in the mandate, so rotating
  it needs a mandate amendment, which the payer re-signs.
- **Key enrollment and custody.** The payer's key has to be enrolled through the bank's
  authenticated channel (online banking, treasury portal). Keep keys in an HSM or KMS
  on both sides.
- **Credits.** Not built. They would use only the originator signature, checked
  against the receiver's keyring of known payers.
