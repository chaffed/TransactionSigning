"""Rail-neutral view of a debit, as built by the originator and as parsed by
the paying bank from either an ACH CTX file or an ISO 20022 message."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass
class RailDebit:
    originator_id: str  # ACH Company Identification / ISO creditor scheme id
    originator_name: str
    routing: str  # payer's bank (RDFI / debtor agent)
    account: str  # payer's account
    payer_name: str
    amount_cents: int
    effective_date: date  # ACH effective entry date / ISO requested collection date
    entry_id: str  # ACH Identification Number / ISO EndToEndId
    mandate_id: str | None = None  # ISO MndtId (ACH has no field for it)
    mandate_text: str | None = None  # signed MD1 record
    entry_text: str | None = None  # signed PE1 record
