"""ISO 20022 direct debits: pain.008 (creditor -> creditor agent) and
pacs.003 (creditor agent -> debtor agent), with the signed records in:

  DrctDbtTx/MndtRltdInf/ElctrncSgntr   payer-signed MD1 mandate
                                       (Max1025Text, defined by ISO as "additional
                                       security provisions, such as a digital
                                       signature, as provided by the debtor")
  SplmtryData/Envlp/ps:SgndNtry        originator-signed PE1 entry

pain008_to_pacs003() models the creditor agent's hop, including an option to
drop SplmtryData the way some intermediaries do.

Element order follows the .001.08 schemas, but the output is NOT validated
against the official XSDs -- treat as illustrative.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import date, datetime

from .model import RailDebit
from .payload import amount_str, parse_amount

PAIN = "urn:iso:std:iso:20022:tech:xsd:pain.008.001.08"
PACS = "urn:iso:std:iso:20022:tech:xsd:pacs.003.001.08"
PS = "urn:example:paysign:1"  # namespace for our SplmtryData envelope content
ET.register_namespace("ps", PS)


def _sub(parent: ET.Element, path: str, text: str | None = None, **attrib) -> ET.Element:
    """Create (or reuse) a '/'-separated chain of child elements."""
    el = parent
    tags = path.split("/")
    for i, tag in enumerate(tags):
        last = i == len(tags) - 1
        found = None if last else el.find(tag)
        el = found if found is not None else ET.SubElement(el, tag)
    if text is not None:
        el.text = text
    el.attrib.update(attrib)
    return el


def _agent(parent: ET.Element, tag: str, routing: str) -> None:
    _sub(parent, f"{tag}/FinInstnId/ClrSysMmbId/ClrSysId/Cd", "USABA")
    _sub(parent, f"{tag}/FinInstnId/ClrSysMmbId/MmbId", routing)


def _account(parent: ET.Element, tag: str, account: str) -> None:
    _sub(parent, f"{tag}/Id/Othr/Id", account)


def _mandate_block(tx: ET.Element, d: RailDebit) -> None:
    dd = _sub(tx, "DrctDbtTx")
    if d.mandate_id or d.mandate_text:
        mri = _sub(dd, "MndtRltdInf")
        _sub(mri, "MndtId", d.mandate_id or "UNKNOWN")
        if d.mandate_text:
            _sub(mri, "ElctrncSgntr", d.mandate_text)
    _sub(dd, "CdtrSchmeId/Id/OrgId/Othr/Id", d.originator_id)


def _supplementary(tx: ET.Element, d: RailDebit) -> None:
    if d.entry_text:
        env = _sub(tx, "SplmtryData/Envlp")
        ET.SubElement(env, f"{{{PS}}}SgndNtry").text = d.entry_text


def _tostring(root: ET.Element) -> bytes:
    ET.indent(root)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def build_pain008(debits: list[RailDebit], *, creditor_routing: str, creditor_account: str,
                  msg_id: str, created: datetime | None = None) -> bytes:
    """One PmtInf per originator + collection date, like ACH batches."""
    now = created or datetime.now()
    plain = ET.Element("CstmrDrctDbtInitn")
    gh = _sub(plain, "GrpHdr")
    _sub(gh, "MsgId", msg_id)
    _sub(gh, "CreDtTm", now.replace(microsecond=0).isoformat())
    _sub(gh, "NbOfTxs", str(len(debits)))
    _sub(gh, "CtrlSum", amount_str(sum(d.amount_cents for d in debits)))
    _sub(gh, "InitgPty/Nm", debits[0].originator_name if debits else "")

    groups: dict[tuple, list[RailDebit]] = {}
    for d in debits:
        groups.setdefault((d.originator_id, d.originator_name, d.effective_date), []).append(d)
    for n, ((oid, oname, eff), items) in enumerate(groups.items(), start=1):
        pi = _sub(plain, "PmtInf")
        _sub(pi, "PmtInfId", f"{msg_id}-{n}")
        _sub(pi, "PmtMtd", "DD")
        _sub(pi, "NbOfTxs", str(len(items)))
        _sub(pi, "CtrlSum", amount_str(sum(d.amount_cents for d in items)))
        _sub(pi, "ReqdColltnDt", eff.isoformat())
        _sub(pi, "Cdtr/Nm", oname)
        _account(pi, "CdtrAcct", creditor_account)
        _agent(pi, "CdtrAgt", creditor_routing)
        for d in items:
            tx = _sub(pi, "DrctDbtTxInf")
            _sub(tx, "PmtId/EndToEndId", d.entry_id)
            _sub(tx, "InstdAmt", amount_str(d.amount_cents), Ccy="USD")
            _mandate_block(tx, d)
            _agent(tx, "DbtrAgt", d.routing)
            _sub(tx, "Dbtr/Nm", d.payer_name)
            _account(tx, "DbtrAcct", d.account)
            _sub(tx, "RmtInf/Ustrd", f"INV-{d.entry_id}")
            _supplementary(tx, d)
    return _document(plain, PAIN)


def _document(body: ET.Element, ns: str) -> bytes:
    """Wrap in <Document> and move every un-namespaced tag into ns. (Built
    without namespaces first so the path helpers stay readable.)"""
    doc = ET.Element("Document")
    doc.append(body)
    for el in doc.iter():
        if not el.tag.startswith("{"):
            el.tag = f"{{{ns}}}{el.tag}"
    ET.register_namespace("", ns)
    return _tostring(doc)


def _strip_ns(root: ET.Element) -> ET.Element:
    """Drop the ISO namespace (keep ours) so paths stay readable."""
    for el in root.iter():
        if el.tag.startswith("{") and not el.tag.startswith(f"{{{PS}}}"):
            el.tag = el.tag.split("}", 1)[1]
    return root


def _text(el: ET.Element, path: str) -> str | None:
    found = el.find(path)
    return found.text if found is not None else None


def parse_pain008(xml: bytes) -> list[RailDebit]:
    root = _strip_ns(ET.fromstring(xml))
    out = []
    for pi in root.iter("PmtInf"):
        eff = date.fromisoformat(_text(pi, "ReqdColltnDt"))
        oname = _text(pi, "Cdtr/Nm")
        for tx in pi.iter("DrctDbtTxInf"):
            out.append(_debit_from_tx(tx, oname, eff, "InstdAmt"))
    return out


def _debit_from_tx(tx: ET.Element, oname: str, eff: date, amt_path: str) -> RailDebit:
    sgnd = tx.find(f"SplmtryData/Envlp/{{{PS}}}SgndNtry")
    return RailDebit(
        originator_id=_text(tx, "DrctDbtTx/CdtrSchmeId/Id/OrgId/Othr/Id"),
        originator_name=oname,
        routing=_text(tx, "DbtrAgt/FinInstnId/ClrSysMmbId/MmbId"),
        account=_text(tx, "DbtrAcct/Id/Othr/Id"),
        payer_name=_text(tx, "Dbtr/Nm"),
        amount_cents=parse_amount(_text(tx, amt_path)),
        effective_date=eff,
        entry_id=_text(tx, "PmtId/EndToEndId"),
        mandate_id=_text(tx, "DrctDbtTx/MndtRltdInf/MndtId"),
        mandate_text=_text(tx, "DrctDbtTx/MndtRltdInf/ElctrncSgntr"),
        entry_text=sgnd.text if sgnd is not None else None,
    )


def build_pacs003(debits: list[RailDebit], *, creditor_routing: str, creditor_account: str,
                  msg_id: str, settlement_date: date, created: datetime | None = None,
                  drop_supplementary: set[str] | None = None) -> bytes:
    """Creditor agent -> debtor agent. drop_supplementary: EndToEndIds whose
    SplmtryData is discarded on this hop."""
    drop = drop_supplementary or set()
    now = created or datetime.now()
    plain = ET.Element("FIToFICstmrDrctDbt")
    gh = _sub(plain, "GrpHdr")
    _sub(gh, "MsgId", msg_id)
    _sub(gh, "CreDtTm", now.replace(microsecond=0).isoformat())
    _sub(gh, "NbOfTxs", str(len(debits)))
    _sub(gh, "TtlIntrBkSttlmAmt", amount_str(sum(d.amount_cents for d in debits)), Ccy="USD")
    _sub(gh, "IntrBkSttlmDt", settlement_date.isoformat())
    _sub(gh, "SttlmInf/SttlmMtd", "CLRG")
    for d in debits:
        tx = _sub(plain, "DrctDbtTxInf")
        _sub(tx, "PmtId/EndToEndId", d.entry_id)
        _sub(tx, "IntrBkSttlmAmt", amount_str(d.amount_cents), Ccy="USD")
        _sub(tx, "ReqdColltnDt", d.effective_date.isoformat())
        _mandate_block(tx, d)
        _sub(tx, "Cdtr/Nm", d.originator_name)
        _account(tx, "CdtrAcct", creditor_account)
        _agent(tx, "CdtrAgt", creditor_routing)
        _sub(tx, "Dbtr/Nm", d.payer_name)
        _account(tx, "DbtrAcct", d.account)
        _agent(tx, "DbtrAgt", d.routing)
        _sub(tx, "RmtInf/Ustrd", f"INV-{d.entry_id}")
        if d.entry_id not in drop:
            _supplementary(tx, d)
    return _document(plain, PACS)


def pain008_to_pacs003(pain: bytes, *, creditor_routing: str, creditor_account: str,
                       msg_id: str, settlement_date: date,
                       drop_supplementary: set[str] | None = None) -> bytes:
    return build_pacs003(parse_pain008(pain), creditor_routing=creditor_routing,
                         creditor_account=creditor_account, msg_id=msg_id,
                         settlement_date=settlement_date, drop_supplementary=drop_supplementary)


def parse_pacs003(xml: bytes) -> list[RailDebit]:
    root = _strip_ns(ET.fromstring(xml))
    return [
        _debit_from_tx(tx, _text(tx, "Cdtr/Nm"), date.fromisoformat(_text(tx, "ReqdColltnDt")),
                       "IntrBkSttlmAmt")
        for tx in root.iter("DrctDbtTxInf")
    ]
