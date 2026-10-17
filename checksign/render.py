"""Render synthetic business checks (8.5 x 3.5 in @ 200 DPI) with a signed QR.

Safety: fictional banks/issuers only, routing numbers that fail the ABA
checksum, and "SPECIMEN" text on every image -- same conventions as CheckSim.
"""

from __future__ import annotations

import io
import os
import random
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

from .payload import CheckData
from .qr import make_qr

DPI = 200
W, H = 1700, 700  # 8.5 x 3.5 in

# Printed payee field, in front-image pixel coordinates. The OCR step crops
# this box; a production system would locate it relative to the QR instead.
PAYEE_BOX = (185, 196, 1290, 252)
QR_ORIGIN = (1445, 330)  # stays above the 0.625in MICR clear band (y >= 575)

_SANS_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]
_SANS_BOLD_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]
_MICR_CANDIDATES = [
    os.environ.get("CHECKSIGN_MICR_FONT", ""),
    str(Path(__file__).resolve().parents[2] / "CheckSim" / "fonts" / "GnuMICR.ttf"),
    "./fonts/GnuMICR.ttf",
]


def _font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont:
    for path in candidates:
        if path and os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default(size=size)


def _micr_font(size: int) -> tuple[ImageFont.FreeTypeFont, str, str]:
    """(font, transit symbol, on-us symbol). GnuMICR maps A=transit, C=on-us."""
    for path in _MICR_CANDIDATES:
        if path and os.path.exists(path):
            return ImageFont.truetype(path, size), "A", "C"
    return _font(_SANS_BOLD_CANDIDATES, size - 6), "T", "U"


@dataclass
class Issuer:
    name: str
    address: str
    bank_name: str
    bank_address: str


def _amount_words(cents: int) -> str:
    ones = ["", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
            "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen",
            "Eighteen", "Nineteen"]
    tens = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"]

    def under_1000(n: int) -> str:
        parts = []
        if n >= 100:
            parts.append(f"{ones[n // 100]} Hundred")
            n %= 100
        if n >= 20:
            parts.append(tens[n // 10] + (f"-{ones[n % 10]}" if n % 10 else ""))
        elif n:
            parts.append(ones[n])
        return " ".join(parts)

    dollars, c = divmod(cents, 100)
    chunks = []
    for value, label in ((1_000_000, "Million"), (1_000, "Thousand"), (1, "")):
        if dollars >= value:
            chunks.append(f"{under_1000(dollars // value)} {label}".strip())
            dollars %= value
    words = " ".join(chunks) or "Zero"
    return f"{words} and {c:02d}/100"


def render_front(
    issuer: Issuer,
    check: CheckData,
    qr_text: str | None,
    *,
    printed_payee: str | None = None,
    printed_amount_cents: int | None = None,
    printed_serial: str | None = None,
) -> Image.Image:
    """Render the check face. The printed_* overrides simulate physical
    alteration (washing, raising) of the paper after the QR was printed."""
    payee = printed_payee if printed_payee is not None else check.payee
    amount = printed_amount_cents if printed_amount_cents is not None else check.amount_cents
    serial = printed_serial if printed_serial is not None else check.serial

    img = Image.new("RGB", (W, H), (246, 248, 244))
    d = ImageDraw.Draw(img)
    ink = (20, 20, 30)
    sans = lambda s: _font(_SANS_CANDIDATES, s)  # noqa: E731
    bold = lambda s: _font(_SANS_BOLD_CANDIDATES, s)  # noqa: E731

    # light security-pattern background lines
    for y in range(0, H, 14):
        d.line([(0, y), (W, y)], fill=(236, 240, 234), width=1)

    d.text((40, 28), issuer.name, font=bold(34), fill=ink)
    d.text((40, 72), issuer.address, font=sans(22), fill=ink)
    d.text((720, 30), issuer.bank_name, font=bold(26), fill=ink)
    d.text((720, 64), issuer.bank_address, font=sans(18), fill=ink)
    d.text((1540, 28), serial, font=bold(32), fill=ink)

    d.text((1170, 138), "DATE", font=sans(20), fill=ink)
    d.text((1260, 126), check.issue_date.strftime("%b %d, %Y").upper(), font=sans(28), fill=ink)
    d.line([(1250, 162), (1520, 162)], fill=ink, width=2)

    d.text((40, 208), "PAY TO THE", font=sans(18), fill=ink)
    d.text((40, 230), "ORDER OF", font=sans(18), fill=ink)
    d.text((PAYEE_BOX[0] + 8, 210), payee, font=sans(32), fill=ink)
    d.line([(PAYEE_BOX[0], 254), (PAYEE_BOX[2], 254)], fill=ink, width=2)

    d.text((1310, 212), "$", font=bold(34), fill=ink)
    d.rectangle([1340, 205, 1660, 258], outline=ink, width=2)
    amt_txt = f"**{amount / 100:,.2f}"
    f_amt = bold(32)
    tw = d.textlength(amt_txt, font=f_amt)
    d.text((1650 - tw, 212), amt_txt, font=f_amt, fill=ink)

    words = _amount_words(amount)
    d.text((40, 292), f"{words} " + "*" * max(0, 70 - len(words)), font=sans(26), fill=ink)
    d.line([(40, 326), (1290, 326)], fill=ink, width=2)
    d.text((1300, 300), "DOLLARS", font=sans(20), fill=ink)

    d.text((40, 526), "MEMO", font=sans(18), fill=ink)
    d.line([(110, 548), (640, 548)], fill=ink, width=2)
    # stand-in for a printed facsimile signature
    rng = random.Random(issuer.name)
    pts = [(860 + i * 14, 520 + rng.randint(-18, 18)) for i in range(32)]
    d.line(pts, fill=(25, 25, 90), width=3)
    d.line([(820, 550), (1400, 550)], fill=ink, width=2)
    d.text((1000, 556), "AUTHORIZED SIGNATURE", font=sans(14), fill=ink)

    if qr_text is not None:
        qr = make_qr(qr_text).convert("RGB")
        img.paste(qr, QR_ORIGIN)
        d.text((QR_ORIGIN[0] - 175, QR_ORIGIN[1] + 6), "DIGITALLY SIGNED", font=bold(15), fill=ink)
        d.text((QR_ORIGIN[0] - 175, QR_ORIGIN[1] + 26), "Scan to verify payee,", font=sans(13), fill=ink)
        d.text((QR_ORIGIN[0] - 175, QR_ORIGIN[1] + 42), "amount, date, serial", font=sans(13), fill=ink)

    micr, transit, on_us = _micr_font(34)
    line = f"{on_us}{serial}{on_us}  {transit}{check.routing}{transit}  {check.account}{on_us}"
    d.text((330, 618), line, font=micr, fill=(0, 0, 0))

    d.text((40, 676), "SPECIMEN - SYNTHETIC TEST ITEM - NOT NEGOTIABLE", font=sans(14), fill=(90, 90, 90))
    return img


def render_back() -> Image.Image:
    img = Image.new("RGB", (W, H), (250, 250, 250))
    d = ImageDraw.Draw(img)
    f = _font(_SANS_CANDIDATES, 18)
    d.text((1250, 40), "ENDORSE HERE", font=f, fill=(40, 40, 40))
    for y in (80, 120, 160):
        d.line([(1150, y), (1650, y)], fill=(40, 40, 40), width=1)
    d.text((1150, 180), "FOR DEPOSIT ONLY", font=f, fill=(40, 40, 120))
    d.text((40, 660), "SPECIMEN - SYNTHETIC TEST ITEM", font=f, fill=(90, 90, 90))
    return img


def simulate_capture(img: Image.Image, seed: int = 0) -> Image.Image:
    """Approximate a bank capture device: grayscale, slight blur, speckle
    noise, then a hard threshold to 1-bit at 200 DPI (X9 bitonal image)."""
    rng = random.Random(seed)
    g = img.convert("L").filter(ImageFilter.GaussianBlur(0.7))
    px = g.load()
    for _ in range(W * H // 400):
        x, y = rng.randrange(W), rng.randrange(H)
        px[x, y] = rng.choice((0, 255))
    return g.point(lambda v: 255 if v > 150 else 0).convert("1", dither=Image.Dither.NONE)


def to_tiff_g4(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.convert("1", dither=Image.Dither.NONE).save(buf, "TIFF", compression="group4", dpi=(DPI, DPI))
    return buf.getvalue()


def from_tiff(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data))
