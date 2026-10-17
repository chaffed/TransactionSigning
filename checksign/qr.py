"""QR encode (segno) and decode (zxing-cpp)."""

from __future__ import annotations

import io

import segno
import zxingcpp
from PIL import Image


def make_qr(text: str, module_px: int = 3) -> Image.Image:
    """1-bit QR image. ECC level M with a 4-module quiet zone.

    module_px=3 at 200 DPI is a 15-mil module -- the smallest that survives
    the 200 DPI bitonal capture used in X9 image cash letters with margin.
    """
    qr = segno.make(text, error="m", mode="byte", micro=False, boost_error=False)
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=module_px, border=4)
    buf.seek(0)
    return Image.open(buf).convert("1")


def decode_qrs(img: Image.Image) -> list[str]:
    """All distinct QR payloads found in the image, in reading order."""
    results = zxingcpp.read_barcodes(img.convert("L"), formats=zxingcpp.BarcodeFormat.QRCode)
    seen: list[str] = []
    for r in results:
        if r.valid and r.text not in seen:
            seen.append(r.text)
    return seen
