"""Text extraction for PDF and image evidence.

PDFs use pypdf (pure python).  Images use Tesseract OCR when it is installed; because
Tesseract is an external binary, extracted text is cached in code/cache/ocr_cache.json
keyed by the SHA-256 of the image so the pipeline is reproducible on machines without it.
"""
import hashlib
import json
from pathlib import Path

CACHE_PATH = Path(__file__).resolve().parent.parent / "cache" / "ocr_cache.json"
_cache = None


def _load():
    global _cache
    if _cache is None:
        _cache = json.loads(CACHE_PATH.read_text(encoding="utf-8")) if CACHE_PATH.exists() else {}
    return _cache


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_cache():
    if _cache is not None:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(_cache, indent=1, sort_keys=True), encoding="utf-8")


def pdf_text(path):
    try:
        from pypdf import PdfReader
        r = PdfReader(str(path))
        return "\n".join((p.extract_text() or "") for p in r.pages)
    except Exception:
        return ""


def image_text(path):
    cache = _load()
    key = _sha(path)
    if key in cache:
        return cache[key]
    try:
        import pytesseract
        from PIL import Image
        img = Image.open(path)
        txt = pytesseract.image_to_string(img, config="--psm 6")
        txt += "\n" + pytesseract.image_to_string(img, config="--psm 11")
    except Exception:
        return ""
    cache[key] = txt
    save_cache()
    return txt
