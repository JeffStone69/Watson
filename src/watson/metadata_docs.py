"""Detect author metadata in PDF and DOCX bytes without keeping the values."""

from __future__ import annotations

import io
import re
import zipfile
from xml.etree import ElementTree

# The captured bytes are only used to decide whether the field is non-empty.
_PDF_TEXT = re.compile(rb"/(Author|Creator)\s*\(((?:\\.|[^\\)])*)\)", re.IGNORECASE)
_PDF_HEX = re.compile(rb"/(Author|Creator)\s*<([0-9A-Fa-f\s]+)>", re.IGNORECASE)
_DOC_TAGS = {"creator", "lastModifiedBy"}


def _nonempty(payload: bytes) -> bool:
    return bool(payload.replace(b"\\", b"").strip())


def pdf_metadata_fields(data: bytes) -> set[str]:
    """Return PDF info field names that have a value. Values are not returned."""
    if not data:
        return set()
    fields: set[str] = set()
    sample = data if len(data) <= 1_000_000 else data[:400_000] + data[-400_000:]
    for match in _PDF_TEXT.finditer(sample):
        if _nonempty(match.group(2)):
            fields.add(match.group(1).decode("ascii", "ignore").title())
    for match in _PDF_HEX.finditer(sample):
        hex_text = re.sub(rb"\s+", b"", match.group(2))
        try:
            decoded = bytes.fromhex(hex_text.decode("ascii"))
        except ValueError:
            decoded = b"present"
        if decoded.strip():
            fields.add(match.group(1).decode("ascii", "ignore").title())
    return fields


def docx_metadata_fields(data: bytes) -> set[str]:
    """Return DOCX core-property names that have a value. Values are not returned."""
    if not data.startswith(b"PK"):
        return set()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            info = archive.getinfo("docProps/core.xml")
            if info.file_size > 200_000:
                return set()
            xml_bytes = archive.read("docProps/core.xml")
    except (KeyError, zipfile.BadZipFile, OSError):
        return set()
    try:
        root = ElementTree.fromstring(xml_bytes)
    except ElementTree.ParseError:
        return set()
    fields: set[str] = set()
    for element in root.iter():
        tag = element.tag.split("}")[-1]
        if tag in _DOC_TAGS and (element.text or "").strip():
            fields.add(tag)
    return fields


def has_author_metadata(data: bytes, suffix: str) -> bool:
    suffix = suffix.lower()
    if suffix == ".pdf":
        return bool(pdf_metadata_fields(data))
    if suffix == ".docx":
        return bool(docx_metadata_fields(data))
    return False
