"""Locate packaged data files, including a PyInstaller build."""

from __future__ import annotations

import sys
from pathlib import Path


def resource_path(*parts: str) -> Path:
    """Return a packaged data path. `parts` are relative to the watson package."""
    relative = Path(*parts)
    if getattr(sys, "frozen", False):
        root = Path(getattr(sys, "_MEIPASS"))
        for candidate in (root / relative, root / "watson" / relative):
            if candidate.exists():
                return candidate
    return Path(__file__).resolve().parent / relative
