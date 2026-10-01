"""so 中隐藏密钥的提取。"""
from __future__ import annotations
from typing import Optional

from config import HIDDEN_PATTERN, LEGACY_OLD_SO_MARKER

def extract_hidden_from_so(so_data: bytes) -> Optional[str]:
    if not so_data:
        return None
    match = HIDDEN_PATTERN.search(so_data)
    if not match:
        return None
    return match.group(0).decode("ascii", errors="ignore")


def extract_legacy_short_sok_from_so(so_data: bytes) -> Optional[str]:
    if not so_data:
        return None
    marker_pos = so_data.find(LEGACY_OLD_SO_MARKER)
    if marker_pos < 4:
        return None
    candidate = so_data[marker_pos - 4:marker_pos]
    try:
        text = candidate.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if len(text) == 4 and text.isprintable() else None


def extract_sok_from_so(so_data: bytes) -> Optional[str]:
    return extract_hidden_from_so(so_data) or extract_legacy_short_sok_from_so(so_data)
