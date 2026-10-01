"""密钥候选与解密策略工厂。"""
from __future__ import annotations
from typing import List, Optional, Tuple

from config import (
    BURDEN_XOR_KEY,
    K_SLKY_NEW,
    K_SLKY_OLD,
    K_SLKY_V2,
    K_XOR_NEW,
    K_XOR_V2,
    MAGIC_BYTES,
    MAGIC_STRING,
)
from crypto.elf import extract_key_candidates_from_so

from algorithms.common import KeySet, OuterCandidate
from algorithms.current import (
    EnvP25Candidate,
    LegacyOuterCandidate,
    NativeX86IdbfjP25Candidate,
    NativeX86IdbfjP25SignatureCandidate,
)
from algorithms.transitional import TransitionalOuterCandidate

def detect_version(so_data: Optional[bytes]) -> Optional[str]:
    """检测引擎版本：new2 / new / old / mete / v4。"""
    if not so_data:
        return None
    if b"_ZN4iapp4mete" in so_data:
        return "mete"
    if b"NSt3__1" in so_data:
        return "old"
    if b"NSt6__ndk11" in so_data:
        if K_XOR_V2[:8] in so_data or K_SLKY_V2[:4] in so_data:
            return "new2"
        return "new"
    return None


_VERSION_KEYS = {
    "new2": (K_SLKY_V2, K_XOR_V2),
    "new": (K_SLKY_NEW, K_XOR_NEW),
    "old": (K_SLKY_OLD, BURDEN_XOR_KEY),
}


def generate_key_sets(
    native_so: Optional[bytes] = None,
    manual_post_key: Optional[bytes] = None,
    manual_xor_key: Optional[bytes] = None,
) -> List[KeySet]:
    out: List[KeySet] = []
    seen = set()

    def add(name: str, pk: bytes, xk: bytes) -> None:
        if (pk, xk) not in seen:
            seen.add((pk, xk))
            out.append(KeySet(name, pk, xk))

    # 1. 引擎版本密钥对（快速路径，公共库）
    ver = detect_version(native_so)
    if ver in _VERSION_KEYS:
        pk, xk = _VERSION_KEYS[ver]
        add(f"public/{ver}", pk, xk)

    # 2. 手动密钥（优先）
    if manual_post_key and manual_xor_key:
        add("manual", manual_post_key, manual_xor_key)

    # 3. 动态提取密钥（自定义库，全组合兜底）
    if native_so:
        so_post, so_xor = extract_key_candidates_from_so(native_so)
        for pk in so_post:
            for xk in so_xor:
                add("extracted", pk, xk)

    # 4. 其它公共密钥组合（兜底）
    for pk in (MAGIC_BYTES, MAGIC_STRING, K_SLKY_OLD, K_SLKY_NEW, K_SLKY_V2):
        for xk in (BURDEN_XOR_KEY, K_XOR_NEW, K_XOR_V2):
            add("public", pk, xk)

    return out

def generate_outer_candidates(mode: str = "auto", has_signature: bool = False) -> List[OuterCandidate]:
    mode = (mode or "auto").strip().lower()
    candidates: List[OuterCandidate] = [
        LegacyOuterCandidate("legacy:unsigned:none:magic_string:keyset:xor", "unsigned", None, "magic_string", "keyset", "xor", 100),
        NativeX86IdbfjP25Candidate("sok", 99),
        TransitionalOuterCandidate(confidence=98),
    ]
    if has_signature:
        candidates.insert(1, NativeX86IdbfjP25SignatureCandidate("sok", 98))
    if mode == "legacy":
        return candidates

    candidates.extend([
        LegacyOuterCandidate("legacy:unsigned:none:magic_string:magic_bytes:xor", "unsigned", None, "magic_string", "magic_bytes", "xor", 96),
        LegacyOuterCandidate("legacy:unsigned:none:keyset:keyset:xor", "unsigned", None, "keyset", "keyset", "xor", 94),
        LegacyOuterCandidate("legacy:signed:none:magic_string:keyset:xor", "signed", None, "magic_string", "keyset", "xor", 92),
        LegacyOuterCandidate("legacy:unsigned:none:nopost:nopost:direct", "unsigned", None, "nopost", "nopost", "direct", 84),
        LegacyOuterCandidate("legacy:signed:none:nopost:nopost:direct", "signed", None, "nopost", "nopost", "direct", 80),
    ])

    for password_name, confidence in (("sok", 90), ("entry_file", 82), ("empty", 78), ("app_name", 74), ("package_name", 72)):
        candidates.append(LegacyOuterCandidate(
            f"legacy:unsigned:{password_name}:magic_string:keyset:xor",
            "unsigned",
            password_name,
            "magic_string",
            "keyset",
            "xor",
            confidence,
        ))
        candidates.append(LegacyOuterCandidate(
            f"legacy:signed:{password_name}:magic_string:keyset:xor",
            "signed",
            password_name,
            "magic_string",
            "keyset",
            "xor",
            max(40, confidence - 12),
        ))

    first_names = ("base", "sok", "base_tail", "entry_file", "package_name", "app_name")
    second_names = ("sok", "dek", "version_name", "package_name", "app_name", "version_code")
    for first_name in first_names:
        for second_name in second_names:
            if first_name == second_name:
                continue
            candidates.append(EnvP25Candidate(first_name, second_name, "keyset", "xor", 62))
            candidates.append(EnvP25Candidate(first_name, second_name, "magic_string", "xor", 58))
            candidates.append(EnvP25Candidate(first_name, second_name, "magic_bytes", "xor", 56))
            candidates.append(EnvP25Candidate(first_name, second_name, "nopost", "direct", 52))

    candidates.sort(key=lambda item: (-item.confidence, item.name))
    seen = set()
    out: List[OuterCandidate] = []
    for item in candidates:
        if item.name in seen:
            continue
        seen.add(item.name)
        out.append(item)
    return out
