"""密钥候选与解密策略工厂。"""
from __future__ import annotations
from typing import List, Optional, Tuple

from config import BURDEN_XOR_KEY, MAGIC_BYTES
from crypto.elf import extract_key_candidates_from_so, uniq_bytes_list

from algorithms.common import KeySet, OuterCandidate
from algorithms.current import (
    EnvP25Candidate,
    LegacyOuterCandidate,
    NativeX86IdbfjP25Candidate,
    NativeX86IdbfjP25SignatureCandidate,
)
from algorithms.transitional import TransitionalOuterCandidate

def generate_key_sets(
    native_so: Optional[bytes] = None,
    manual_post_key: Optional[bytes] = None,
    manual_xor_key: Optional[bytes] = None,
) -> List[KeySet]:
    post_candidates = [MAGIC_BYTES]
    xor_candidates = [BURDEN_XOR_KEY]
    if manual_post_key:
        post_candidates = [manual_post_key] + post_candidates
    if manual_xor_key:
        xor_candidates = [manual_xor_key] + xor_candidates
    if native_so:
        so_post_candidates, so_xor_candidates = extract_key_candidates_from_so(native_so)
        post_candidates = so_post_candidates + post_candidates
        xor_candidates = so_xor_candidates + xor_candidates

    post_candidates = uniq_bytes_list(post_candidates)[:8]
    xor_candidates = uniq_bytes_list(xor_candidates)[:8]

    out: List[KeySet] = []
    seen = set()
    for pi, post_key in enumerate(post_candidates):
        for xi, xor_key in enumerate(xor_candidates):
            sig = (post_key, xor_key)
            if sig in seen:
                continue
            seen.add(sig)
            name = "generic"
            if post_key != MAGIC_BYTES or xor_key != BURDEN_XOR_KEY:
                name = f"post[{pi}]/xor[{xi}]"
            out.append(KeySet(name, post_key, xor_key))
            if len(out) >= 20:
                return out
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
