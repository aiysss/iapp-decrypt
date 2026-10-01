"""解密入口：dispatch 到各算法族并组装响应。"""
from __future__ import annotations
import hashlib
import re
from typing import Dict, List, Optional, Tuple

from algorithms.common import (
    DecryptConfig,
    crawl_members,
    filter_output_files,
    normalize_member_name,
    resolve_config,
    verify_outer_candidate,
)
from algorithms.factory import generate_key_sets, generate_outer_candidates
from algorithms.legacy4 import decrypt_bundle_legacy4
from algorithms.transitional import decrypt_bundle_transitional

def decrypt_bundle_current(
    lib_so: bytes,
    config: DecryptConfig,
    native_so: Optional[bytes] = None,
    mode: str = "auto",
    manual_post_key: Optional[bytes] = None,
    manual_xor_key: Optional[bytes] = None,
) -> Tuple[bytes, dict[str, bytes], list[dict[str, str]], Dict[str, bytes]]:
    candidates = generate_outer_candidates(mode, has_signature=bool((config.sign_b64 or "").strip()))
    key_sets = generate_key_sets(native_so, manual_post_key=manual_post_key, manual_xor_key=manual_xor_key)
    tried = 0

    for key_set in key_sets:
        for candidate in candidates:
            tried += 1
            result = verify_outer_candidate(lib_so, config, key_set, candidate)
            if result is None:
                continue
            outer_key, container, trace, preferred_strategy, entry_plain = result
            extracted, failed = crawl_members(container, config, key_set, preferred_strategy)
            extracted.setdefault(normalize_member_name(config.entry_file), entry_plain)
            trace["outer_key"] = outer_key
            trace["resolved_sok"] = config.sok.encode("utf-8")
            trace["resolved_dek"] = config.dek.encode("utf-8")
            trace["pwd_input"] = config.pwd_key.encode("utf-8")
            trace["pwd_key"] = config.user_enc.encode("utf-8")
            trace["candidate_count"] = str(len(candidates)).encode("ascii")
            trace["key_set_count"] = str(len(key_sets)).encode("ascii")
            trace["tried_count"] = str(tried).encode("ascii")
            trace["post_key"] = key_set.post_key
            trace["xor_key"] = key_set.xor_key
            trace["algorithm_family"] = b"current"
            return container, extracted, failed, trace

    raise RuntimeError(f"decrypt failed after trying {tried} candidate combinations")


def decrypt_bundle(
    lib_so: bytes,
    config: DecryptConfig,
    native_so: Optional[bytes] = None,
    mode: str = "auto",
    manual_post_key: Optional[bytes] = None,
    manual_xor_key: Optional[bytes] = None,
) -> Tuple[bytes, dict[str, bytes], list[dict[str, str]], Dict[str, bytes]]:
    resolved = resolve_config(config, native_so)
    normalized_mode = (mode or "auto").strip().lower()

    if normalized_mode == "legacy4":
        return decrypt_bundle_legacy4(lib_so, resolved)
    if normalized_mode == "transitional":
        return decrypt_bundle_transitional(lib_so, resolved)
    if normalized_mode == "current":
        return decrypt_bundle_current(
            lib_so,
            resolved,
            native_so=native_so,
            mode="auto",
            manual_post_key=manual_post_key,
            manual_xor_key=manual_xor_key,
        )
    if normalized_mode == "legacy":
        return decrypt_bundle_current(
            lib_so,
            resolved,
            native_so=native_so,
            mode="legacy",
            manual_post_key=manual_post_key,
            manual_xor_key=manual_xor_key,
        )
    if normalized_mode != "auto":
        raise ValueError("mode must be auto, current, legacy or legacy4")

    if len(resolved.sok) <= 4:
        try:
            return decrypt_bundle_legacy4(lib_so, resolved)
        except Exception:
            return decrypt_bundle_current(
                lib_so,
                resolved,
                native_so=native_so,
                mode="auto",
                manual_post_key=manual_post_key,
                manual_xor_key=manual_xor_key,
            )

    return decrypt_bundle_current(
        lib_so,
        resolved,
        native_so=native_so,
        mode="auto",
        manual_post_key=manual_post_key,
        manual_xor_key=manual_xor_key,
    )


def build_response(
    lib_so: bytes,
    config: DecryptConfig,
    native_so: Optional[bytes] = None,
    mode: str = "auto",
    manual_post_key: Optional[bytes] = None,
    manual_xor_key: Optional[bytes] = None,
) -> dict:
    resolved = resolve_config(config, native_so)
    container, extracted, failed, trace = decrypt_bundle(
        lib_so,
        resolved,
        native_so=native_so,
        mode=mode,
        manual_post_key=manual_post_key,
        manual_xor_key=manual_xor_key,
    )
    files: dict[str, str] = {}
    for name, content in sorted(extracted.items()):
        files[name] = content.decode("utf-8", errors="ignore")

    algorithm_family = trace.get("algorithm_family", b"").decode("utf-8", errors="ignore")
    files = filter_output_files(files, algorithm_family)

    strategy = {
        "algorithm_family": algorithm_family,
        "candidate": trace.get("candidate", b"").decode("utf-8", errors="ignore"),
        "key_set": trace.get("key_set", b"").decode("utf-8", errors="ignore"),
        "member_strategy": trace.get("member_strategy", b"").decode("utf-8", errors="ignore"),
        "outer_key_hex": trace.get("outer_key", b"").hex(),
        "post_key_hex": trace.get("post_key", b"").hex(),
        "xor_key_hex": trace.get("xor_key", b"").hex(),
        "resolved_sok": trace.get("resolved_sok", b"").decode("utf-8", errors="ignore"),
        "resolved_dek": trace.get("resolved_dek", b"").decode("utf-8", errors="ignore"),
        "sign_key": trace.get("sign_key", b"").decode("utf-8", errors="ignore"),
        "pwd_key": trace.get("pwd_key", b"").decode("utf-8", errors="ignore"),
        "sign_input": trace.get("sign_input", b"").decode("utf-8", errors="ignore"),
        "pwd_input": trace.get("pwd_input", b"").decode("utf-8", errors="ignore"),
        "pwd_source": trace.get("pwd_source", b"").decode("utf-8", errors="ignore"),
        "signature_used": bool(trace.get("signature")),
        "candidate_count": int(trace.get("candidate_count", b"0") or b"0"),
        "key_set_count": int(trace.get("key_set_count", b"0") or b"0"),
        "tried_count": int(trace.get("tried_count", b"0") or b"0"),
        "container_size": len(container),
    }

    return {
        "ok": True,
        "entry_file": normalize_member_name(resolved.entry_file),
        "files": files,
        "failed": failed,
        "strategy": strategy,
    }
