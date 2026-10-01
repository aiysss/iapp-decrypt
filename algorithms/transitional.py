"""transitional(mete) 算法族。"""
from __future__ import annotations
from collections import deque
from typing import Dict, Tuple

from crypto.aes import aes_cbc_decrypt_only
from crypto.slky import slky

from algorithms.common import (
    DecryptConfig,
    KeySet,
    OuterCandidate,
    build_outer_env,
    normalize_member_name,
    scan_member_references,
)

def _idbfj_pick6_unsigned(data: bytes) -> int:
    if not data:
        return 0
    return (len(data) + sum(data) + data[0] * data[-1]) % 6

class TransitionalOuterCandidate(OuterCandidate):
    """过渡期 (mete::slky) 算法族：slky 无 post_key、pick6 unsigned、AES 无 xor_key。

    对应 1.apk 的 libygsiyu.so（`iapp::mete::slky` + `iapp::burden::b`）。outer key 派生：
      first = sok + version_name + package_name + app_name + version_code + dek
      pick  = (len(first) + sum(first) + first[0]*first[-1]) % 6  (unsigned)
      second = [version_name, package_name, app_name, version_code, sok, dek][pick]
      p19 = slky(first, second, None)
      p24 = slky(signature_der, p19, None) if 签名校验关闭 else slky(p19, p19, None)
      p25 = slky(p19, p24, None)
      outer_key = p25[:16]
    """

    def __init__(self, name: str = "transitional:unsigned:none:p19_sig_p25:direct", confidence: int = 97):
        super().__init__(name, confidence)

    def derive(self, env: Dict[str, bytes], key_set: KeySet) -> Tuple[bytes, Dict[str, bytes]]:
        signature = env.get("signature") or b""
        first = env["base"]
        seconds = [
            env["version_name"],
            env["package_name"],
            env["app_name"],
            env["version_code"],
            env["sok"],
            env["dek"],
        ]
        pick = _idbfj_pick6_unsigned(first)
        second = seconds[pick]
        p19 = slky(first, second, None)
        if signature:
            p24 = slky(signature, p19, None)
        else:
            p24 = slky(p19, p19, None)
        p25 = slky(p19, p24, None)
        outer_key = p25[:16]
        return outer_key, {
            "candidate": self.name.encode("utf-8"),
            "key_set": key_set.name.encode("utf-8"),
            "outer_key": outer_key,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "transform": b"direct",
            "idbfj_first": first,
            "idbfj_pick": str(pick).encode("ascii"),
            "idbfj_second": second,
            "signature": signature,
            "algorithm": b"transitional: mete::slky(post_key=None), pick6 unsigned, AES-CBC key=iv=p25, no xor",
        }

def _try_transitional_member(container: bytes, file_name: str, config: DecryptConfig) -> Optional[bytes]:
    name = normalize_member_name(file_name).encode("utf-8")
    start_marker = slky(name, (config.sok + config.dek).encode("utf-8"), None)
    end_marker = slky(name, (config.dek + config.sok).encode("utf-8"), None)
    start = container.find(start_marker)
    if start == -1:
        return None
    payload_start = start + len(start_marker)
    end = container.find(end_marker, payload_start)
    if end == -1:
        return None
    blob = container[payload_start:end]
    if len(blob) % 16:
        return None
    seed = slky(name + (config.sok + config.dek).encode("utf-8"), name, None)
    try:
        return aes_cbc_decrypt_only(blob, seed[:16])
    except Exception:
        return None


def decrypt_bundle_transitional(lib_so: bytes, config: DecryptConfig) -> Tuple[bytes, dict[str, bytes], list[dict[str, str]], Dict[str, bytes]]:
    env = build_outer_env(config)
    key_set = KeySet("transitional:nopost:noxor", b"", b"")
    candidate = TransitionalOuterCandidate()
    outer_key, trace = candidate.derive(env, key_set)
    container = aes_cbc_decrypt_only(lib_so, outer_key)

    extracted: dict[str, bytes] = {}
    failed: list[dict[str, str]] = []
    queue: deque[str] = deque([normalize_member_name(config.entry_file)])
    seen: set[str] = set()
    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        content = _try_transitional_member(container, current, config)
        if content is None:
            failed.append({"name": current, "error": "transitional member decrypt failed"})
            continue
        extracted[current] = content
        for ref in sorted(scan_member_references(content)):
            if ref not in seen:
                queue.append(ref)

    trace["outer_key"] = outer_key
    trace["resolved_sok"] = config.sok.encode("utf-8")
    trace["resolved_dek"] = config.dek.encode("utf-8")
    trace["candidate_count"] = b"1"
    trace["key_set_count"] = b"1"
    trace["tried_count"] = b"1"
    trace["post_key"] = b""
    trace["xor_key"] = b""
    trace["algorithm_family"] = b"transitional"
    return container, extracted, failed, trace
