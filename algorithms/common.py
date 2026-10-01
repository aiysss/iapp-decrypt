"""算法公共类型、工具与成员解密编排。"""
from __future__ import annotations
import base64
import hashlib
import re
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from config import (
    CALL_PATTERN,
    FN_PATTERN,
    LEGACY_HIDDEN_OUTPUTS,
    MAGIC_BYTES,
    MAGIC_STRING,
    REFERENCE_PATTERN,
    REFERENCE_SUFFIXES,
)
from crypto.aes import aes_cbc_then_xor_decrypt, cyclic_xor
from crypto.slky import signed_div, signed_mod, slky, to_signed
from crypto.sok import extract_sok_from_so

@dataclass
class DecryptConfig:
    package_name: str
    version_name: str
    version_code: str
    app_name: str
    sok: str = ""
    dek: str = ""
    entry_file: str = "mian.iyu"
    sign_key: str = ""
    sign_b64: str = ""
    pwd_key: str = ""


@dataclass(frozen=True)
class MemberStrategy:
    marker_post_key: Optional[bytes]
    member_post_key: Optional[bytes]
    key_mode: str
    label: str


@dataclass(frozen=True)
class KeySet:
    name: str
    post_key: bytes
    xor_key: bytes

def normalize_member_name(name: str) -> str:
    return name.strip().strip("\"'").replace("\\", "/").lower()

def resolve_post_key_mode(mode: str, key_set: KeySet) -> Optional[bytes]:
    if mode == "magic_string":
        return MAGIC_STRING
    if mode == "magic_bytes":
        return MAGIC_BYTES
    if mode == "keyset":
        return key_set.post_key
    if mode == "nopost":
        return None
    raise ValueError(f"unknown post key mode: {mode}")


def resolve_config(config: DecryptConfig, native_so: Optional[bytes] = None) -> DecryptConfig:
    sok = (config.sok or "").strip()
    if not sok and native_so:
        auto_sok = extract_sok_from_so(native_so)
        if auto_sok:
            sok = auto_sok
    resolved = DecryptConfig(
        package_name=(config.package_name or "").strip(),
        version_name=(config.version_name or "").strip(),
        version_code=(config.version_code or "").strip(),
        app_name=(config.app_name or "").strip(),
        sok=sok,
        dek=(config.dek or "").strip(),
        entry_file=normalize_member_name(config.entry_file or "mian.iyu"),
        sign_key=(config.sign_key or "").strip(),
        sign_b64=(config.sign_b64 or "").strip(),
        pwd_key=(config.pwd_key or "").strip(),
    )
    missing = []
    for field_name in ("package_name", "version_name", "version_code", "app_name", "sok", "dek"):
        if not getattr(resolved, field_name):
            missing.append(field_name)
    if missing:
        raise ValueError("missing decrypt fields: " + ", ".join(missing))
    return resolved


def looks_like_iapp_plain(data: bytes) -> bool:
    head = data[:4096]
    needles = [
        b"<View",
        b"</View",
        b"<eventItme",
        b"<UIEventset",
        b"LinearLayout",
        b"function",
        b"fn ",
        b"call(",
        b"dim ",
        b"syso(",
    ]
    hits = sum(1 for item in needles if item in head)
    textish = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
    ratio = textish / max(1, len(head))
    return hits >= 2 or (hits >= 1 and ratio >= 0.65)


def build_outer_env(config: DecryptConfig) -> Dict[str, bytes]:
    env: Dict[str, bytes] = {}
    env["package_name"] = config.package_name.encode("utf-8")
    env["version_name"] = config.version_name.encode("utf-8")
    env["version_code"] = config.version_code.encode("utf-8")
    env["app_name"] = config.app_name.encode("utf-8")
    env["sok"] = config.sok.encode("utf-8")
    env["dek"] = config.dek.encode("utf-8")
    env["empty"] = b""
    env["sign_b64"] = re.sub(rb"\s+", b"", (config.sign_b64 or "").encode("utf-8"))
    try:
        env["signature"] = base64.b64decode(env["sign_b64"], validate=True) if env["sign_b64"] else b""
    except Exception:
        env["signature"] = b""
    env["entry_file"] = normalize_member_name(config.entry_file).encode("utf-8")
    env["base"] = env["sok"] + env["version_name"] + env["package_name"] + env["app_name"] + env["version_code"] + env["dek"]
    env["base_tail"] = env["version_name"] + env["package_name"] + env["app_name"] + env["version_code"] + env["dek"]
    env["sok_dek"] = env["sok"] + env["dek"]
    env["dek_sok"] = env["dek"] + env["sok"]
    return env


def idbfj_seed(env: Dict[str, bytes], password_name: Optional[str], mode: str, post_key: Optional[bytes]) -> Tuple[bytes, Dict[str, bytes]]:
    password = b""
    if password_name and password_name != "none":
        password = env[password_name]
    deriv = env["base"] + password
    if mode == "unsigned":
        case_idx = (sum(deriv) + len(deriv) + deriv[0] * deriv[-1]) % 6
    elif mode == "signed":
        signed_sum = sum(to_signed(b) for b in deriv) + len(deriv)
        case_idx = signed_mod(signed_sum + to_signed(deriv[0]) * to_signed(deriv[-1]), 6)
    else:
        raise ValueError(f"unknown idbfj mode: {mode}")
    seconds = [
        env["version_name"],
        env["package_name"],
        env["app_name"],
        env["version_code"],
        env["sok"],
        env["dek"],
    ]
    second = seconds[case_idx]
    return slky(deriv, second, post_key), {
        "idbfj_case": str(case_idx).encode("ascii"),
        "idbfj_mode": mode.encode("ascii"),
        "idbfj_password": password_name.encode("ascii") if password_name else b"none",
        "idbfj_second": second,
    }


def _idbfj_pick6(data: bytes) -> int:
    if not data:
        return 0
    signed_sum = len(data) + sum(to_signed(x) for x in data)
    value = signed_sum + to_signed(data[0]) * to_signed(data[-1])
    return signed_mod(value, 6)


class OuterCandidate:
    def __init__(self, name: str, confidence: int = 50):
        self.name = name
        self.confidence = confidence

    def derive(self, env: Dict[str, bytes], key_set: KeySet) -> Tuple[bytes, Dict[str, bytes]]:
        raise NotImplementedError

def derive_markers(file_name: str, config: DecryptConfig, marker_post_key: Optional[bytes]) -> Tuple[bytes, bytes]:
    name = normalize_member_name(file_name).encode("utf-8")
    start_marker = slky(name, (config.sok + config.dek).encode("utf-8"), marker_post_key)
    end_marker = slky(name, (config.dek + config.sok).encode("utf-8"), marker_post_key)
    return start_marker, end_marker


def derive_member_seed(file_name: str, config: DecryptConfig, member_post_key: Optional[bytes]) -> bytes:
    first = (normalize_member_name(file_name) + config.sok + config.dek).encode("utf-8")
    second = normalize_member_name(file_name).encode("utf-8")
    return slky(first, second, member_post_key)


def member_strategies(key_set: KeySet, preferred: Optional[MemberStrategy] = None) -> List[MemberStrategy]:
    variants = [
        MemberStrategy(key_set.post_key, key_set.post_key, "xor", "keyset/xor"),
        MemberStrategy(key_set.post_key, key_set.post_key, "direct", "keyset/direct"),
        MemberStrategy(MAGIC_STRING, MAGIC_STRING, "xor", "post/xor"),
        MemberStrategy(MAGIC_STRING, MAGIC_STRING, "direct", "post/direct"),
        MemberStrategy(None, None, "direct", "nopost/direct"),
        MemberStrategy(None, None, "xor", "nopost/xor"),
        MemberStrategy(MAGIC_STRING, None, "direct", "marker-post_key-nopost/direct"),
        MemberStrategy(MAGIC_STRING, None, "xor", "marker-post_key-nopost/xor"),
        MemberStrategy(None, MAGIC_STRING, "xor", "marker-nopost_key-post/xor"),
        MemberStrategy(key_set.post_key, MAGIC_STRING, "xor", "marker-keyset_key-post/xor"),
        MemberStrategy(MAGIC_STRING, key_set.post_key, "xor", "marker-post_key-keyset/xor"),
    ]
    ordered = []
    seen = set()
    if preferred:
        ordered.append(preferred)
    ordered.extend(variants)
    out = []
    for item in ordered:
        sig = (item.marker_post_key, item.member_post_key, item.key_mode)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(item)
    return out


def try_decrypt_member_with_strategy(
    container: bytes,
    file_name: str,
    config: DecryptConfig,
    xor_key: bytes,
    strategy: MemberStrategy,
) -> Optional[bytes]:
    start_marker, end_marker = derive_markers(file_name, config, strategy.marker_post_key)
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
    seed = derive_member_seed(file_name, config, strategy.member_post_key)
    if strategy.key_mode == "xor":
        member_key = cyclic_xor(seed, xor_key)[:16]
    elif strategy.key_mode == "direct":
        member_key = seed[:16]
    else:
        raise ValueError(f"unknown key mode: {strategy.key_mode}")
    try:
        return aes_cbc_then_xor_decrypt(blob, member_key)
    except Exception:
        return None


def verify_outer_candidate(
    lib_so: bytes,
    config: DecryptConfig,
    key_set: KeySet,
    candidate: OuterCandidate,
) -> Optional[Tuple[bytes, bytes, Dict[str, bytes], MemberStrategy, bytes]]:
    env = build_outer_env(config)
    try:
        outer_key, trace = candidate.derive(env, key_set)
    except Exception:
        return None
    try:
        container = aes_cbc_then_xor_decrypt(lib_so, outer_key)
    except Exception:
        return None

    entry_name = normalize_member_name(config.entry_file)
    for strategy in member_strategies(key_set):
        plain = try_decrypt_member_with_strategy(container, entry_name, config, key_set.xor_key, strategy)
        if plain is None:
            continue
        if not looks_like_iapp_plain(plain):
            continue
        trace["member_strategy"] = strategy.label.encode("utf-8")
        trace["candidate"] = candidate.name.encode("utf-8")
        trace["key_set"] = key_set.name.encode("utf-8")
        trace["post_key"] = key_set.post_key
        trace["xor_key"] = key_set.xor_key
        return outer_key, container, trace, strategy, plain
    return None


def scan_member_references(content: bytes) -> set[str]:
    text = content.decode("utf-8", errors="ignore")
    refs = set()

    for match in REFERENCE_PATTERN.finditer(text):
        refs.add(normalize_member_name(match.group(1)))

    for match in FN_PATTERN.finditer(text):
        module_name = match.group(1)
        refs.add(normalize_member_name(module_name + ".myu"))

    for match in CALL_PATTERN.finditer(text):
        ext = match.group(1).strip()
        module_name = match.group(2).strip()
        refs.add(normalize_member_name(module_name + "." + ext))

    return {ref for ref in refs if ref.rsplit(".", 1)[-1] in REFERENCE_SUFFIXES}


def crawl_members(
    container: bytes,
    config: DecryptConfig,
    key_set: KeySet,
    preferred_strategy: MemberStrategy,
) -> Tuple[dict[str, bytes], list[dict[str, str]]]:
    queue: deque[str] = deque([normalize_member_name(config.entry_file)])
    seen: set[str] = set()
    extracted: dict[str, bytes] = {}
    failed: list[dict[str, str]] = []

    while queue:
        current = queue.popleft()
        if current in seen:
            continue
        seen.add(current)
        content = None
        for strategy in member_strategies(key_set, preferred_strategy):
            content = try_decrypt_member_with_strategy(container, current, config, key_set.xor_key, strategy)
            if content is not None:
                break
        if content is None:
            failed.append({"name": current, "error": "all member strategies failed"})
            continue

        extracted[current] = content
        refs = scan_member_references(content)
        for ref in sorted(refs):
            if ref not in seen:
                queue.append(ref)

    return extracted, failed


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def filter_output_files(files: dict[str, str], algorithm_family: str) -> dict[str, str]:
    if algorithm_family != "legacy4":
        return files
    return {
        name: content
        for name, content in files.items()
        if name not in LEGACY_HIDDEN_OUTPUTS
    }
