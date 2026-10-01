"""legacy4(远古) 算法族。"""
from __future__ import annotations
import base64
import hashlib
import re
from typing import Dict, List, Optional, Tuple

from Crypto.Cipher import AES

from config import (
    LEGACY_CALL_MODULE_RE,
    LEGACY_DEFAULT_PWD_KEY,
    LEGACY_DEFAULT_SIGN_KEY,
    LEGACY_HIDDEN_OUTPUTS,
    LEGACY_LOCAL_MARKER,
    LEGACY_REFERENCE_RE,
    LEGACY_WZYANG_JMXY_3,
    LEGACY_WZYANG_JMXY_4,
)
from algorithms.common import DecryptConfig, md5_hex

def legacy_clean_base64(data: bytes) -> bytes:
    return re.sub(rb"\s+", b"", data or b"")


def legacy_fix_base64_padding(data: bytes) -> bytes:
    missing = len(data) % 4
    if missing:
        data += b"=" * (4 - missing)
    return data


def legacy_trim_plain(data: bytes) -> bytes:
    if not data:
        return data
    if 1 <= data[-1] <= 16 and data.endswith(bytes([data[-1]]) * data[-1]):
        data = data[:-data[-1]]
    return data.rstrip(b"\x00")


def legacy_aes_cbc_decrypt_b64(cipher_b64: bytes, key_text: str) -> bytes:
    key = key_text.encode("utf-8")
    cipher = AES.new(key[:16], AES.MODE_CBC, iv=key[:16])
    ciphertext = base64.b64decode(legacy_fix_base64_padding(legacy_clean_base64(cipher_b64)))
    return cipher.decrypt(ciphertext)


def legacy_substring_between(text: str, start: str, end: str) -> Optional[str]:
    start_idx = text.find(start)
    if start_idx < 0:
        return None
    start_idx += len(start)
    end_idx = text.find(end, start_idx)
    if end_idx < 0:
        return None
    return text[start_idx:end_idx]


def legacy_safe_b64decode_to_text(value: str) -> str:
    raw = legacy_fix_base64_padding(legacy_clean_base64(value.encode("latin1", errors="ignore")))
    return base64.b64decode(raw).decode("utf-8", errors="ignore")


def legacy_legacy4_sign_candidates(config: DecryptConfig) -> List[Tuple[str, str]]:
    raw = (config.sign_key or "").strip()
    out: List[Tuple[str, str]] = []
    if raw:
        out.append(("manual-input", raw))
        out.append(("cert-md5-derived", md5_hex(raw + LEGACY_WZYANG_JMXY_3 + config.sok)))
    out.append(("default-null", LEGACY_DEFAULT_SIGN_KEY))
    seen = set()
    deduped: List[Tuple[str, str]] = []
    for label, value in out:
        if value in seen:
            continue
        seen.add(value)
        deduped.append((label, value))
    return deduped


def legacy_legacy4_pwd_candidates(config: DecryptConfig) -> List[Tuple[str, str]]:
    raw = (config.pwd_key or "").strip()
    out: List[Tuple[str, str]] = []
    if raw:
        out.append(("manual-input", raw))
        out.append(("password-derived", md5_hex(raw + LEGACY_WZYANG_JMXY_4)))
    out.append(("default-empty", LEGACY_DEFAULT_PWD_KEY))
    seen = set()
    deduped: List[Tuple[str, str]] = []
    for label, value in out:
        if value in seen:
            continue
        seen.add(value)
        deduped.append((label, value))
    return deduped


def legacy_local_lib_key(config: DecryptConfig, sign_key: str, pwd_key: str) -> str:
    app_key = md5_hex(config.app_name + config.version_name + config.package_name + config.version_code)
    half_lib_key = md5_hex(
        config.dek + config.sok + app_key + sign_key + pwd_key
    )
    return half_lib_key[16:32]


def legacy_find_segment_names(outer_text: str) -> List[str]:
    head = outer_text.split(LEGACY_LOCAL_MARKER, 1)[0]
    names: List[str] = []
    for item in head.split("=/"):
        item = item.strip()
        if not item:
            continue
        try:
            decoded = legacy_safe_b64decode_to_text(item)
        except Exception:
            continue
        if decoded:
            names.append(decoded)
    return names


def legacy_file_markers(so_key: str, index: int) -> Tuple[str, str]:
    key_md5 = md5_hex(so_key + "iapp" + str(index))
    keys_md5 = md5_hex(so_key + "ysiapp" + str(index))
    start_marker = base64.b64encode(keys_md5.encode("utf-8")).decode("ascii").replace("\n", "")
    end_marker = base64.b64encode(key_md5.encode("utf-8")).decode("ascii").replace("\n", "")
    return start_marker, end_marker


def legacy_decrypt_member(outer_text: str, so_key: str, index: int, file_name: str) -> Optional[bytes]:
    start_marker, end_marker = legacy_file_markers(so_key, index)
    encrypted_segment = legacy_substring_between(outer_text, start_marker, end_marker)
    if not encrypted_segment:
        return None
    keys_md5 = md5_hex(so_key + "ysiapp" + str(index))
    decrypt_key = md5_hex(so_key + keys_md5 + file_name)[16:32]
    try:
        return legacy_trim_plain(
            legacy_aes_cbc_decrypt_b64(encrypted_segment.encode("latin1", errors="ignore"), decrypt_key)
        )
    except Exception:
        return None


def legacy_discover_reference_names(text: str) -> List[str]:
    names: List[str] = []
    for match in LEGACY_REFERENCE_RE.finditer(text):
        file_name = match.group(0)
        if not file_name:
            continue
        if file_name.startswith("fn "):
            item = file_name[3:] + ".myu"
        elif file_name.startswith("call("):
            module_match = LEGACY_CALL_MODULE_RE.search(file_name)
            quoted = re.search(r'"([^"]+)"', file_name)
            if not module_match or not quoted:
                continue
            item = module_match.group(1) + quoted.group(1)
        else:
            item = file_name
        if item not in names:
            names.append(item)
    return names


def legacy_move_alias(files: dict[str, bytes], src: str, dst: str) -> None:
    if src in files and dst not in files:
        files[dst] = files.pop(src)


def legacy_apply_fixed_aliases(files: dict[str, bytes], so_key: str) -> None:
    for name in ("import.mjs", "import.mlua", "mian.iyu"):
        legacy_move_alias(files, md5_hex(so_key + "ysiapp" + name), name)


def legacy_apply_reference_aliases(files: dict[str, bytes], so_key: str) -> None:
    changed = True
    while changed:
        changed = False
        for _, content in list(files.items()):
            text = content.decode("utf-8", errors="ignore")
            for name in legacy_discover_reference_names(text):
                hashed = md5_hex(so_key + "ysiapp" + name)
                if hashed in files and name not in files:
                    files[name] = files.pop(hashed)
                    changed = True

def decrypt_bundle_legacy4(
    lib_so: bytes,
    config: DecryptConfig,
) -> Tuple[bytes, dict[str, bytes], list[dict[str, str]], Dict[str, bytes]]:
    sign_candidates = legacy_legacy4_sign_candidates(config)
    pwd_candidates = legacy_legacy4_pwd_candidates(config)
    tried = 0

    for sign_source, sign_value in sign_candidates:
        for pwd_source, pwd_value in pwd_candidates:
            tried += 1
            lib_key = legacy_local_lib_key(config, sign_value, pwd_value)
            try:
                outer_plain = legacy_trim_plain(legacy_aes_cbc_decrypt_b64(lib_so, lib_key))
            except Exception:
                continue
            outer_text = outer_plain.decode("latin1", errors="ignore")
            if LEGACY_LOCAL_MARKER not in outer_text:
                continue

            names = legacy_find_segment_names(outer_text)
            extracted: dict[str, bytes] = {}
            failed: list[dict[str, str]] = []
            for idx, file_name in enumerate(names):
                content = legacy_decrypt_member(outer_text, config.sok, idx, file_name)
                if content is None:
                    failed.append({"name": file_name, "error": "legacy4 member decrypt failed"})
                    continue
                extracted[file_name] = content

            legacy_apply_fixed_aliases(extracted, config.sok)
            legacy_apply_reference_aliases(extracted, config.sok)

            trace: Dict[str, bytes] = {
                "candidate": b"legacy4:local",
                "key_set": f"{sign_source}|{pwd_source}".encode("utf-8"),
                "member_strategy": b"md5/base64/aes-cbc",
                "outer_key": lib_key.encode("utf-8"),
                "resolved_sok": config.sok.encode("utf-8"),
                "resolved_dek": config.dek.encode("utf-8"),
                "candidate_count": str(len(sign_candidates)).encode("ascii"),
                "key_set_count": str(len(pwd_candidates)).encode("ascii"),
                "tried_count": str(tried).encode("ascii"),
                "post_key": b"",
                "xor_key": b"",
                "algorithm_family": b"legacy4",
                "sign_key": sign_value.encode("utf-8"),
                "pwd_key": pwd_value.encode("utf-8"),
                "sign_input": config.sign_key.encode("utf-8"),
                "pwd_input": config.pwd_key.encode("utf-8"),
                "pwd_source": pwd_source.encode("utf-8"),
            }
            return outer_plain, extracted, failed, trace

    raise RuntimeError(f"legacy4 decrypt failed after trying {tried} candidate combinations")
