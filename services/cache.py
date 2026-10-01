"""解密结果缓存。"""
import hashlib
import json
import os
import re
import threading
from datetime import datetime
from typing import Optional

from config import CACHE_DIR
from algorithms.common import filter_output_files

_cache_lock = threading.Lock()

def _lib_cache_path(lib_sha256: str) -> str:
    return os.path.join(CACHE_DIR, f"{lib_sha256}.json")


def _read_cached_payload(lib_so: bytes) -> Optional[dict]:
    lib_sha256 = hashlib.sha256(lib_so).hexdigest()
    return _lookup_cached_payload_by_sha256(lib_sha256)


def _write_cached_payload(lib_so: bytes, payload: dict) -> None:
    if not payload.get("ok"):
        return
    os.makedirs(CACHE_DIR, exist_ok=True)
    lib_sha256 = hashlib.sha256(lib_so).hexdigest()
    cache_path = _lib_cache_path(lib_sha256)
    cache_record = {
        "lib_sha256": lib_sha256,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "payload": payload,
    }
    with _cache_lock:
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_record, f, ensure_ascii=False, indent=2)


def _lookup_cached_payload_by_sha256(lib_sha256: str) -> Optional[dict]:
    cleaned = (lib_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", cleaned):
        return None
    cache_path = _lib_cache_path(cleaned)
    if not os.path.exists(cache_path):
        return None
    try:
        with _cache_lock:
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
        payload = cached.get("payload")
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        payload = dict(payload)
        strategy = payload.get("strategy")
        if isinstance(strategy, dict):
            strategy = dict(strategy)
            strategy.pop("sign_source", None)
            payload["strategy"] = strategy
        files = payload.get("files")
        algorithm_family = strategy.get("algorithm_family", "") if isinstance(strategy, dict) else ""
        if isinstance(files, dict):
            payload["files"] = filter_output_files(dict(files), algorithm_family)
        payload["cache_hit"] = True
        payload["cache_message"] = "成功命中缓存，已直接返回历史解密结果"
        payload["message"] = payload["cache_message"]
        payload["cache_key"] = cleaned
        payload["cache_scope"] = "libso_sha256"
        return payload
    except (OSError, json.JSONDecodeError):
        return None
