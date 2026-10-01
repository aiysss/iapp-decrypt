"""分片上传与文件令牌。"""
import cgi
import hashlib
import json
import os
import re
import secrets
import shutil
import threading
from datetime import datetime
from typing import Optional

from config import (
    UPLOAD_CHUNK_SIZE,
    UPLOAD_MAX_SIZE,
    UPLOAD_STORE_DIR,
    UPLOAD_TMP_DIR,
)

_upload_lock = threading.Lock()

def _parse_optional_hex_field(form: cgi.FieldStorage, name: str) -> Optional[bytes]:
    raw = form.getfirst(name, "").strip()
    return _parse_optional_hex_value(raw, name)


def _parse_optional_hex_value(raw: str, name: str) -> Optional[bytes]:
    if not raw:
        return None
    cleaned = re.sub(r"[^0-9a-fA-F]", "", raw)
    if not cleaned:
        return None
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{name} must contain an even number of hex digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex for {name}: {exc}") from exc


def _iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _upload_session_dir(upload_id: str) -> str:
    return os.path.join(UPLOAD_TMP_DIR, upload_id)


def _upload_session_meta_path(upload_id: str) -> str:
    return os.path.join(_upload_session_dir(upload_id), "meta.json")


def _upload_chunk_path(upload_id: str, index: int) -> str:
    return os.path.join(_upload_session_dir(upload_id), f"chunk_{index:08d}.part")


def _stored_upload_file_path(token: str) -> str:
    return os.path.join(UPLOAD_STORE_DIR, f"{token}.bin")


def _stored_upload_meta_path(token: str) -> str:
    return os.path.join(UPLOAD_STORE_DIR, f"{token}.json")


def _ensure_hex_token(value: str, name: str = "token") -> str:
    cleaned = (value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", cleaned):
        raise ValueError(f"invalid {name}")
    return cleaned


def _load_json_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"invalid json payload in {path}")
    return data


def _write_json_file(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _create_upload_session(filename: str, size: int, purpose: str = "") -> dict:
    if size <= 0:
        raise ValueError("上传文件不能为空")
    if size > UPLOAD_MAX_SIZE:
        raise ValueError(f"文件大小超过限制 (最大 {UPLOAD_MAX_SIZE // (1024 * 1024)}MB)")
    upload_id = secrets.token_hex(16)
    session_dir = _upload_session_dir(upload_id)
    os.makedirs(session_dir, exist_ok=False)
    total_chunks = (size + UPLOAD_CHUNK_SIZE - 1) // UPLOAD_CHUNK_SIZE
    meta = {
        "upload_id": upload_id,
        "filename": filename or "upload.bin",
        "size": int(size),
        "purpose": purpose or "",
        "chunk_size": UPLOAD_CHUNK_SIZE,
        "total_chunks": total_chunks,
        "created_at": _iso_now(),
    }
    _write_json_file(_upload_session_meta_path(upload_id), meta)
    return meta


def _load_upload_session(upload_id: str) -> dict:
    upload_id = _ensure_hex_token(upload_id, "upload_id")
    meta_path = _upload_session_meta_path(upload_id)
    if not os.path.exists(meta_path):
        raise FileNotFoundError("upload session not found")
    meta = _load_json_file(meta_path)
    meta["upload_id"] = upload_id
    return meta


def _store_upload_chunk(upload_id: str, index: int, chunk: bytes) -> dict:
    meta = _load_upload_session(upload_id)
    total_chunks = int(meta.get("total_chunks", 0))
    chunk_size = int(meta.get("chunk_size", UPLOAD_CHUNK_SIZE))
    total_size = int(meta.get("size", 0))
    if index < 0 or index >= total_chunks:
        raise ValueError("chunk index out of range")
    max_chunk_size = chunk_size
    if index == total_chunks - 1:
        consumed = chunk_size * (total_chunks - 1)
        max_chunk_size = max(total_size - consumed, 0)
    if len(chunk) > max_chunk_size:
        raise ValueError("chunk too large")
    path = _upload_chunk_path(meta["upload_id"], index)
    with open(path, "wb") as f:
        f.write(chunk)
    return meta


def _finalize_upload_session(upload_id: str, expected_sha256: str = "") -> dict:
    meta = _load_upload_session(upload_id)
    upload_id = meta["upload_id"]
    total_chunks = int(meta["total_chunks"])
    os.makedirs(UPLOAD_STORE_DIR, exist_ok=True)
    token = secrets.token_hex(16)
    stored_file = _stored_upload_file_path(token)
    sha256 = hashlib.sha256()
    total_size = 0
    with open(stored_file, "wb") as dst:
        for index in range(total_chunks):
            chunk_path = _upload_chunk_path(upload_id, index)
            if not os.path.exists(chunk_path):
                raise ValueError(f"missing chunk: {index}")
            with open(chunk_path, "rb") as src:
                data = src.read()
            dst.write(data)
            sha256.update(data)
            total_size += len(data)
    if total_size != int(meta["size"]):
        try:
            os.remove(stored_file)
        except OSError:
            pass
        raise ValueError("assembled file size mismatch")
    file_sha256 = sha256.hexdigest()
    expected_sha256 = (expected_sha256 or "").strip().lower()
    if expected_sha256 and expected_sha256 != file_sha256:
        try:
            os.remove(stored_file)
        except OSError:
            pass
        raise ValueError("sha256 mismatch")
    stored_meta = {
        "token": token,
        "filename": meta.get("filename") or "upload.bin",
        "size": total_size,
        "purpose": meta.get("purpose") or "",
        "sha256": file_sha256,
        "stored_at": _iso_now(),
    }
    _write_json_file(_stored_upload_meta_path(token), stored_meta)
    shutil.rmtree(_upload_session_dir(upload_id), ignore_errors=True)
    return stored_meta


def _load_stored_upload(token: str) -> tuple[dict, bytes]:
    token = _ensure_hex_token(token)
    meta_path = _stored_upload_meta_path(token)
    data_path = _stored_upload_file_path(token)
    if not os.path.exists(meta_path) or not os.path.exists(data_path):
        raise FileNotFoundError("uploaded file not found")
    meta = _load_json_file(meta_path)
    with open(data_path, "rb") as f:
        data = f.read()
    return meta, data


def _load_token_file_from_json(data: dict, field_name: str, required: bool = True) -> tuple[Optional[dict], Optional[bytes]]:
    token = str(data.get(f"{field_name}_token", "")).strip().lower()
    if not token:
        if required:
            raise ValueError(f"missing field: {field_name}_token")
        return None, None
    meta, payload = _load_stored_upload(token)
    return meta, payload
