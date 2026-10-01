"""HTTP 请求处理与路由。"""
import cgi
import hashlib
import json
import mimetypes
import os
import re
import shutil
import zipfile
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from typing import List, Optional
from urllib.parse import parse_qs, urlparse

from config import CACHE_DIR, REPAIR_DIR, UPLOAD_CHUNK_SIZE, UPLOAD_MAX_SIZE
from services.cache import (
    _lib_cache_path,
    _lookup_cached_payload_by_sha256,
    _read_cached_payload,
    _write_cached_payload,
)
from services.log import _log_request, _safe_filename
from services.upload import (
    _create_upload_session,
    _ensure_hex_token,
    _finalize_upload_session,
    _load_stored_upload,
    _load_token_file_from_json,
    _parse_optional_hex_field,
    _parse_optional_hex_value,
    _store_upload_chunk,
    _upload_lock,
)
from services.apk_extract import ApkExtractor
from services.repair import _repair_output_path, _save_repair_output, repair_source_bundle
from services.decrypt import build_response
from algorithms.common import DecryptConfig
from crypto.elf import extract_key_candidates_from_so

class DecryptHandler(BaseHTTPRequestHandler):
    server_version = "IAppDecryptAPI/1.0"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/repair_download":
            self._handle_repair_download(parsed)
            return

        # 健康检查端点
        if self.path == "/health":
            payload = {
                "ok": True,
                "service": "iapp-decrypt-api",
                "endpoints": {
                    "POST /decrypt": "multipart/form-data or application/json with file tokens",
                    "POST /cache_lookup": "lookup cached result by libso sha256",
                    "POST /extract_apk": "extract params from multipart apk or apk_token json",
                    "POST /extract_libs": "extract post_key/xor_key from multipart lib.zip or libzip_token json",
                    "POST /repair_dynamic": "repair source from multipart files or dexzip_token/srczip_token json",
                    "POST /upload_init": "create chunk upload session",
                    "POST /upload_chunk?upload_id=...&index=...": "upload a file chunk as raw bytes",
                    "POST /upload_complete": "finalize chunk upload and return file token",
                    "GET /repair_download?token=...": "download repaired source zip",
                    "GET /": "static index.html",
                },
            }
            resp_status = HTTPStatus.OK
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(resp_status, payload)
            _log_request(self, "GET", "health", None, None, resp_status.value, resp_body)
            return

        # 静态文件服务（包括根路径 / 和 /result.html 等）
        self._serve_static()

    def do_POST(self) -> None:
        method = "POST"
        parsed = urlparse(self.path)
        request_path = parsed.path
        
        if request_path == "/extract_apk":
            self._handle_extract_apk()
            return
        if request_path == "/extract_libs":
            self._handle_extract_libs()
            return
        if request_path == "/repair_dynamic":
            self._handle_repair_dynamic()
            return
        if request_path == "/cache_lookup":
            self._handle_cache_lookup()
            return
        if request_path == "/upload_init":
            self._handle_upload_init()
            return
        if request_path == "/upload_chunk":
            self._handle_upload_chunk()
            return
        if request_path == "/upload_complete":
            self._handle_upload_complete()
            return
            
        # 路径错误
        if request_path != "/decrypt":
            resp_status = HTTPStatus.NOT_FOUND
            error_msg = "not found"
            self.send_error(resp_status, error_msg)
            _log_request(
                self,
                method,
                "unknown",
                None,
                None,
                resp_status.value,
                error_msg,
                error=error_msg,
            )
            return

        # 正常处理（可能抛出异常）
        form_fields = {}
        file_info = None
        app_name = "unknown"
        try:
            content_type = self.headers.get("Content-Type", "")
            text_fields = [
                "package_name",
                "version_name",
                "version_code",
                "app_name",
                "sok",
                "dek",
                "sign_key",
                "sign_b64",
                "pwd_key",
                "post_key",
                "xor_key",
                "entry_file",
                "format",
                "mode",
            ]
            if "application/json" in content_type:
                data = self._read_json_body()
                for field in text_fields:
                    val = str(data.get(field, "") or "").strip()
                    if val:
                        form_fields[field] = val
                app_name = form_fields.get("app_name", "unknown")
                response_format = str(data.get("format", "json")).strip().lower()
                if response_format not in {"text", "json"}:
                    raise ValueError("format must be text or json")
                lib_meta, lib_so = _load_token_file_from_json(data, "libso", required=True)
                assert lib_meta is not None and lib_so is not None
                if not lib_so:
                    raise ValueError("libso is empty")
                file_info = {
                    "filename": lib_meta["filename"],
                    "size": len(lib_so),
                }
                config = DecryptConfig(
                    package_name=str(data.get("package_name", "")).strip(),
                    version_name=str(data.get("version_name", "")).strip(),
                    version_code=str(data.get("version_code", "")).strip(),
                    app_name=str(data.get("app_name", "")).strip(),
                    sok=str(data.get("sok", "")).strip(),
                    dek=str(data.get("dek", "")).strip(),
                    entry_file=str(data.get("entry_file", "mian.iyu")),
                    sign_key=str(data.get("sign_key", "")).strip(),
                    sign_b64=str(data.get("sign_b64", "")).strip(),
                    pwd_key=str(data.get("pwd_key", "")).strip(),
                )
                decrypt_mode = str(data.get("mode", "auto")).strip().lower()
                manual_post_key = _parse_optional_hex_value(str(data.get("post_key", "")).strip(), "post_key")
                manual_xor_key = _parse_optional_hex_value(str(data.get("xor_key", "")).strip(), "xor_key")
                native_meta, native_so = _load_token_file_from_json(data, "native_so", required=False)
                native_so_filename = native_meta["filename"] if native_meta else None
            else:
                form = self._parse_multipart()

                for field in text_fields:
                    val = form.getfirst(field)
                    if val:
                        form_fields[field] = val

                app_name = form_fields.get("app_name", "unknown")
                response_format = form.getfirst("format", "json").strip().lower()
                if response_format not in {"text", "json"}:
                    raise ValueError("format must be text or json")

                if "libso" not in form:
                    raise ValueError("missing field: libso")
                file_item = form["libso"]
                lib_so = file_item.file.read()
                if not lib_so:
                    raise ValueError("libso is empty")

                file_info = {
                    "filename": file_item.filename,
                    "size": len(lib_so),
                }
                config = DecryptConfig(
                    package_name=self._require_field(form, "package_name"),
                    version_name=self._require_field(form, "version_name"),
                    version_code=self._require_field(form, "version_code"),
                    app_name=self._require_field(form, "app_name"),
                    sok=form.getfirst("sok", "").strip(),
                    dek=self._require_field(form, "dek"),
                    entry_file=form.getfirst("entry_file", "mian.iyu"),
                    sign_key=form.getfirst("sign_key", "").strip(),
                    sign_b64=form.getfirst("sign_b64", "").strip(),
                    pwd_key=form.getfirst("pwd_key", "").strip(),
                )
                decrypt_mode = form.getfirst("mode", "auto").strip().lower()
                manual_post_key = _parse_optional_hex_field(form, "post_key")
                manual_xor_key = _parse_optional_hex_field(form, "xor_key")

                native_so = None
                native_so_filename = None
                if "native_so" in form and getattr(form["native_so"], "file", None) is not None:
                    native_so_filename = form["native_so"].filename
                    native_so = form["native_so"].file.read()
                    if native_so == b"":
                        native_so = None

            if decrypt_mode not in {"auto", "current", "legacy", "legacy4"}:
                raise ValueError("mode must be auto, current, legacy or legacy4")

            if not config.package_name:
                raise ValueError("missing field: package_name")
            if not config.version_name:
                raise ValueError("missing field: version_name")
            if not config.version_code:
                raise ValueError("missing field: version_code")
            if not config.app_name:
                raise ValueError("missing field: app_name")
            if not config.dek:
                raise ValueError("missing field: dek")

            # region debug-point decrypt-request-file-sizes
            form_fields["_debug_libso_size"] = str(len(lib_so))
            form_fields["_debug_has_native_so"] = "yes" if native_so is not None else "no"
            form_fields["_debug_native_so_size"] = str(len(native_so) if native_so else 0)
            if native_so_filename:
                form_fields["_debug_native_so_name"] = native_so_filename
            # endregion debug-point decrypt-request-file-sizes
            if native_so:
                file_info["native_so_size"] = len(native_so)

            payload = build_response(
                lib_so,
                config,
                native_so=native_so,
                mode=decrypt_mode,
                manual_post_key=manual_post_key,
                manual_xor_key=manual_xor_key,
            )
            payload["cache_hit"] = False
            payload["cache_message"] = ""
            payload["message"] = "解密成功"
            payload["cache_key"] = hashlib.sha256(lib_so).hexdigest()
            payload["cache_scope"] = "libso_sha256"
            _write_cached_payload(lib_so, payload)
            form_fields["_cache_hit"] = "no"
            resp_status = HTTPStatus.OK
            if response_format == "json":
                resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
                self._write_json(resp_status, payload)
            else:
                resp_body = self._format_source_bundle(payload)
                self._write_text(resp_status, resp_body)

            _log_request(
                self,
                method,
                app_name,
                form_fields,
                file_info,
                resp_status.value,
                resp_body,
            )

        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            resp_body_dict = {"ok": False, "error": error_msg}
            resp_body = json.dumps(resp_body_dict, ensure_ascii=False, indent=2)
            self._write_json(resp_status, resp_body_dict)

            # 尽可能收集已解析的信息
            try:
                if "form" in locals():
                    app_name = form.getfirst("app_name", "unknown")
                    for field in [
                        "package_name",
                        "version_name",
                        "version_code",
                        "app_name",
                        "sok",
                        "dek",
                        "sign_key",
                        "sign_b64",
                        "pwd_key",
                        "post_key",
                        "xor_key",
                        "entry_file",
                        "format",
                        "mode",
                    ]:
                        val = form.getfirst(field)
                        if val:
                            form_fields[field] = val
                    if "libso" in form:
                        file_item = form["libso"]
                        file_info = {
                            "filename": file_item.filename,
                            "size": 0,
                        }  # 未成功读取，大小未知
                elif "data" in locals():
                    app_name = str(data.get("app_name", "unknown")).strip() or "unknown"
                    for field in [
                        "package_name",
                        "version_name",
                        "version_code",
                        "app_name",
                        "sok",
                        "dek",
                        "sign_key",
                        "sign_b64",
                        "pwd_key",
                        "post_key",
                        "xor_key",
                        "entry_file",
                        "format",
                        "mode",
                    ]:
                        val = str(data.get(field, "") or "").strip()
                        if val:
                            form_fields[field] = val
            except Exception:
                pass

            _log_request(
                self,
                method,
                app_name,
                form_fields if form_fields else None,
                file_info,
                resp_status.value,
                resp_body,
                error=error_msg,
            )

    def log_message(self, format: str, *args) -> None:
        return

    # ---------- 静态文件服务 ----------
    def _serve_static(self) -> None:
        """从 ./temp 目录安全地提供静态文件"""
        # 确定请求的文件路径（去掉 query string，避免 ?v=xxx 破坏静态文件查找）
        path = urlparse(self.path).path
        if path == "/":
            rel_path = "index.html"
        else:
            # 去除开头的斜杠，防止绝对路径
            rel_path = path.lstrip("/")
            # 禁止路径遍历
            if ".." in rel_path or rel_path.startswith("/"):
                self.send_error(403, "Forbidden")
                return

        # 映射到 temp 目录
        base_dir = "temp"
        file_path = os.path.join(base_dir, rel_path)

        # 确保文件在 temp 目录内（二次保险）
        real_path = os.path.realpath(file_path)
        real_base = os.path.realpath(base_dir)
        if not real_path.startswith(real_base):
            self.send_error(403, "Forbidden")
            return

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            # 获取 MIME 类型
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            # 简单控制台日志（不写入 logs.json）
            print(f"[{datetime.now()}] GET {self.path} -> 200")
        except FileNotFoundError:
            self.send_error(404, f"File not found: {self.path}")
            print(f"[{datetime.now()}] GET {self.path} -> 404")
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
            print(f"[{datetime.now()}] GET {self.path} -> 500")

    # ---------- 原有辅助方法 ----------
    def _parse_multipart(self) -> cgi.FieldStorage:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            raise ValueError("Content-Type must be multipart/form-data")
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ValueError("empty request body")
        
        # 设置最大上传大小为100MB
        max_size = 100 * 1024 * 1024
        if content_length > max_size:
            raise ValueError(f"文件大小超过限制 (最大 {max_size // (1024 * 1024)}MB)")
        
        environ = {
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": str(content_length),
        }
        
        # 分段读取大文件
        raw = b""
        remaining = content_length
        chunk_size = 1024 * 1024  # 1MB chunks
        
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, chunk_size))
            if not chunk:
                raise ValueError("连接中断或文件不完整")
            raw += chunk
            remaining -= len(chunk)
        
        return cgi.FieldStorage(
            fp=BytesIO(raw),
            headers=self.headers,
            environ=environ,
            keep_blank_values=True,
        )

    def _require_field(self, form: cgi.FieldStorage, name: str) -> str:
        value = form.getfirst(name)
        if value is None or not value.strip():
            raise ValueError(f"missing field: {name}")
        return value.strip()

    def _read_json_body(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ValueError("empty request body")
        raw = self.rfile.read(content_length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid json body") from exc
        if not isinstance(data, dict):
            raise ValueError("json body must be an object")
        return data

    def _read_raw_body(self, max_size: Optional[int] = None) -> bytes:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            raise ValueError("empty request body")
        if max_size is not None and content_length > max_size:
            raise ValueError("request body too large")
        remaining = content_length
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("连接中断或文件不完整")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _write_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_text(self, status: HTTPStatus, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_bytes(self, status: HTTPStatus, body: bytes, content_type: str, download_name: Optional[str] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if download_name:
            self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        self.end_headers()
        self.wfile.write(body)

    def _format_source_bundle(self, payload: dict) -> str:
        sections: List[str] = []
        files = payload.get("files", {})
        for name, content in files.items():
            sections.append(f"===== {name} =====\n{content.rstrip()}")
        failed = payload.get("failed", [])
        if failed:
            error_lines = [f"{item['name']}: {item['error']}" for item in failed]
            sections.append("===== failed =====\n" + "\n".join(error_lines))
        return "\n\n".join(sections) + "\n"

    def _handle_upload_init(self) -> None:
        method = "POST"
        try:
            data = self._read_json_body()
            filename = str(data.get("filename", "")).strip()
            size = int(data.get("size", 0))
            purpose = str(data.get("purpose", "")).strip()
            with _upload_lock:
                meta = _create_upload_session(filename, size, purpose)
            payload = {
                "ok": True,
                "upload_id": meta["upload_id"],
                "chunk_size": meta["chunk_size"],
                "total_chunks": meta["total_chunks"],
                "max_size": UPLOAD_MAX_SIZE,
                "message": "上传会话已创建",
            }
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(HTTPStatus.OK, payload)
            _log_request(
                self,
                method,
                "upload_init",
                {"filename": filename, "size": str(size), "purpose": purpose},
                None,
                HTTPStatus.OK.value,
                resp_body,
            )
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            payload = {"ok": False, "error": error_msg}
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(resp_status, payload)
            _log_request(self, method, "upload_init", None, None, resp_status.value, resp_body, error=error_msg)

    def _handle_upload_chunk(self) -> None:
        method = "POST"
        try:
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            upload_id = (query.get("upload_id") or [""])[0]
            index_raw = (query.get("index") or [""])[0]
            if index_raw == "":
                raise ValueError("missing query: index")
            index = int(index_raw)
            chunk = self._read_raw_body(max_size=UPLOAD_CHUNK_SIZE)
            with _upload_lock:
                meta = _store_upload_chunk(upload_id, index, chunk)
            payload = {
                "ok": True,
                "upload_id": meta["upload_id"],
                "index": index,
                "size": len(chunk),
                "message": "分片上传成功",
            }
            self._write_json(HTTPStatus.OK, payload)
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            payload = {"ok": False, "error": error_msg}
            self._write_json(resp_status, payload)
            _log_request(self, method, "upload_chunk", None, None, resp_status.value, json.dumps(payload, ensure_ascii=False, indent=2), error=error_msg)

    def _handle_upload_complete(self) -> None:
        method = "POST"
        try:
            data = self._read_json_body()
            upload_id = str(data.get("upload_id", "")).strip()
            expected_sha256 = str(data.get("sha256", "")).strip().lower()
            with _upload_lock:
                meta = _finalize_upload_session(upload_id, expected_sha256=expected_sha256)
            payload = {
                "ok": True,
                "file_token": meta["token"],
                "filename": meta["filename"],
                "size": meta["size"],
                "sha256": meta["sha256"],
                "purpose": meta["purpose"],
                "message": "文件上传完成",
            }
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(HTTPStatus.OK, payload)
            _log_request(
                self,
                method,
                "upload_complete",
                {"upload_id": upload_id, "purpose": str(meta.get("purpose", ""))},
                {"filename": meta["filename"], "size": meta["size"]},
                HTTPStatus.OK.value,
                resp_body,
            )
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            payload = {"ok": False, "error": error_msg}
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(resp_status, payload)
            _log_request(self, method, "upload_complete", None, None, resp_status.value, resp_body, error=error_msg)

    def _handle_extract_apk(self) -> None:
        """处理APK文件上传并提取参数"""
        method = "POST"
        file_info = None
        app_name = "unknown"
        try:
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                data = self._read_json_body()
                meta, apk_bytes = _load_token_file_from_json(data, "apk", required=True)
                assert meta is not None and apk_bytes is not None
                file_info = {"filename": meta["filename"], "size": len(apk_bytes)}
            else:
                form = self._parse_multipart()
                if "apk" not in form:
                    raise ValueError("缺少apk文件")
                file_item = form["apk"]
                apk_bytes = file_item.file.read()
                if not apk_bytes:
                    raise ValueError("apk文件为空")
                file_info = {
                    "filename": file_item.filename,
                    "size": len(apk_bytes),
                }
            result = ApkExtractor.extract_all(apk_bytes)
            app_name = result.get("app_name", "unknown")
            payload = {
                "ok": True,
                "data": result,
                "message": "参数提取成功"
            }
            
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(HTTPStatus.OK, payload)
            
            _log_request(
                self,
                method,
                app_name,
                None,
                file_info,
                HTTPStatus.OK.value,
                resp_body,
            )
            
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            resp_body_dict = {"ok": False, "error": error_msg}
            resp_body = json.dumps(resp_body_dict, ensure_ascii=False, indent=2)
            self._write_json(resp_status, resp_body_dict)
            
            _log_request(
                self,
                method,
                app_name,
                None,
                file_info,
                resp_status.value,
                resp_body,
                error=error_msg,
            )

    def _handle_extract_libs(self) -> None:
        """处理 lib.zip 上传并提取所有 libygsiyu.so 的 key 候选"""
        method = "POST"
        file_info = None
        try:
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                data = self._read_json_body()
                meta, zip_bytes = _load_token_file_from_json(data, "libzip", required=True)
                assert meta is not None and zip_bytes is not None
                file_info = {"filename": meta["filename"], "size": len(zip_bytes)}
            else:
                form = self._parse_multipart()
                if "libzip" not in form:
                    raise ValueError("缺少libzip文件")
                file_item = form["libzip"]
                zip_bytes = file_item.file.read()
                if not zip_bytes:
                    raise ValueError("libzip文件为空")
                file_info = {
                    "filename": file_item.filename,
                    "size": len(zip_bytes),
                }

            entries = []
            with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
                names = sorted(name for name in zf.namelist() if name.endswith("libygsiyu.so"))
                if not names:
                    raise ValueError("压缩包中未找到 libygsiyu.so")
                for name in names:
                    so_data = zf.read(name)
                    post_candidates, xor_candidates = extract_key_candidates_from_so(so_data)
                    entries.append(
                        {
                            "path": name,
                            "post_key": post_candidates[0].hex() if post_candidates else "",
                            "xor_key": xor_candidates[0].hex() if xor_candidates else "",
                            "post_candidate_count": len(post_candidates),
                            "xor_candidate_count": len(xor_candidates),
                        }
                    )

            payload = {
                "ok": True,
                "count": len(entries),
                "items": entries,
                "message": "动态库提取成功",
            }

            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(HTTPStatus.OK, payload)
            _log_request(
                self,
                method,
                "lib_extract",
                None,
                file_info,
                HTTPStatus.OK.value,
                resp_body,
            )

        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            resp_body_dict = {"ok": False, "error": error_msg}
            resp_body = json.dumps(resp_body_dict, ensure_ascii=False, indent=2)
            self._write_json(resp_status, resp_body_dict)
            _log_request(
                self,
                method,
                "lib_extract",
                None,
                file_info,
                resp_status.value,
                resp_body,
                error=error_msg,
            )

    def _handle_repair_dynamic(self) -> None:
        """处理 dex zip/apk 和源码 zip 上传，返回修复结果与下载地址"""
        method = "POST"
        file_info = None
        try:
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type:
                data = self._read_json_body()
                dex_meta, dex_bundle_bytes = _load_token_file_from_json(data, "dexzip", required=True)
                src_meta, src_zip_bytes = _load_token_file_from_json(data, "srczip", required=True)
                assert dex_meta is not None and dex_bundle_bytes is not None
                assert src_meta is not None and src_zip_bytes is not None
                dex_name = dex_meta["filename"]
                src_name = src_meta["filename"]
            else:
                form = self._parse_multipart()
                if "dexzip" not in form:
                    raise ValueError("缺少 dexzip 文件")
                if "srczip" not in form:
                    raise ValueError("缺少 srczip 文件")
                dex_item = form["dexzip"]
                src_item = form["srczip"]
                dex_bundle_bytes = dex_item.file.read()
                src_zip_bytes = src_item.file.read()
                if not dex_bundle_bytes:
                    raise ValueError("dexzip 文件为空")
                if not src_zip_bytes:
                    raise ValueError("srczip 文件为空")
                dex_name = dex_item.filename or ""
                src_name = src_item.filename or ""

            result = repair_source_bundle(dex_bundle_bytes, src_zip_bytes, dex_name)
            token = _save_repair_output(result.output_zip_bytes)
            zip_name = re.sub(r"\.zip$", "", src_name or "source", flags=re.IGNORECASE) + "_repaired.zip"
            payload = {
                "ok": True,
                "message": "动态加密修复成功",
                "dex_count": result.dex_count,
                "mapping_count": len(result.mapping),
                "modified_file_count": len(result.modified_files),
                "replaced_count": result.replaced_count,
                "modified_files": result.modified_files,
                "dict_preview": result.preview_map,
                "download_token": token,
                "download_url": f"/repair_download?token={token}",
                "zip_name": zip_name,
            }

            file_info = {
                "filename": dex_name,
                "size": len(dex_bundle_bytes),
                "srczip_name": src_name,
                "srczip_size": len(src_zip_bytes),
            }
            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(HTTPStatus.OK, payload)
            _log_request(
                self,
                method,
                "dynamic_repair",
                None,
                file_info,
                HTTPStatus.OK.value,
                resp_body,
            )
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            resp_body_dict = {"ok": False, "error": error_msg}
            resp_body = json.dumps(resp_body_dict, ensure_ascii=False, indent=2)
            self._write_json(resp_status, resp_body_dict)
            _log_request(
                self,
                method,
                "dynamic_repair",
                None,
                file_info,
                resp_status.value,
                resp_body,
                error=error_msg,
            )

    def _handle_cache_lookup(self) -> None:
        """根据 libso sha256 查询历史解密缓存，命中后直接返回结果"""
        method = "POST"
        try:
            data = self._read_json_body()
            lib_sha256 = str(data.get("lib_sha256", "")).strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", lib_sha256):
                raise ValueError("lib_sha256 must be a 64-char hex sha256")

            cached_payload = _lookup_cached_payload_by_sha256(lib_sha256)
            if cached_payload is None:
                payload = {
                    "ok": True,
                    "cache_hit": False,
                    "cache_key": lib_sha256,
                    "cache_scope": "libso_sha256",
                    "message": "未命中缓存",
                }
            else:
                payload = cached_payload

            resp_body = json.dumps(payload, ensure_ascii=False, indent=2)
            self._write_json(HTTPStatus.OK, payload)
            _log_request(
                self,
                method,
                "cache_lookup",
                {"lib_sha256": lib_sha256},
                None,
                HTTPStatus.OK.value,
                resp_body,
            )
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            resp_body_dict = {"ok": False, "error": error_msg}
            resp_body = json.dumps(resp_body_dict, ensure_ascii=False, indent=2)
            self._write_json(resp_status, resp_body_dict)
            _log_request(
                self,
                method,
                "cache_lookup",
                None,
                None,
                resp_status.value,
                resp_body,
                error=error_msg,
            )

    def _handle_repair_download(self, parsed) -> None:
        method = "GET"
        try:
            query = parse_qs(parsed.query)
            token = (query.get("token") or [""])[0].strip()
            if not re.fullmatch(r"[0-9a-f]{32}", token):
                raise ValueError("invalid token")
            zip_path = _repair_output_path(token)
            if not os.path.exists(zip_path):
                raise FileNotFoundError("repair zip not found")
            with open(zip_path, "rb") as f:
                zip_bytes = f.read()
            self._write_bytes(HTTPStatus.OK, zip_bytes, "application/zip", f"{token}.zip")
            _log_request(
                self,
                method,
                "repair_download",
                {"token": token},
                {"filename": f"{token}.zip", "size": len(zip_bytes)},
                HTTPStatus.OK.value,
                f"download repair zip {token}",
            )
        except Exception as exc:
            resp_status = HTTPStatus.BAD_REQUEST
            error_msg = str(exc)
            self.send_error(resp_status, error_msg)
            _log_request(
                self,
                method,
                "repair_download",
                None,
                None,
                resp_status.value,
                error_msg,
                error=error_msg,
            )
