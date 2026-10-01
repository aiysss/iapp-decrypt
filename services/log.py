"""请求日志。"""
import json
import os
import re
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from typing import Optional

from config import LOG_DIR, LOGS_JSON_PATH

_log_lock = threading.Lock()

def _safe_filename(name: str) -> str:
    """将字符串中的非字母数字字符替换为下划线，避免文件名问题"""
    return re.sub(r"[^a-zA-Z0-9]", "_", name)


def _log_request(
    handler: BaseHTTPRequestHandler,
    method: str,
    app_name: str,
    form_fields: Optional[dict],
    file_info: Optional[dict],
    response_status: int,
    response_body: str,
    error: Optional[str] = None,
) -> None:
    """
    记录请求日志：
    - 生成独立的 .log 文件到 LOG_DIR
    - 将日志条目追加到 logs.json
    """
    now = datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")
    log_filename = f"{_safe_filename(app_name)}_{now.strftime('%Y%m%d_%H%M%S_%f')}.log"
    log_filepath = os.path.join(LOG_DIR, log_filename)

    client_ip, client_port = handler.client_address
    user_agent = handler.headers.get("User-Agent", "")

    # 构建日志文本内容
    lines = []
    lines.append(f"Time: {timestamp_str}")
    lines.append(f"Client: {client_ip}:{client_port}")
    lines.append(f"User-Agent: {user_agent}")
    lines.append(f"Method: {method}")
    lines.append(f"App Name: {app_name}")

    if form_fields:
        lines.append("Parameters:")
        for k, v in form_fields.items():
            lines.append(f"  {k}: {v}")

    if file_info:
        lines.append(f"File: {file_info['filename']} ({file_info['size']} bytes)")

    lines.append(f"Response Status: {response_status}")

    if error:
        lines.append(f"Error: {error}")
    else:
        lines.append("Response Body:")
        lines.append(response_body)

    log_content = "\n".join(lines) + "\n"

    # 写入独立日志文件
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(log_filepath, "w", encoding="utf-8") as f:
        f.write(log_content)

    # 更新 logs.json（线程安全）
    log_entry = {"time": timestamp_str, "log_file": log_filename}
    with _log_lock:
        logs_data = []
        if os.path.exists(LOGS_JSON_PATH):
            try:
                with open(LOGS_JSON_PATH, "r", encoding="utf-8") as f:
                    logs_data = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                logs_data = []
        logs_data.append(log_entry)
        with open(LOGS_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(logs_data, f, ensure_ascii=False, indent=2)
