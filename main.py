"""iApp 解密服务入口。"""
import argparse
import os
import socket
from http.server import ThreadingHTTPServer

from config import CACHE_DIR, LOG_DIR, REPAIR_DIR
from server.handler import DecryptHandler


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HTTP API for iApp lib.so static decryption")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, default=8008, help="Bind port")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    # 确保日志目录和静态文件目录存在
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(REPAIR_DIR, exist_ok=True)
    os.makedirs("temp", exist_ok=True)  # 确保 temp 目录存在，存放 index.html 和 result.html

    server = ThreadingHTTPServer((args.host, args.port), DecryptHandler)
    
    # 设置socket选项，支持大文件上传
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024 * 100)  # 100MB缓冲区
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024 * 100)
    
    # 设置超时时间（300秒 = 5分钟）
    server.socket.settimeout(300)
    
    print(f"listening on http://{args.host}:{args.port}")
    print("Serving static files from ./temp/")
    print("POST /decrypt endpoint available")
    print("Max upload size: 100MB")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
