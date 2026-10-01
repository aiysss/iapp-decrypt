# iApp 解密服务

解密 iApp v3 打包 APK 的源码、自动提取参数、修复动态加密。纯 Python 实现，自带 HTTP API 与文档站。

> 成品网站：<https://iapp.0d0d.top>（前端页面 + 在线 API 文档 + 在线调试）

## 功能

- **源码解密**：解密 APK 内的 `assets/lib.so`，还原 `mian.iyu` 等源码文件（`POST /decrypt`）。
- **自动提取参数**：从 APK 提取 `package_name` / `sok` / `dek` / 签名 等（`POST /extract_apk`）。
- **提取动态库 Key**：从 `lib.zip` 提取所有 `libygsiyu.so` 的 `post_key` / `xor_key`（`POST /extract_libs`）。
- **动态加密修复**：把加密调用替换为明文映射，输出修复后的源码包（`POST /repair_dynamic`）。
- **缓存命中**：按 lib.so 的 sha256 复用历史解密结果（`POST /cache_lookup`）。
- **分片上传**：大文件分片上传换取 `file_token`（`/upload_init` → `/upload_chunk` → `/upload_complete`）。
- **API 文档站**：`/docs.html` 侧边栏目录 + 在线调试，Markdown 源文件可直接访问（`/api.md`）。

## 快速开始

### 依赖

- Python 3.9+
- Java 运行时（`baksmali.jar` 反编译 dex 需要）
- pip 包：`pycryptodome`、`cryptography`

```bash
pip install -r requirements.txt
# 需安装 JRE，例如 Ubuntu: sudo apt-get install -y openjdk-17-jre-headless
```

### 运行

```bash
python3 api.py --host 127.0.0.1 --port 8008
```

打开 `http://127.0.0.1:8008/` 使用前端；`/docs.html` 查看 API 文档。

## API 端点

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/decrypt` | 解密源码（lib.so） |
| POST | `/extract_apk` | 从 APK 自动提取参数 |
| POST | `/extract_libs` | 提取 lib.zip 中所有 libygsiyu.so 的 Key |
| POST | `/repair_dynamic` | 动态加密源码修复 |
| POST | `/cache_lookup` | 按 sha256 查询解密缓存 |
| POST | `/upload_init` | 创建分片上传会话 |
| POST | `/upload_chunk` | 上传单个分片 |
| POST | `/upload_complete` | 完成上传并换取 file_token |
| GET | `/repair_download` | 下载修复结果 zip |
| GET | `/health` | 健康检查 |

完整文档见 [`api.md`](api.md)（也作为文档站 `/docs.html` 的内容源）。

## 项目结构

```
.
├── api.py               # 入口（import main）
├── main.py              # 入口：argparse + HTTP 服务
├── config.py            # 常量 + 路径（运行时数据统一在 data/）
├── crypto/              # 密码学原语（slky/aes/elf/sok）
├── algorithms/          # 算法族（common/current/transitional/legacy4/factory）
├── services/            # 业务（上传/缓存/日志/APK 提取/解密/修复）
├── server/              # HTTP 路由与静态文件服务
├── temp/                # 前端静态资源（页面 + css/js/docs/favicon）
└── tool/                # baksmali.jar（第三方反编译工具）
```

依赖方向：`crypto → algorithms → services → server → main`，单向无循环。

## 部署

生产环境建议 nginx 反向代理 + systemd，前端静态文件由 `server/handler.py` 直接服务。

- 服务默认监听 `127.0.0.1:8008`。
- 运行时数据（日志/缓存/上传/修复输出）统一写入 `data/`。
- 大文件上传：`UPLOAD_MAX_SIZE` 512MB，分片 2MB。

## 第三方

- [baksmali/smali](https://github.com/JesusFreke/smali)（`tool/baksmali.jar`）：dex 反编译，用于提取 `dek` 与动态加密修复。
- [pycryptodome](https://github.com/Legrandin/pycryptodome)、[cryptography](https://github.com/pyca/cryptography)：加密原语。

## License

[MIT](LICENSE)
