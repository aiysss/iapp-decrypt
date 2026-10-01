# iApp 解密服务 API

基准地址：`https://iapp.0d0d.top`

本服务提供 iApp v3 打包 APK 的源码解密、参数提取与动态加密修复能力。所有接口返回 JSON；仅 `/decrypt` 传 `format=text` 时返回纯文本。

> 完整 API 文档（Markdown，可甩给 AI 直接读取全部接口）：[https://iapp.0d0d.top/api.md](https://iapp.0d0d.top/api.md)

## 通用说明

- 出错统一返回 `{"ok": false, "error": "..."}`，HTTP 状态码 400。
- 文件上传支持两种方式：multipart（旧）与分片上传 + token（新，推荐）。

## 文件传参方式

每个需要上传文件的接口都支持两种方式：

1. **multipart/form-data**：直接把文件作为表单字段上传。
2. **application/json + 文件 token**：先走分片上传拿到 `file_token`，再在 JSON 里用 `<字段>_token` 引用。

先看 [分片上传](#/upload) 了解如何拿到 `file_token`。

| 接口 | JSON 文件字段 |
| --- | --- |
| `/decrypt` | `libso_token`（必填）、`native_so_token`（可选） |
| `/extract_apk` | `apk_token` |
| `/extract_libs` | `libzip_token` |
| `/repair_dynamic` | `dexzip_token`、`srczip_token` |

## 端点总览

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
