# 解密源码

`POST /decrypt`

解密 iApp 打包的 `lib.so`（通常为 APK 内 `assets/lib.so`），返回解密后的源码文件。

## 请求参数

multipart 方式直接传 `libso` 文件；JSON 方式传 `libso_token`。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `libso` / `libso_token` | file / token | 是 | 加密的 lib.so |
| `native_so` / `native_so_token` | file / token | 否 | 原生 so，用于密钥派生 |
| `package_name` | string | 是 | 包名 |
| `version_name` | string | 是 | 版本名 |
| `version_code` | string | 是 | 版本号 |
| `app_name` | string | 是 | 应用名 |
| `dek` | string | 是 | dex 密钥 |
| `sok` | string | 否 | so 密钥 |
| `sign_key` | string | 否 | 签名 md5 |
| `sign_b64` | string | 否 | 签名 base64 |
| `pwd_key` | string | 否 | 密码密钥 |
| `post_key` | string | 否 | 手动 post_key（hex） |
| `xor_key` | string | 否 | 手动 xor_key（hex） |
| `entry_file` | string | 否 | 入口文件名，默认 `mian.iyu` |
| `mode` | string | 否 | `auto` / `current` / `legacy` / `legacy4`，默认 `auto` |
| `format` | string | 否 | `json` / `text`，默认 `json` |

## JSON 请求示例

```json
{
  "libso_token": "<file_token>",
  "package_name": "com.iapp.example",
  "version_name": "1.0",
  "version_code": "1",
  "app_name": "示例",
  "dek": "...",
  "mode": "auto",
  "format": "json"
}
```

## 响应（format=json）

```json
{
  "ok": true,
  "entry_file": "mian.iyu",
  "files": { "mian.iyu": "解密的源码..." },
  "failed": [],
  "strategy": {
    "algorithm_family": "current",
    "candidate": "...",
    "key_set": "...",
    "member_strategy": "...",
    "outer_key_hex": "...",
    "post_key_hex": "...",
    "xor_key_hex": "...",
    "resolved_sok": "...",
    "resolved_dek": "...",
    "sign_key": "...",
    "pwd_key": "...",
    "sign_input": "...",
    "pwd_input": "...",
    "pwd_source": "...",
    "signature_used": false,
    "candidate_count": 1,
    "key_set_count": 1,
    "tried_count": 1,
    "container_size": 20800
  },
  "cache_hit": false,
  "cache_message": "",
  "message": "解密成功",
  "cache_key": "<libso 的 sha256>",
  "cache_scope": "libso_sha256"
}
```

- `files`：解密出的源码（key 为文件名，value 为文本内容）。
- `failed`：解密失败的文件列表，每项为 `{"name": "...", "error": "..."}`。
- `strategy`：本次解密使用的算法与密钥信息（诊断用）。

## 响应（format=text）

每个文件一段：`===== 文件名 =====` 后接内容；失败文件归入 `===== failed =====`。

## cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/decrypt \
  -F "libso=@lib.so" \
  -F "package_name=com.iapp.example" \
  -F "version_name=1.0" \
  -F "version_code=1" \
  -F "app_name=示例" \
  -F "dek=..."
```
