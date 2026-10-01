# iApp 解密服务 API

基准地址：`https://iapp.0d0d.top`

本服务提供 iApp v3 打包 APK 的源码解密、参数提取与动态加密修复能力。所有接口返回 JSON；仅 `/decrypt` 传 `format=text` 时返回纯文本。


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


## 分片上传

大文件建议走分片上传拿到 `file_token`，再用于 JSON 方式调用其它接口。流程分三步。

### POST /upload_init

创建分片上传会话。

```json
{ "filename": "lib.so", "size": 20800, "purpose": "decrypt_libso" }
```

`purpose` 取值：`extract_apk` / `extract_libs` / `decrypt_libso` / `decrypt_native_so` / `repair_dynamic_dexzip` / `repair_dynamic_srczip`。

```json
{ "ok": true, "upload_id": "<hex32>", "chunk_size": 2097152, "total_chunks": 1, "max_size": 536870912, "message": "上传会话已创建" }
```

### POST /upload_chunk

- Query：`upload_id`、`index`（从 0 开始）。
- Body：该分片的原始字节（≤ `chunk_size`）。

```json
{ "ok": true, "upload_id": "<hex32>", "index": 0, "size": 20800, "message": "分片上传成功" }
```

### POST /upload_complete

完成上传并换取 `file_token`。

```json
{ "upload_id": "<hex32>", "sha256": "<64 位 hex 可选>" }
```

```json
{ "ok": true, "file_token": "<hex32>", "filename": "lib.so", "size": 20800, "sha256": "<sha256>", "purpose": "decrypt_libso", "message": "文件上传完成" }
```

### 完整示例

#### cURL

```bash
# 1. 初始化上传
INIT=$(curl -s -X POST https://iapp.0d0d.top/upload_init \
  -H 'Content-Type: application/json' \
  -d '{"filename":"lib.so","size":'"$(stat -c%s lib.so)"',"purpose":"decrypt_libso"}')
UPLOAD_ID=$(echo "$INIT" | grep -o '"upload_id":"[^"]*"' | cut -d'"' -f4)

# 2. 上传分片（小文件整体作为一片）
curl -s -X POST "https://iapp.0d0d.top/upload_chunk?upload_id=$UPLOAD_ID&index=0" \
  --data-binary @lib.so

# 3. 完成上传，拿到 token
curl -s -X POST https://iapp.0d0d.top/upload_complete \
  -H 'Content-Type: application/json' \
  -d "{\"upload_id\":\"$UPLOAD_ID\"}"
```

#### Python

```python
import math, requests

BASE = "https://iapp.0d0d.top"

def upload(path, purpose):
    data = open(path, "rb").read()
    init = requests.post(f"{BASE}/upload_init", json={
        "filename": path, "size": len(data), "purpose": purpose,
    }).json()
    uid, chunk = init["upload_id"], init["chunk_size"]
    for i in range(math.ceil(len(data) / chunk)):
        requests.post(f"{BASE}/upload_chunk", params={"upload_id": uid, "index": i},
                      data=data[i*chunk:(i+1)*chunk])
    done = requests.post(f"{BASE}/upload_complete", json={"upload_id": uid}).json()
    return done["file_token"]

token = upload("lib.so", "decrypt_libso")
print(token)
```

#### JavaScript

```js
const BASE = "https://iapp.0d0d.top";

async function uploadFile(file, purpose) {
  const init = await fetch(`${BASE}/upload_init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename: file.name, size: file.size, purpose }),
  }).then((r) => r.json());
  const { upload_id, chunk_size } = init;
  for (let i = 0, start = 0; start < file.size; i++, start += chunk_size) {
    await fetch(`${BASE}/upload_chunk?upload_id=${upload_id}&index=${i}`, {
      method: "POST",
      body: file.slice(start, start + chunk_size),
    });
  }
  const done = await fetch(`${BASE}/upload_complete`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id }),
  }).then((r) => r.json());
  return done.file_token;
}

const token = await uploadFile(file, "decrypt_libso");
console.log(token);
```


## 解密源码

`POST /decrypt`

解密 iApp 打包的 `lib.so`（通常为 APK 内 `assets/lib.so`），返回解密后的源码文件。

### 请求参数

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
| `pwd_key` | string | 否 | 用户加密密码（原始密码，如 `1314521`）。服务端自动算 `MD5(密码 + "mmpfbf")` 作为 user_enc 参与密钥派生 |
| `post_key` | string | 否 | 手动 post_key（hex） |
| `xor_key` | string | 否 | 手动 xor_key（hex） |
| `entry_file` | string | 否 | 入口文件名，默认 `mian.iyu` |
| `mode` | string | 否 | `auto` / `current` / `legacy` / `legacy4`，默认 `auto` |
| `format` | string | 否 | `json` / `text`，默认 `json` |

### JSON 请求示例

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

### 响应（format=json）

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

### 响应（format=text）

每个文件一段：`===== 文件名 =====` 后接内容；失败文件归入 `===== failed =====`。

### cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/decrypt \
  -F "libso=@lib.so" \
  -F "package_name=com.iapp.example" \
  -F "version_name=1.0" \
  -F "version_code=1" \
  -F "app_name=示例" \
  -F "dek=..."
```


## 提取 APK 参数

`POST /extract_apk`

从 APK 自动提取解密所需参数与 so 文件，避免手工填写 `package_name`、`dek` 等字段。

### 请求参数

| 字段 | 说明 |
| --- | --- |
| multipart `apk` | 直接上传 APK 文件 |
| JSON `apk_token` | 分片上传拿到的 token |

### 响应

```json
{
  "ok": true,
  "data": {
    "package_name": "com.iapp.example",
    "version_name": "1.0",
    "version_code": "1",
    "app_name": "示例",
    "sok": "...",
    "dek": "...",
    "sign_key": "...",
    "sign_b64": "...",
    "detected_mode": "current",
    "lib_so_base64": "...",
    "lib_so_name": "lib.so",
    "native_so_base64": "...",
    "native_so_name": "lib/arm64-v8a/libygsiyu.so"
  },
  "message": "参数提取成功"
}
```

`sok` 长度 ≤ 4 时 `detected_mode` 返回 `legacy4`，否则为 `current`。`lib_so_base64` / `native_so_base64` 可直接解出文件后回传给 `/decrypt`。

### cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/extract_apk \
  -F "apk=@app.apk"
```


## 提取动态库 Key

`POST /extract_libs`

从 lib.zip（含 `libygsiyu.so` 的压缩包）提取每个动态库的 `post_key` / `xor_key` 候选。

### 请求参数

| 字段 | 说明 |
| --- | --- |
| multipart `libzip` | 直接上传 zip |
| JSON `libzip_token` | 分片上传拿到的 token |

### 响应

```json
{
  "ok": true,
  "count": 1,
  "items": [
    {
      "path": "lib/arm64-v8a/libygsiyu.so",
      "post_key": "<hex>",
      "xor_key": "<hex>",
      "post_candidate_count": 1,
      "xor_candidate_count": 1
    }
  ],
  "message": "动态库提取成功"
}
```

`post_key` / `xor_key` 为十六进制字符串，可直接作为 `/decrypt` 的 `post_key` / `xor_key`。

### cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/extract_libs \
  -F "libzip=@lib.zip"
```


## 动态加密修复

`POST /repair_dynamic`

对动态加密源码做修复（把加密调用替换为明文映射），返回修复后的源码包下载地址。

### 请求参数

| 字段 | 说明 |
| --- | --- |
| multipart `dexzip` + `srczip` | dex 包（zip/apk）与待修复源码 zip |
| JSON `dexzip_token` + `srczip_token` | 分片上传拿到的 token |

### 响应

```json
{
  "ok": true,
  "message": "动态加密修复成功",
  "dex_count": 1,
  "mapping_count": 0,
  "modified_file_count": 0,
  "replaced_count": 0,
  "modified_files": ["..."],
  "dict_preview": {},
  "download_token": "<hex32>",
  "download_url": "/repair_download?token=<hex32>",
  "zip_name": "source_repaired.zip"
}
```

用 `download_url`（GET）下载修复后的源码 zip。

### cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/repair_dynamic \
  -F "dexzip=@dex.zip" \
  -F "srczip=@source.zip"
```


## 缓存查询

`POST /cache_lookup`

按 lib.so 的 sha256 查询历史解密缓存，命中后直接返回结果，避免重复解密。

### 请求参数

```json
{ "lib_sha256": "<64 位 hex>" }
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `lib_sha256` | string | 是 | lib.so 的 sha256（64 位小写 hex） |

### 响应

未命中：

```json
{ "ok": true, "cache_hit": false, "cache_key": "<sha256>", "cache_scope": "libso_sha256", "message": "未命中缓存" }
```

命中：直接返回与 `/decrypt` 相同的完整结果（含 `files`、`strategy` 等）。

### cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/cache_lookup \
  -H 'Content-Type: application/json' \
  -d '{"lib_sha256":"<sha256>"}'
```


## 下载修复结果

`GET /repair_download`

下载 `/repair_dynamic` 生成的修复源码 zip。

### 请求参数

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `token` | query | 是 | `repair_dynamic` 返回的 `download_token`（32 位 hex） |

### 响应

`application/zip` 附件下载。

### cURL 调用

```bash
curl -O "https://iapp.0d0d.top/repair_download?token=<hex32>"
```


## 健康检查

`GET /health`

返回服务信息与端点清单。

### 响应

```json
{
  "ok": true,
  "service": "iapp-decrypt-api",
  "endpoints": {
    "POST /decrypt": "...",
    "POST /extract_apk": "...",
    "POST /extract_libs": "...",
    "POST /repair_dynamic": "...",
    "POST /cache_lookup": "...",
    "POST /upload_init": "...",
    "POST /upload_chunk": "...",
    "POST /upload_complete": "...",
    "GET /repair_download": "...",
    "GET /": "static index.html"
  }
}
```

### cURL 调用

```bash
curl https://iapp.0d0d.top/health
```
