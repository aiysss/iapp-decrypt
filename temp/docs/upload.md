# 分片上传

大文件建议走分片上传拿到 `file_token`，再用于 JSON 方式调用其它接口。流程分三步。

## POST /upload_init

创建分片上传会话。

```json
{ "filename": "lib.so", "size": 20800, "purpose": "decrypt_libso" }
```

`purpose` 取值：`extract_apk` / `extract_libs` / `decrypt_libso` / `decrypt_native_so` / `repair_dynamic_dexzip` / `repair_dynamic_srczip`。

```json
{ "ok": true, "upload_id": "<hex32>", "chunk_size": 2097152, "total_chunks": 1, "max_size": 536870912, "message": "上传会话已创建" }
```

## POST /upload_chunk

- Query：`upload_id`、`index`（从 0 开始）。
- Body：该分片的原始字节（≤ `chunk_size`）。

```json
{ "ok": true, "upload_id": "<hex32>", "index": 0, "size": 20800, "message": "分片上传成功" }
```

## POST /upload_complete

完成上传并换取 `file_token`。

```json
{ "upload_id": "<hex32>", "sha256": "<64 位 hex 可选>" }
```

```json
{ "ok": true, "file_token": "<hex32>", "filename": "lib.so", "size": 20800, "sha256": "<sha256>", "purpose": "decrypt_libso", "message": "文件上传完成" }
```

## 完整示例

### cURL

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

### Python

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

### JavaScript

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
