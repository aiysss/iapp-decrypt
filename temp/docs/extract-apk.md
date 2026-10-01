# 提取 APK 参数

`POST /extract_apk`

从 APK 自动提取解密所需参数与 so 文件，避免手工填写 `package_name`、`dek` 等字段。

## 请求参数

| 字段 | 说明 |
| --- | --- |
| multipart `apk` | 直接上传 APK 文件 |
| JSON `apk_token` | 分片上传拿到的 token |

## 响应

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

## cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/extract_apk \
  -F "apk=@app.apk"
```
