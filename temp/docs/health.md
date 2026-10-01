# 健康检查

`GET /health`

返回服务信息与端点清单。

## 响应

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

## cURL 调用

```bash
curl https://iapp.0d0d.top/health
```
