# 提取动态库 Key

`POST /extract_libs`

从 lib.zip（含 `libygsiyu.so` 的压缩包）提取每个动态库的 `post_key` / `xor_key` 候选。

## 请求参数

| 字段 | 说明 |
| --- | --- |
| multipart `libzip` | 直接上传 zip |
| JSON `libzip_token` | 分片上传拿到的 token |

## 响应

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

## cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/extract_libs \
  -F "libzip=@lib.zip"
```
