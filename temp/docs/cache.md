# 缓存查询

`POST /cache_lookup`

按 lib.so 的 sha256 查询历史解密缓存，命中后直接返回结果，避免重复解密。

## 请求参数

```json
{ "lib_sha256": "<64 位 hex>" }
```

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `lib_sha256` | string | 是 | lib.so 的 sha256（64 位小写 hex） |

## 响应

未命中：

```json
{ "ok": true, "cache_hit": false, "cache_key": "<sha256>", "cache_scope": "libso_sha256", "message": "未命中缓存" }
```

命中：直接返回与 `/decrypt` 相同的完整结果（含 `files`、`strategy` 等）。

## cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/cache_lookup \
  -H 'Content-Type: application/json' \
  -d '{"lib_sha256":"<sha256>"}'
```
