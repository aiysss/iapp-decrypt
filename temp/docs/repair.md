# 动态加密修复

`POST /repair_dynamic`

对动态加密源码做修复（把加密调用替换为明文映射），返回修复后的源码包下载地址。

## 请求参数

| 字段 | 说明 |
| --- | --- |
| multipart `dexzip` + `srczip` | dex 包（zip/apk）与待修复源码 zip |
| JSON `dexzip_token` + `srczip_token` | 分片上传拿到的 token |

## 响应

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

## cURL 调用

```bash
curl -X POST https://iapp.0d0d.top/repair_dynamic \
  -F "dexzip=@dex.zip" \
  -F "srczip=@source.zip"
```
