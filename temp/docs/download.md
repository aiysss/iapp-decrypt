# 下载修复结果

`GET /repair_download`

下载 `/repair_dynamic` 生成的修复源码 zip。

## 请求参数

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `token` | query | 是 | `repair_dynamic` 返回的 `download_token`（32 位 hex） |

## 响应

`application/zip` 附件下载。

## cURL 调用

```bash
curl -O "https://iapp.0d0d.top/repair_download?token=<hex32>"
```
