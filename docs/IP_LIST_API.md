# IP 列表 API

IP 列表 API 与管理端共用同一个监听地址，接口路径为当前随机管理入口追加
`api`：

```text
GET https://<管理地址>/<随机入口>/api
```

接口默认关闭。管理员在“管理设置 → IP 列表接口”中开启后，首次开启会生成
key；完整 key 只在生成或轮换的管理响应中返回一次。状态库只保存以
`instance_key` 计算的 HMAC 指纹和展示前缀。

## 鉴权

优先使用以下任一请求头，key 不应放在 URL 查询参数中：

```http
Authorization: Bearer <API key>
```

或：

```http
X-API-Key: <API key>
```

轮换 key 会立即使旧 key 失效。接口关闭时返回 `404`；key 缺失或无效时返回
`401`。

## 查询参数

不带查询参数时返回当前保留事件聚合出的全量 IP 列表。

| 参数 | 示例 | 说明 |
| --- | --- | --- |
| `days` | `days=7` | 最近 N 天；范围 `1–3650`，与 `month` 互斥 |
| `month` | `month=2026-09` | Asia/Shanghai 自然月，与 `days` 互斥 |
| `risk` | `risk=high` | `all`、`low`、`medium`、`high`；默认 `all` |

风险档位与管理端 IP 情报保持一致：低风险 `0–29`、中风险 `30–59`、高风险
`60–100`。接口按查询时间范围重新聚合指标，返回 `items`、`count`、实际
`filters` 和每个 IP 的风险分、置信度、出现时间、命中原因、蜜罐产品、关联 IP
及建议动作。

示例：

```sh
curl -H 'Authorization: Bearer <API key>' \
  'https://<管理地址>/<随机入口>/api?days=7&risk=high'
```

管理员页面使用 `admin/api/v1/ip-list-api` 读取/切换接口设置，使用
`admin/api/v1/ip-list-api/key:rotate` 轮换 key；这两个管理接口仍需要管理员
会话和同源请求校验。
