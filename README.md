# AegisLure

AI/LLM 服务蜜罐与 IP 风险情报平台。

AegisLure 面向单机部署，提供 New API、vLLM、Ollama、SGLang 和 LocalAI 的协议兼容入口，用于记录访问、认证、模型目录、调用行为和风险事件。服务返回合成数据，不连接真实模型供应商，不执行真实推理，也不下载、解析或转发访问者提交的内容。

## 功能

- 五类 AI/LLM 服务协议兼容入口和模型目录仿真。
- New API 风格的首页、登录、注册、模型、密钥、用量和调用日志页面。
- 管理控制台：总览、观测记录、调用分析、交互链路、IP 情报、蜜罐实例、规则策略和系统设置。
- 规则与策略管理：支持规则、正则条件、身份策略、OAuth 渠道和风险等级的查看与维护。
- IP 情报：支持本地地址分类、MaxMind GeoLite2 City + ASN 和 IPinfo Lite，并在查询失败时回退到可用结果或“未知”。
- GitHub、LinuxDO 和 Discord 注册入口，可按身份策略启用或停用。
- 风险事件、审计记录、IP/身份指标、JSON/CSV/plain/STIX2/nftables 导出和有界保留策略。
- SQLite 默认存储，也支持 PostgreSQL 新部署模式；两种模式均会自动加载默认规则和模型目录。

## Docker Compose 部署

需要 Docker Engine 和 Docker Compose v2。

默认使用 SQLite：

```bash
./install.sh --mode sqlite --version v0.1.0
```

使用内置 PostgreSQL：

```bash
./install.sh --mode postgres --version v0.1.0
```

安装完成后可使用以下命令查看状态：

```bash
./hpctl status
./hpctl health
```

远程安装：

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh \
  | bash -s -- --mode sqlite --version v0.1.0
```

将 `--mode sqlite` 改为 `--mode postgres` 可使用 PostgreSQL 模式；`--version last` 可选择最新可用版本。

## 网络入口

Docker 默认启用全部五类公开 profile，并使用正常项目端口：

| 服务 | 端口 |
| --- | ---: |
| New API | 3000 |
| vLLM | 8000 |
| Ollama | 11434 |
| SGLang | 30000 |
| LocalAI | 8080 |

管理入口使用 `HP_ADMIN_PORT` 指定的高位端口，默认仅绑定到 `127.0.0.1`。公开蜜罐端口默认绑定到 `0.0.0.0`。可在 `.env` 中设置：

```env
HP_PROFILES=new-api,vllm,ollama,sglang,localai
HP_PUBLIC_PORT_BIND_IP=0.0.0.0
HP_ADMIN_PORT_BIND_IP=127.0.0.1
```

管理入口路径由服务生成，可通过 `./hpctl status` 查看。首次访问管理入口时创建 owner，密码至少 8 个字符；请离线保存服务生成的恢复码，并通过防火墙、VPN 或可信反向代理限制管理端口来源。

## 数据库与 IP 情报

SQLite 是默认数据库。PostgreSQL 模式使用 `docker-compose.pg.yml`，内部数据库端口不会发布到宿主机；也可以通过 `HP_DATABASE_URL` 或 `HP_DATABASE_URL_FILE` 连接托管 PostgreSQL。

IP 情报默认使用本地 MaxMind GeoLite2 City 和 ASN 数据库。数据库缺失、未命中或查询失败时，服务会回退到本地地址分类和“未知”。也可以在管理设置中切换到 IPinfo Lite 并配置访问密钥；密钥只由后端使用。

备份只能恢复到相同数据库类型，SQLite 与 PostgreSQL 之间不执行隐式迁移。

## 安全与数据边界

- 所有模型响应、额度、密钥和账户数据均为虚拟数据。
- 不执行真实模型推理、工具调用、URL 访问、重定向、下载或上游转发。
- 上传内容仅进行有界分类、哈希或安全字段提取，不进入危险解析流程。
- 密码、Cookie、Authorization、验证码和 token 不以明文写入事件预览。
- 风险分用于表示观测证据，不等同于真实身份或自动封禁决定。

## 项目文件

- [运维说明](docs/OPERATIONS.md)
- [架构说明](docs/ARCHITECTURE.md)
- [隐私与数据生命周期](docs/PRIVACY.md)
- [发布说明](docs/RELEASE.md)
- [安全策略](SECURITY.md)
- [第三方归属](NOTICE)

## 许可证

本项目使用 AGPL v3.0 协议。使用、修改和分发本项目时请遵守许可证要求。
