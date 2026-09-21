# AegisLure

AI/LLM 服务蜜罐与 IP 风险情报平台。

AegisLure 面向单机部署，提供 New API、vLLM、Ollama、SGLang、LocalAI 和 Sub2API 的协议兼容入口，用于记录访问、认证、模型目录、调用行为和风险事件。服务返回合成数据，不连接真实模型供应商，不执行真实推理，也不下载、解析或转发访问者提交的内容。

## 功能

- 六类 AI/LLM 服务协议兼容入口和模型目录仿真。
- New API 风格的首页、登录、注册、模型、密钥、用量和调用日志页面。
- 管理控制台：总览、观测记录、调用分析、交互链路、IP 情报、蜜罐实例、规则策略和系统设置。
- 规则与策略管理：支持规则、正则条件、身份策略、OAuth 渠道和风险等级的查看与维护。
- IP 情报：本地/保留地址直接分类，公网地址统一通过 IPinfo API 获取，并在查询失败时回退到“未知”。
- GitHub、LinuxDO 和 Discord 登录入口，以及 Sub2API 的 GitHub、LinuxDO、Google、WeChat、OIDC、DingTalk 登录入口，可按身份策略启用或停用；所有入口均为本地合成流程。
- 风险事件、审计记录、IP/身份指标、JSON/CSV/plain/STIX2/nftables 导出和有界保留策略。
- SQLite 默认存储，也支持 PostgreSQL 新部署模式；两种模式均会自动加载默认规则和模型目录。

## 一键 Docker 部署

前置条件只有 Docker Engine（Linux）或 Docker Desktop（macOS），并启用 Docker Compose v2。支持 `linux/amd64`、`linux/arm64` 和 Apple Silicon；安装脚本还会检查 Docker daemon、Compose 和 OpenSSL 是否可用。

SQLite（默认，适合单机）：

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | bash -s -- --mode sqlite
```

内置 PostgreSQL（数据库不会暴露宿主机端口）：

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | bash -s -- --mode postgres
```

命令默认下载 GitHub `main` 源码并在本机 Docker 中构建，安装到当前目录的 `aegislure/`。如需指定目录或公网域名/IP：

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | \
  bash -s -- --mode postgres --dir /opt/aegislure --public-host aegis.example.com
```

安装成功后，脚本会先确认容器健康和数据库连接正常，然后输出：

- 本机后台地址；
- 自动探测或通过 `--public-host` 指定的公网后台地址；
- 首次设置提示，管理员用户名默认预填为 `owner`，密码由用户在页面中自行设置（至少 8 个字符）；
- 管理端自签 TLS 证书的 SHA-256 指纹。

首次打开后台时，浏览器会提示这是自签证书；核对命令输出的指纹后继续。创建 owner 后，恢复码只显示一次，请立即离线保存。安装器不会生成、保存或输出管理员密码。

使用固定 Release 镜像时，将 `--version main` 改为版本号或 `latest`：

```bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | \
  bash -s -- --mode sqlite --version latest
```

`latest` 和固定版本会校验 Release 包 SHA-256，并使用 manifest 中的不可变 GHCR 镜像摘要。`main` 适合直接部署当前代码；生产环境发布后优先使用固定版本。

已克隆源码时也可直接安装：

```bash
./install.sh --mode sqlite
# 或
./install.sh --mode postgres --public-host 203.0.113.10
```

状态与健康检查：

```bash
cd aegislure
./hpctl status
./hpctl health
```

删除部署（会删除本地运行数据、恢复码、TLS 证书和内置 PostgreSQL 数据卷；外部 PostgreSQL 不受影响）：

```bash
INSTALL_DIR=/path/to/aegislure
(
  cd "$INSTALL_DIR"
  docker compose -f docker-compose.yml -f docker-compose.pg.yml --profile bundled-pg down --remove-orphans --volumes
)
rm -rf "$INSTALL_DIR"
```

## 网络入口

Docker 默认启用五类公开 profile，并使用正常项目端口；LocalAI 与 Sub2API 互斥，默认启用 Sub2API：

| 服务 | 端口 |
| --- | ---: |
| New API | 3000 |
| vLLM | 8000 |
| Ollama | 11434 |
| SGLang | 30000 |
| LocalAI（可选） | 8081 |
| Sub2API | 8080 |

管理入口使用 `HP_ADMIN_PORT` 指定的高位端口，默认绑定到 `0.0.0.0`，以便从公网访问。公开蜜罐端口同样默认绑定到 `0.0.0.0`。可在 `.env` 中设置：

```env
HP_PROFILES=new-api,vllm,ollama,sglang,sub2api
HP_PUBLIC_PORT_BIND_IP=0.0.0.0
HP_ADMIN_PORT_BIND_IP=0.0.0.0
```

需要运行 LocalAI 时，将 `HP_PROFILES` 中的 `sub2api` 替换为 `localai`；同时选择两者时服务保留 Sub2API。

管理入口路径由服务随机生成，可通过 `./hpctl status` 查看。一键安装会直接打印包含该隐藏路径的完整地址。首次访问时创建 owner；页面默认填写用户名 `owner`，密码由部署者设置。请离线保存服务生成的恢复码，并通过防火墙、VPN 或可信反向代理限制管理端口来源。若只需要本机访问，可将 `HP_ADMIN_PORT_BIND_IP` 设置为 `127.0.0.1`。

在 VPS 上至少放行实际输出的 `HP_ADMIN_PORT`；公开蜜罐端口是否放行按用途决定。域名、云安全组、防火墙和 NAT 属于 Docker 主机之外的设施，安装器会输出地址但不会擅自修改它们。若自动探测的公网 IP 不适用，重新执行时传入 `--public-host`。

## 数据库与 IP 情报

SQLite 是默认数据库。PostgreSQL 模式使用 `docker-compose.pg.yml`，内部数据库端口不会发布到宿主机；也可以通过 `HP_DATABASE_URL` 或 `HP_DATABASE_URL_FILE` 连接托管 PostgreSQL。

IP 情报仅使用 IPinfo API（City + ASN）查询公网地址；本地、保留和文档地址继续做确定性本地分类，不会发送给 IPinfo。管理设置中保存 key 时会先请求 `8.8.8.8` 验证，验证失败会提示并保留原配置；key 只由后端使用。key 更换后，下一次总览刷新会自动清除旧缓存并重新查询。

Docker Compose 的 `edge_net` 默认开启 masquerade，为 IPinfo API 查询提供出站 HTTPS；`bait_net` 和 `admin_net` 仍保持 internal。若主机防火墙限制出站，请至少允许 `ipinfo.io` 的 TCP 443。

备份只能恢复到相同数据库类型，SQLite 与 PostgreSQL 之间不执行隐式迁移。

## 安全与数据边界

- 所有模型响应、额度、密钥和账户数据均为虚拟数据。
- 不执行真实模型推理、工具调用、URL 访问、重定向、下载或上游转发。
- 上传内容仅进行有界分类、哈希或安全字段提取，不进入危险解析流程。
- 密码、Cookie、Authorization、验证码和 token 不以明文写入事件预览；新事件的完整受限原始请求只通过认证管理端展示，备份必须按敏感证据保护。
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
