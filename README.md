# AegisLure

AI/LLM 服务蜜罐与 IP 风险情报平台。

AegisLure 提供五类安全的 clean-room 协议仿真：New API、vLLM、Ollama、SGLang 和 LocalAI。它记录产品识别、模型目录浏览、认证结果、合成调用、响应消费和虚拟效果验证，但不会运行模型、执行 prompt 工具、解析攻击者上传的模型/媒体、访问 URL 或连接真实供应商。

## 当前版本

当前仓库实现的是可断网运行的 Standalone 单机 baseline：

- Go HTTP 服务，同时承载启用的 profile 和隐藏管理入口；
- SQLite WAL 权威存储、JSONL 兼容镜像、虚拟账户/令牌/额度和风险聚合；多机 Hive/传输仍属于后续发布门；
- `exact/contains/starts_with/ends_with` 探活规则的安全契约；
- vLLM `secured/legacy-gap/no-key` 语义、Ollama 原生/ OpenAI 兼容接口、SGLang HTTP 管理面和 LocalAI 模型管理面；
- New API 风格的 guest → 注册 → 签到 → honey key → 合成调用 → 日志链；内置自包含公共前端，覆盖首页、模型、能力说明、文档、登录/注册、虚拟令牌、调用日志和账户页，并保留 OpenAI、Claude Messages、Gemini GenerateContent 的本地协议识别面；
- 可选、默认关闭的 GitHub/Discord/LinuxDO 官方 OAuth broker：只保存稳定 subject HMAC，支持本地身份解除关联/删除；
- Argon2id 管理员密码（最低 8 字符）、恢复码、隐藏路径、事件/IP JSON/CSV/plain 导出；
- 本地只读 PromptPot/T-Pot source registry、幂等 JSONL 导入、IP/身份人工审批和 TTL 导出任务；
- Compose 安全基线、随机管理端口/入口、TLS/Host 限制、事件保留、`install.sh`、`hpctl`、备份/恢复和离线 SPDX SBOM。
- Ollama/vLLM persona compatibility suite：PowerShell 指纹检查脚本位于 `scripts/check-ai.ps1`，覆盖公共 Header、错误格式、模型列表、metrics 和 anti-leak 规则；macOS 可运行 `scripts/check-ai-mac.sh` 做同等检查。

`runtime/`、`data/` 和密钥不进入 Git。当前管理初始化不使用 Bootstrap code 或 TOTP；这是为了降低操作门槛，生产部署仍应把隐藏入口放在 VPN/可信网络后。OAuth broker 已作为可选单机能力实现，但默认关闭，且只允许固定官方端点。正式发布前仍需完成正式证书、主机防火墙/VPN、no-egress 与 OAuth 出站抓包验收、不可变镜像签名、备份恢复演练、外部渗透和 2–4 周稳定性观察；PostgreSQL/Hive、审计哈希远端复制和 sensor 联动属于本请求明确排除的联机设计。

## 本地运行

需要 Go 1.25+：

```bash
./hpctl init --config ./config.json --data-dir ./data
go run ./cmd/aegislure -config ./config.json
```

启动输出中的 `admin_port` 和 `admin_path` 是管理入口。没有正确入口前缀时，管理处理器会直接关闭连接；开发环境未配置 `HP_TLS_CERT`/`HP_TLS_KEY` 时使用 HTTP，仅用于本机测试。

启用 New API profile 后，公共入口是配置中的 `profile_ports["new-api"]`，例如：

```bash
HP_PROFILES=new-api go run ./cmd/aegislure -config ./config.json
```

默认配置下可打开 `http://127.0.0.1:3000/`。公共页面包括 `/`、`/models`、`/pricing`、`/docs`、`/login`、`/register` 和 `/forgot-password`；登录后可进入 `/dashboard`、`/keys`、`/usage`、`/profile`。协议面包括 OpenAI `/v1/*`、Claude `/v1/messages`、Gemini `/v1beta/models` 与 `generateContent`；请求只返回有界本地响应并写入当前 honey tenant 的虚拟日志，不暴露计费、真实渠道、Webhook、上游转发或 root/system 管理面。

默认监听 `ollama:11434` 和 `vllm:8000`。启用全部 profile：

```bash
HP_PROFILES=new-api,vllm,ollama,sglang,localai go run ./cmd/aegislure -config ./config.json
```

macOS 上启动默认的 Ollama/vLLM profile 后，可直接运行 HTTP 指纹检查：

```bash
./scripts/check-ai-mac.sh
```

需要人工查看完整 HTTP 请求和响应时，运行不带断言的观察脚本：

```bash
./scripts/observe-ai-mac.sh
```

管理 API 的路径格式为：

```text
<admin_path>/setup/status
<admin_path>/setup/create-owner
<admin_path>/admin/api/v1/auth/login
<admin_path>/admin/api/v1/dashboard
<admin_path>/admin/api/v1/events
<admin_path>/admin/api/v1/indicators/ips?min_score=40
<admin_path>/admin/api/v1/indicators/{id}:approve|ignore|revoke
<admin_path>/admin/api/v1/indicators/ips?status=approved&format=json|csv|plain|stix2|nftables
<admin_path>/admin/api/v1/exports
<admin_path>/admin/api/v1/import-sources
<admin_path>/admin/api/v1/identity-indicators
<admin_path>/admin/api/v1/model-catalogs
<admin_path>/admin/api/v1/instances/<profile>/(start|stop|restart)
```

管理入口使用嵌入 Go 二进制的 Preact + HTM 组件化控制台，不依赖公网 CDN。`<admin_path>/login`
是独立登录页；登录后可在总览、观测记录、调用分析、交互链路、IP 情报、蜜罐实例、规则策略和管理设置之间切换。
实例页的启停会实际控制对应的公开 listener，同时保留管理 listener 在线；所有公开 profile 仍只返回合成响应。

首次打开管理入口即可创建 owner，密码最低 8 个字符；不再需要 Bootstrap code、TOTP 或 MFA。管理端不提供在线改密，服务生成的一次性恢复码和本机救援码是唯一的密码恢复路径，请离线保存。由于后台只有单因素密码认证，生产环境必须优先通过 VPN、Windows 防火墙白名单或可信反向代理限制管理端口来源。

## Docker Compose

如果当前主机没有系统级工具，可使用项目内工具链：

```bash
./scripts/install-tools.sh
source scripts/env.sh
```

它会将 Go 1.26.5、Docker CLI 29.1.3、Buildx 0.36.1、Compose CLI 5.4.0 及 rootless 辅助工具放到 `.tools/`。Docker Engine 静态运行组件也会放入项目目录，但真正启动守护进程仍需要宿主机的 rootless UID/GID 配置或 root 权限；若 `docker info` 报无法连接 `/var/run/docker.sock`，需要宿主管理员按 Docker 官方 Ubuntu 安装流程安装并启动 Engine，或提供一个可用的远程 Docker context。

```bash
./install.sh
./hpctl status
```

当 Docker daemon 位于独立的 WSL/VM 网络命名空间、Docker 发布端口无法转发到
Windows 时，可以用同一份 `runtime` 数据直接在 WSL 宿主运行：

```bash
./scripts/stop-native.sh
./scripts/run-native.sh
./scripts/stop-native.sh
```

此模式的管理入口仍使用 HTTPS；公开 profile listener 在当前 baseline 中是 HTTP，随机管理路径
和认证状态不变。WSL 采用 mirrored networking 时，Windows
优先访问 `https://localhost:<admin_port>/<admin_path>`；若 Hyper-V 防火墙拦截，需要在
Windows 的 Hyper-V 防火墙规则中允许对应 TCP 端口。WSL NAT 模式下才使用
`wsl.exe -- hostname -I` 得到的 WSL 地址；该地址不一定是 Windows 以太网卡地址，不能把它
与 Windows 主机 IP 混用。Docker Compose 部署仍可单独使用。

`compose.yaml` 为五个 profile 各暴露默认端口加 7 个候选端口（共 40 个公开 profile 映射）和一个随机高位管理端口。实际是否监听由 `HP_PROFILES` 决定，未启用的候选端口不会返回应用响应。容器采用非 root、只读 rootfs、tmpfs、drop-all-capabilities、no-new-privileges、资源上限和隔离网络；没有 Docker socket、host PID/network、GPU 或模型卷。端口计划由 `hpctl ports plan/apply` 生成并校验签名；apply 后需显式重启 Compose 服务。

## 安全边界

- 所有模型响应和漏洞效果均为合成数据；事件里明确记录 `execution_outcome` 和 `invocation_level`，不使用“真实推理成功”措辞。
- URL 只做语法/IP 类别判断，不做 DNS、连接、重定向或下载。
- GGUF、pickle、torch、音频/视频和归档输入只保存有限哈希/分类信息，不进入危险解析库。
- `Authorization`、Cookie、密码、验证码和 token 只进入 keyed fingerprint 或固定 `[REDACTED]`；事件预览上限 2KB。
- OAuth 只允许跳转到官方授权页；默认关闭，Discord 和 LinuxDO 身份保持 local-only，未经批准的跨站 feed 在服务端拒绝。
- 风险分只表示观测证据，不等同于真实身份；单次访问、普通 OAuth 登录或单次公开服务调用不会自动封禁。

## 参考代码

`new-api` 上游派生仓库由部署者在项目外部的受控源码目录维护，AegisLure 本仓库中的 `new-api` profile 只模拟安全的用户侧业务契约。任何要合并进上游派生版的变更，都必须保留 AGPLv3、上游历史、署名、原仓库链接和对应 source-code 入口，并通过出站/secret/危险解析审查。

架构与发布门见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，运维命令见 [docs/OPERATIONS.md](docs/OPERATIONS.md)，隐私与数据生命周期见 [docs/PRIVACY.md](docs/PRIVACY.md)，发布清单见 [docs/RELEASE.md](docs/RELEASE.md)，第三方归属见 [NOTICE](NOTICE)，安全边界见 [SECURITY.md](SECURITY.md)。
