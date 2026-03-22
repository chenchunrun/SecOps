# SecOps Agent — 产品功能介绍

> Crush 企业级安全运维助手，让 AI 真正成为值得信赖的运维伙伴。

---

## 一句话定位

SecOps Agent 构建在 [Crush](https://github.com/chenchunrun/SecOps) 之上，将大型语言模型与安全运维工具链深度集成，提供 **18 类安全运维工具**、**双专家角色代理**、**多层安全架构**和**合规自动化报告**，使 AI 代理能够安全地执行生产级运维和审计任务。

---

## 核心能力矩阵

### 18 类安全运维工具

| 类别 | 工具 | 说明 |
|------|------|------|
| **日志分析** | Log Analyze | 多源日志解析、模式匹配、异常检测 |
| **监控查询** | Monitoring Query | Prometheus、Grafana、Datadog、New Relic、InfluxDB |
| **合规检查** | Compliance Check | CIS、Docker Bench、PCI-DSS、SOC2、HIPAA、GDPR、ISO 27001 |
| **证书审计** | Certificate Audit | TLS/SSL 证书过期、密钥强度、证书链验证 |
| **安全扫描** | Security Scan | Trivy、Grype、Nuclei、ClamAV 集成 |
| **配置审计** | Configuration Audit | SSH、sudo、防火墙、文件权限、内核参数 |
| **网络诊断** | Network Diagnostic | traceroute、MTR、端口扫描、DNS 查询、ping |
| **数据库查询** | Database Query | MySQL、PostgreSQL、MongoDB、Redis 只读查询 |
| **备份检查** | Backup Check | MySQL、PostgreSQL、Kubernetes、文件备份状态 |
| **复制监控** | Replication Status | MySQL / PostgreSQL 主从复制状态 |
| **凭证审计** | Secret Audit | 正则匹配检测 13 种凭证模式（Bearer Token、GitHub PAT、GCP/AWS/GCP 密钥、Slack、Stripe、Private Key、JWT、数据库 DSN 等） |
| **密钥轮换** | Rotation Check | AWS、GCP、Azure、Kubernetes 密钥轮换状态 |
| **访问审查** | Access Review | IAM/用户访问审计，含风险评分 |
| **基础设施查询** | Infrastructure Query | Terraform 状态、云资源查询、扩缩容、成本分析 |
| **部署状态** | Deployment Status | 部署健康检查、滚动发布、金丝雀分析 |
| **告警检查** | Alert Check | Prometheus、Grafana、Datadog、PagerDuty 告警查询 |
| **事件时间线** | Incident Timeline | 告警、操作、升级链构建，生成事件时间线 |
| **资源监控** | Resource Monitor | CPU、内存、磁盘、网络、进程监控 + 异常检测 |

---

## 双专家角色代理

### OpsAgent — 运维自动化专家

负责任务：日志分析、监控查询、故障诊断、事件调查、系统维护。

**三层权限模型：**

```
Viewer（只读）
  └─ 查看日志、查询监控、读取配置、查看证书
Operator（受限写操作）
  └─ 执行诊断（ping/traceroute/DNS）、生成合规报告、
     运行漏洞扫描（只读模式）、创建/更新事件工单
Admin（生产变更）
  └─ 配置变更（需审批）、重启服务（需回滚计划）、
     应用安全补丁（需验证）
```

### SecurityExpertAgent — 安全专家

负责领域：漏洞管理、渗透测试、事件响应、合规审计、威胁情报。

**专项能力：**
- **漏洞管理** — Trivy / Grype / Nuclei 扫描，CVE/CVSS 分析与优先级排序，修复计划跟踪
- **渗透测试** — 网络渗透测试（需授权），Web 应用安全测试，攻击模拟与验证
- **事件响应** — 初始分类与定级、证据保全、威胁隔离与遏制、数字取证

> ⚠️ 明确边界：SecurityExpertAgent 明确声明**不执行未授权的进攻性行动**。

---

## 多层安全架构

```
┌─────────────────────────────────────────────────────┐
│                   AI Agent Layer                      │
│         (OpsAgent / SecurityExpertAgent)              │
├─────────────────────────────────────────────────────┤
│                  Tool Registry                        │
│           18 tools, each with capability gates        │
├─────────────────────────────────────────────────────┤
│  Risk Scoring Engine    │   Permission Service       │
│  5-factor · 0-100分     │  自动审批/用户确认/管理员审查│
├─────────────────────────────────────────────────────┤
│                Sandbox Executor                      │
│       Local / Docker / SSH · 资源隔离·凭证脱敏        │
├─────────────────────────────────────────────────────┤
│               Audit & Compliance                      │
│    审计日志 · 合规报告(SOC2/HIPAA/ISO…) · SIEM 导出  │
└─────────────────────────────────────────────────────┘
```

### 风险评估引擎

**5 因子加权评分（满分 100）：**

| 风险因子 | 分值 | 示例 |
|---------|------|------|
| 禁用命令 | +40 | `rm -rf /`、`dd`、`halt` |
| 凭证暴露 | +50 | 命令行中含 `password=`、`api_key=`、`bearer token` |
| 敏感路径访问 | +25 | `/etc/shadow`、`/.aws/credentials`、`/root/.ssh` |
| 系统修改操作 | +30 | `sed`、`chmod`、`systemctl restart` |
| 网络访问 | +15 | `curl`、`wget`、`nc` |

**决策阈值：**

| 分数区间 | 决策 |
|---------|------|
| ≥ 80 | 🔴 **阻断**（立即拒绝） |
| 60–79 | 🟠 **管理员审查**（人工审批） |
| 40–59 | 🟡 **用户确认**（弹窗确认） |
| < 40 | 🟢 **自动放行**（缓存 1 小时） |

### 沙箱隔离执行

**三种执行后端：**

| 后端 | 隔离级别 | 适用场景 |
|------|---------|---------|
| LocalExecutor | 中 | 开发测试环境 |
| DockerExecutor | 高 | 生产环境（推荐） |
| SSHExecutor | 高 | 远程主机/跳板机 |

**Docker 隔离策略：**
```
--network=none          完全网络隔离
--read-only            只读文件系统
--user 65534:65534     非 root 用户
--cap-drop=ALL          移除所有特权
--memory=512MB         内存上限
--cpus=2               CPU 上限
```

**凭证自动脱敏：**
导出前对事件内容中 13 种凭证模式进行深度脱敏，脱敏后的值统一替换为 `***REDACTED***`：

| # | 凭证类型 | 检测模式 |
|---|---------|---------|
| 1 | Bearer Token | `Authorization: Bearer xxx` |
| 2 | Stripe Live Key | `sk_live_xxx` |
| 3 | Stripe Test Key | `sk_test_xxx` |
| 4 | AWS Access Key | `AKIA*` / `ASIA*` / `ABIA*` / `ACCA*` |
| 5 | AWS Secret Key | `aws_secret_access_key=xxx` |
| 6 | URL 密码 | `?password=xxx` |
| 7 | 私钥 | `-----BEGIN ... PRIVATE KEY-----` |
| 8 | GitHub PAT | `ghp_xxx` / `github_pat_xxx` |
| 9 | GCP 凭证 | `gcp_xxx` / `GOOGLE_xxx` |
| 10 | Slack Token | `xox[baprs]-xxx` |
| 11 | Generic API Key | `api_key=` / `apikey=` / `api-key=` |
| 12 | 数据库 DSN | `mysql://user:pass@` / `postgres://...` / `mongodb://...` / `redis://...` |
| 13 | JWT Token | `eyJxxx.eyJxxx.eyJxxx` |

---

## 合规自动化

### 支持的框架

| 框架 | 覆盖控制点 | 关键检查项 |
|------|-----------|-----------|
| **SOC 2** | 访问控制、审计日志、事件响应 | 权限变更追踪、异常操作检测 |
| **HIPAA** | 审计追踪、加密、数据保护 | PHI 访问日志、加密状态验证 |
| **GDPR** | 数据保护 | 个人数据访问记录、数据处理审计 |
| **PCI-DSS** | 持卡人数据 | 敏感数据访问、密钥管理检查 |
| **ISO 27001** | 信息安全控制 | 全面安全控制评估 |

### 合规评分公式

```
合规得分 = 成功率 - (失败率 × 2) - (关键风险事件数 × 5)
结果范围：[0, 100]
```

**判定规则：**
- `fail` — 存在关键风险事件 **或** 得分 < 60
- `warning` — 存在高风险事件 **或** 得分 < 80
- `pass` — 通过

每次报告自动输出：**违规控制项清单**、**通过控制项清单**、**可疑事件列表**、**改进建议**。

---

## SIEM 集成

### 支持的导出目标

| SIEM 系统 | 协议 | 认证方式 |
|----------|------|---------|
| **Elasticsearch (ELK)** | HTTP Bulk API (NDJSON) | Basic Auth |
| **Splunk** | HTTP Event Collector (HEC) | Bearer Token |

### 安全设计

- **TLS 强制** — 所有 HTTP 导出默认启用 TLS，禁止明文传输
- **凭证脱敏** — 导出前对事件内容中 13 种凭证模式（Bearer Token、GitHub PAT、GCP/AWS/GCP 密钥、Slack、Stripe、私钥、JWT、数据库 DSN 等）进行深度脱敏，统一替换为 `***REDACTED***`
- **指数退避重试** — 3 次重试，间隔 1s → 2s → 4s，仅在 5xx 或连接错误时重试
- **审计日志截断** — 命令描述最多保留 64 字符，防止长命令含敏感数据落盘

---

## 审计追踪

### 事件模型

覆盖 10 种事件类型：

`permission_request` · `permission_approved` · `permission_denied` · `command_executed` · `command_failed` · `login_success` · `login_failure` · `data_access` · `config_change` · `security_alert`

每个事件包含：UUID v4 标识 · UTC 时间戳 · 用户/会话身份 · 操作/资源/结果 · 风险评分 · 变更前后值（配置变更场景）· 审批信息

### 内存安全设计

- `Params` 字段（可能含凭证）**永不**写入审计日志
- 内存审计日志上限 **10,000 条**，超出时 FIFO 淘汰最旧记录，防止内存泄漏

---

## 快速开始

```bash
# 构建
go build .

# 运行
./crush

# 运行测试
go test ./...
```

在 Crush 中，SecOps 工具通过工具注册表自动加载，所有工具均有 `RequiredCapabilities` 声明，由权限服务和风险评估引擎统一控制访问。

---

## 适用场景

- **SOC 2 / HIPAA / PCI-DSS 审计准备** — 自动生成合规差距报告
- **安全事件调查** — 日志聚合 + 凭证暴露检测 + 时间线重建
- **生产环境变更** — 风险评分 + 审批流 + 完整审计追踪
- **多云运维** — Terraform 状态查询 + AWS/GCP/Azure 密钥轮换检查
- **DevSecOps 集成** — Trivy/Grype 扫描接入 CI/CD

---
