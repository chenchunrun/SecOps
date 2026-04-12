# ProjectDiscovery 工具链参考

## 工具链概览

```
┌──────────────────────────────────────────────────────────────┐
│                   PD 工具链扫描流程                            │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  [subfinder]  →  [dnsx]  →  [naabu]  →  [httpx]  →  [tlsx]  │
│   子域名发现      DNS验证     端口扫描     HTTP探测     TLS分析  │
│                                                              │
│  输出: txt    →  txt/存活  →  host:port →  JSON     →  JSON   │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## 工具安装

```bash
# 前置条件: Go 1.21+
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# 工具安装位置: ~/go/bin/
# 确保 PATH 包含: export PATH="$HOME/go/bin:$PATH"
```

## 各工具详解

### 1. subfinder - 子域名发现

**功能**: 被动收集子域名，聚合多个数据源

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-d` | 目标域名 | `-d example.com` |
| `-all` | 使用所有数据源 | |
| `-recursive` | 递归枚举 | |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | `-o subs.txt` |
| `-oJ` | JSON 输出 | |

**常用命令**:
```bash
# 基础扫描
subfinder -d example.com -silent -o subs.txt

# 完整扫描 (所有源 + 递归)
subfinder -d example.com -all -recursive -silent -o subs.txt

# JSON 输出
subfinder -d example.com -all -oJ -o subs.json
```

**数据源配置** (`~/.config/subfinder/provider-config.yaml`):
```yaml
binaryedge:
  - xxx-api-key
censys:
  - xxx-api-id:xxx-api-secret
shodan:
  - xxx-api-key
```

---

### 2. dnsx - DNS 解析验证

**功能**: 快速 DNS 解析，验证域名存活，获取 DNS 记录

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-l` | 输入列表 | `-l domains.txt` |
| `-a` | 查询 A 记录 | |
| `-aaaa` | 查询 AAAA 记录 | |
| `-cname` | 查询 CNAME | |
| `-resp` | 显示响应 | |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | |

**常用命令**:
```bash
# 验证存活并获取 A 记录
dnsx -l subs.txt -a -resp -silent -o resolved.txt

# 完整 DNS 记录
dnsx -l subs.txt -a -aaaa -cname -resp -silent -o dns.txt

# 仅提取存活域名
dnsx -l subs.txt -silent -o alive.txt
```

---

### 3. naabu - 端口扫描

**功能**: 快速 TCP 端口扫描

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-l` | 主机列表 | `-l hosts.txt` |
| `-p` | 端口范围 | `-p 80,443,8080` 或 `-p 1-1000` |
| `-top-ports` | 常用端口 | `-top-ports 100` |
| `-c` | 并发数 | `-c 25` |
| `-rate` | 速率限制 | `-rate 100` |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | |

**常用命令**:
```bash
# 常用端口扫描
naabu -l hosts.txt -p 80,443,8080,8443,22,3389 -c 25 -rate 100 -silent -o ports.txt

# Top 100 端口
naabu -l hosts.txt -top-ports 100 -c 50 -rate 200 -silent -o ports.txt

# 高危端口扫描
naabu -l hosts.txt -p 22,23,445,1433,3306,3389,5432,6379,27017,9200 -silent -o high_risk.txt
```

**输出格式**: `host:port` (如 `example.com:443`)

---

### 4. httpx - HTTP 探测

**功能**: HTTP 服务探测，技术指纹识别

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-l` | 输入列表 | `-l targets.txt` |
| `-title` | 获取标题 | |
| `-status-code` | 状态码 | |
| `-tech-detect` | 技术栈检测 | |
| `-ip` | 显示 IP | |
| `-cdn` | CDN 检测 | |
| `-server` | Server 头 | |
| `-json` | JSON 输出 | |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | |

**常用命令**:
```bash
# 完整探测
httpx -l hosts.txt -title -status-code -tech-detect -ip -cdn -server -json -silent -o http.json

# 快速探测
httpx -l hosts.txt -title -status-code -silent -o http.txt

# 筛选存活
httpx -l hosts.txt -mc 200,301,302 -silent -o alive.txt
```

**JSON 输出字段**:
```json
{
  "url": "https://example.com",
  "host": "example.com",
  "status_code": 200,
  "title": "Example Domain",
  "webserver": "nginx",
  "tech": ["Nginx", "PHP"],
  "host_ip": "93.184.216.34",
  "cdn": false
}
```

---

### 5. tlsx - TLS 证书分析

**功能**: TLS/SSL 证书分析

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-l` | 主机列表 | `-l hosts.txt` |
| `-u` | 单个目标 | `-u example.com` |
| `-san` | SAN 提取 | |
| `-cn` | CN 提取 | |
| `-so` | 证书链 | |
| `-json` | JSON 输出 | |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | |

**常用命令**:
```bash
# 基础分析
tlsx -l hosts.txt -json -silent -o tls.json

# 提取 SAN/CN
tlsx -l hosts.txt -san -cn -silent -o tls_domains.txt
```

**JSON 输出字段**:
```json
{
  "host": "example.com",
  "port": "443",
  "tls_version": "TLSv1.3",
  "subject_cn": "example.com",
  "issuer_cn": "DigiCert",
  "not_after": "2025-01-01",
  "wildcard_certificate": false
}
```

---

### 6. nuclei - 漏洞扫描 (可选)

**功能**: 基于模板的漏洞扫描

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-l` | 目标列表 | `-l urls.txt` |
| `-t` | 模板目录 | `-t ~/nuclei-templates/` |
| `-s` | 严重级别 | `-s critical,high` |
| `-jsonl` | JSON Lines 输出 | |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | |

**常用命令**:
```bash
# 高危扫描
nuclei -l urls.txt -s critical,high -jsonl -silent -o vulns.json

# 更新模板
nuclei -update-templates
```

---

### 7. katana - 爬虫 (可选)

**功能**: Web 爬虫，URL 发现

**核心参数**:
| 参数 | 说明 | 示例 |
|------|------|------|
| `-l` | 目标列表 | `-l urls.txt` |
| `-d` | 爬取深度 | `-d 3` |
| `-jc` | JS 解析 | |
| `-silent` | 静默输出 | |
| `-o` | 输出文件 | |

**常用命令**:
```bash
# 基础爬取
katana -l urls.txt -d 2 -jc -silent -o crawled.txt
```

---

## 扫描模式对比

| 模式 | 工具 | 耗时 | 覆盖度 |
|------|------|------|--------|
| **quick** | subfinder → dnsx → httpx | ~5min | 基础 |
| **standard** | + naabu + tlsx | ~15min | 标准 |
| **full** | + katana + nuclei | ~30min+ | 完整 |

## 高价值目标识别

### URL 模式匹配

| 类型 | 关键词 | 风险等级 |
|------|--------|----------|
| 登录页面 | login, signin, auth, sso | 🔴 高 |
| API 端点 | api, gateway, openapi | 🔴 高 |
| 管理后台 | admin, console, dashboard | 🔴 高 |
| 测试环境 | test, dev, uat, staging, gray | 🔴 高 |
| DevOps | git, jenkins, gitlab, ci | 🔴 严重 |

### 状态码分析

| 状态码 | 含义 | 关注点 |
|--------|------|--------|
| 200 | 正常 | 可访问内容 |
| 301/302 | 重定向 | 目标位置 |
| 401/403 | 认证/禁止 | 存在但受保护 |
| 500+ | 服务器错误 | 可能有漏洞 |

## 输出文件结构

```
output/
├── 1_subdomains.txt      # 子域名列表
├── 2_resolved.txt        # DNS 解析结果
├── 2_alive.txt           # 存活域名
├── 3_ports.txt           # 开放端口 (host:port)
├── 4_http.json           # HTTP 服务详情
├── 5_tls.json            # TLS 证书详情
├── assets.db             # SQLite 数据库
└── summary.json          # 扫描摘要
```

## 数据库结构

```sql
-- 子域名
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE,
    source TEXT,
    discovered_at TIMESTAMP
);

-- HTTP 服务
CREATE TABLE http_services (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE,
    host TEXT,
    port INTEGER,
    status_code INTEGER,
    title TEXT,
    server TEXT,
    technologies TEXT,  -- JSON array
    ip TEXT
);

-- TLS 证书
CREATE TABLE tls_certs (
    id INTEGER PRIMARY KEY,
    host TEXT,
    port INTEGER,
    subject_cn TEXT,
    issuer_cn TEXT,
    tls_version TEXT,
    not_after TIMESTAMP,
    wildcard BOOLEAN
);
```

## 常见问题

### 1. 工具找不到
```bash
# 检查安装
ls ~/go/bin/

# 添加到 PATH
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 2. naabu 需要 root
```bash
# macOS: 使用 libpcap (无需 root)
# Linux: 添加 CAP_NET_RAW
sudo setcap cap_net_raw+ep ~/go/bin/naabu
```

### 3. subfinder 数据源少
配置 API Keys (`~/.config/subfinder/provider-config.yaml`)

### 4. 扫描超时
- 减少并发: `-c 10 -rate 50`
- 分批扫描
- 增加超时: `-timeout 10`
