---
name: asset-monitor
description: 企业攻击面资产发现、持续监控与安全基线检测。当用户要求"监控域名"、"资产发现"、"子域名枚举"、"攻击面测绘"、"资产变更"、"扫描资产"、"查看资产"、"EASM"、"两高一弱"、"高危漏洞检测"、"高危端口检测"、"弱口令检测"、"安全基线检测"、"暴露面分析"时使用此技能。
metadata:
  version: 4.2.0
  builtin: true
---

# 攻击面资产监控

集成资产发现、持续监控、变更告警、两高一弱检测的一体化攻击面管理技能。

---

## 依赖要求

**MCP 服务**:
| MCP | 工具 | 用途 |
|------|------|------|
| **asm-server** | asm_* | 资产数据存储与管理 |
| cybersec-cloud | cybersec_cloud_mcp_subdomain_discovery | 子域名发现（首选） |
| cybersec-cloud | cybersec_cloud_mcp_dns_history | DNS 解析历史（关联分析） |
| cybersec-cloud | cybersec_cloud_mcp_cyberspace-search | 网络空间资产搜索 |
| cybersec-cloud | cybersec_cloud_mcp_intel_icp_lookup | ICP 备案查询 |
| cybersec-cloud | cybersec_cloud_mcp_ops_portscan | 端口扫描 |
| cybersec-cloud | cybersec_cloud_mcp_risk_insight | 资产威胁情报 |

---

## 执行检查清单

### 执行前检查

```
MCP 调用: asm_list_targets
参数: {}
```

如果没有目标，需要先创建。

### 发现资产后（必须执行）

```
# 1. 创建监控目标
MCP 调用: asm_create_target
参数: {
  "name": "公司名",
  "type": "organization",
  "seed_domains": ["example.com", "example.cn"]
}
返回: target 对象，记录 id 字段

# 2. 保存发现的资产（必须包含 attributes 和风险标记）
MCP 调用: asm_create_assets
参数: {
  "assets": [
    {
      "target_id": "target_xxx",
      "type": "subdomain",
      "value": "api.example.com",
      "risk_level": "high",
      "risk_reason": "API接口暴露",
      "attributes": {"ip": "1.2.3.4", "port": 443},
      "tags": ["api", "https"]
    },
    {
      "target_id": "target_xxx",
      "type": "subdomain",
      "value": "admin.example.com",
      "risk_level": "high",
      "risk_reason": "管理后台暴露",
      "attributes": {"ip": "1.2.3.5", "port": 443},
      "tags": ["admin"]
    },
    {
      "target_id": "target_xxx",
      "type": "port",
      "value": "1.2.3.4:22",
      "risk_level": "critical",
      "risk_reason": "SSH暴露公网",
      "attributes": {"hostname": "api.example.com", "service": "ssh"},
      "tags": ["ssh", "high-risk-port"]
    }
  ]
}
```

**重要**: `attributes` 字段用于存储 IP、端口、服务等扩展信息，`tags` 用于分类标签。

**子域名自动风险标记规则**：
| 模式 | risk_level | risk_reason |
|------|------------|-------------|
| `*test*`, `*dev*`, `*uat*`, `*staging*` | high | 测试环境暴露 |
| `*admin*`, `*manage*`, `*backend*` | high | 管理后台暴露 |
| `*api*`, `*gateway*` | high | API接口暴露 |
| `*git*`, `*svn*`, `*jenkins*`, `*gitlab*` | critical | DevOps系统暴露 |
| `*vpn*`, `*sslvpn*`, `*remote*` | medium | 远程访问入口 |
| `*mail*`, `*owa*`, `*webmail*` | medium | 邮件系统 |

### 执行结束前（必须验证）

```
# 确认资产已保存
MCP 调用: asm_get_stats
参数: {"target_id": "target_xxx"}
```

### 检查清单摘要

| 阶段 | 必须执行 | MCP 工具 |
|------|----------|----------|
| 开始前 | 检查已有目标 | `asm_list_targets` |
| 目标确认后 | 创建目标 | `asm_create_target` |
| 资产发现后 | **保存资产** | `asm_create_assets` |
| 结束前 | 验证保存 | `asm_get_stats` |

---

## 资产发现工作流

### Phase 1: 目标确认

| 输入类型 | 处理方式 |
|----------|----------|
| 主域名 (example.com) | 直接分析 |
| 企业名称 | ICP 查询获取域名 |
| IP 段 (192.168.1.0/24) | CIDR 搜索 |

**创建监控目标**:
```
MCP 调用: asm_create_target
参数: {
  "name": "示例公司",
  "target_type": "organization",
  "seed_domains": ["example.com", "example.cn"]
}
```

### Phase 2: ICP 备案查询

```
MCP 调用: cybersec_cloud_mcp_intel_icp_lookup
参数: domain = "example.com"
```

提取关联域名和企业信息。

### Phase 3: 子域名枚举

**网络空间搜索（首选）**:
```
MCP 调用: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com"
参数: include_raw=true, limit=100
```

**高价值子域名识别**:
| 模式 | 风险 | 说明 |
|------|------|------|
| admin/管理/后台 | 高 | 管理入口 |
| api/gateway | 高 | API 接口暴露 |
| dev/test/staging/uat | 高 | 测试环境 |
| git/svn/jenkins | 高 | DevOps |
| vpn/sslvpn | 中 | 远程访问 |
| mail/owa/imap | 中 | 邮件系统 |
| iam/sso | 中 | 身份认证 |

### Phase 4: 敏感资产深度扫描

**测试环境搜索**:
```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && (hostname="*test*" || hostname="*dev*" || hostname="*uat*")
```

**管理后台搜索**:
```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && (title="admin" || title="管理" || title="login")
```

**高危端口搜索**:
```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && (port=22 || port=3389 || port=3306 || port=6379)
```

### Phase 5: 漏洞检测

```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && vuln!=""
```

### Phase 6: 保存结果（关键步骤）

**从 cybersec_cloud_mcp_cyberspace-search 结果提取并入库**:

cybersec_cloud_mcp_cyberspace-search 返回格式：
```json
{"domain": "api.example.com", "ip": "1.2.3.4", "port": 443, "update_time": "..."}
```

转换为 asm_create_assets 格式：
```
MCP 调用: asm_create_assets
参数: {
  "assets": [
    {
      "target_id": "target_xxx",
      "type": "subdomain",
      "value": "api.example.com",
      "risk_level": "high",
      "risk_reason": "API接口暴露",
      "attributes": {"ip": "1.2.3.4", "port": 443, "last_seen": "2026-01-02"},
      "tags": ["api"]
    },
    {
      "target_id": "target_xxx",
      "type": "ip",
      "value": "1.2.3.4",
      "risk_level": "low",
      "attributes": {"hostnames": ["api.example.com", "admin.example.com"]},
      "tags": ["shared-ip"]
    },
    {
      "target_id": "target_xxx",
      "type": "port",
      "value": "1.2.3.4:22",
      "risk_level": "critical",
      "risk_reason": "SSH暴露公网",
      "attributes": {"hostname": "api.example.com", "service": "ssh", "banner": "OpenSSH 8.0"},
      "tags": ["ssh", "high-risk-port"]
    }
  ]
}
```

**资产字段说明**:
| 字段 | 必需 | 说明 |
|------|------|------|
| target_id | 是 | 来自 asm_create_target |
| type | 是 | subdomain / ip / port / certificate / webapp |
| value | 是 | 资产值（子域名、IP、IP:端口） |
| risk_level | 建议 | safe / low / medium / high / critical / unknown |
| risk_reason | 建议 | 风险原因说明 |
| **attributes** | **建议** | **JSON 对象，存储 IP、端口、服务、banner 等扩展信息** |
| **tags** | 建议 | 字符串数组，用于分类标签 |

**attributes 常用字段**:
| 资产类型 | attributes 示例 |
|----------|----------------|
| subdomain | `{"ip": "1.2.3.4", "port": 443, "title": "登录页面"}` |
| ip | `{"hostnames": ["a.com", "b.com"], "asn": 12345, "geo": "CN"}` |
| port | `{"hostname": "a.com", "service": "nginx", "version": "1.18", "banner": "..."}` |
| certificate | `{"issuer": "DigiCert", "expiry": "2025-06-01", "subject": "*.example.com"}` |
| webapp | `{"title": "管理后台", "status_code": 200, "technologies": ["React", "nginx"]}` |

**验证保存**:
```
MCP 调用: asm_get_stats
参数: {"target_id": "target_xxx"}
```

---

## 两高一弱检测

> **触发词**: "两高一弱"、"高危漏洞检测"、"高危端口检测"、"弱口令检测"、"安全基线检测"

### 高危漏洞检测

```
MCP: cybersec_cloud_mcp_cyberspace-search
查询: hostname="*.example.com" && vuln!=""
```

### 高危端口检测

```
MCP: cybersec_cloud_mcp_ops_portscan
参数: target="x.x.x.x", ports=[22,23,445,1433,3306,3389,5432,6379,27017,9200]
```

**高危端口清单**:
| 端口 | 服务 | 风险 |
|------|------|------|
| 22 | SSH | 远程访问 |
| 23 | Telnet | 明文传输 |
| 3389 | RDP | Windows 远程 |
| 3306 | MySQL | 数据库暴露 |
| 6379 | Redis | 未授权访问 |
| 27017 | MongoDB | 数据泄露 |

### 弱口令检测

> 需要授权，仅限自有资产

详细检测流程参见: [references/baseline-detection.md](references/baseline-detection.md)

---

## 查看与管理资产

### 查看资产列表

```
MCP 调用: asm_list_assets
参数: {
  "target_id": "target_xxx",    // 可选：按目标筛选
  "asset_type": "subdomain",    // 可选：按类型筛选
  "risk_level": "high",         // 可选：按风险筛选
  "limit": 50,
  "offset": 0
}
```

### 查看统计信息

```
MCP 调用: asm_get_stats
参数: {"target_id": "target_xxx"}  // 可选
```

### 查看变更告警

```
MCP 调用: asm_list_changes
参数: {
  "target_id": "target_xxx",    // 可选
  "is_acknowledged": false,     // 只看未确认的
  "severity": "high",           // 可选：按严重程度筛选
  "limit": 50
}
```

### 确认变更

```
MCP 调用: asm_acknowledge_change
参数: {
  "id": "change_xxx"           // 确认单个变更
}
// 或
参数: {
  "target_id": "target_xxx"    // 确认该目标所有变更
}
// 或
参数: {
  "all": true                  // 确认所有变更
}
```

---

## MCP 工具速查

### asm-server 工具

| 工具 | 用途 | 关键参数 |
|------|------|----------|
| `asm_create_target` | 创建监控目标 | name, target_type, seed_domains |
| `asm_list_targets` | 列出所有目标 | status, limit |
| `asm_get_target` | 获取目标详情 | id |
| `asm_update_target` | 更新目标 | id, name, status |
| `asm_delete_target` | 删除目标 | id |
| `asm_create_assets` | 批量创建资产 | assets[] |
| `asm_list_assets` | 列出资产 | target_id, asset_type, risk_level |
| `asm_get_asset` | 获取资产详情 | id |
| `asm_update_asset` | 更新资产 | id, risk_level, risk_reason |
| `asm_delete_asset` | 删除资产 | id |
| `asm_get_stats` | 获取统计 | target_id |
| `asm_list_changes` | 列出变更 | target_id, is_acknowledged, severity |
| `asm_acknowledge_change` | 确认变更 | id / target_id / all |

### cybersec-cloud 工具

| 任务 | 命令 |
|------|------|
| **子域名发现** | `cybersec_cloud_mcp_subdomain_discovery: domain="example.com" limit=1000` |
| **DNS 历史** | `cybersec_cloud_mcp_dns_history: indicator="example.com" limit=100` |
| 子域名搜索(补充) | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com"` |
| 高危端口 | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com" && port=22` |
| 漏洞搜索 | `cybersec_cloud_mcp_cyberspace-search: hostname="*.domain.com" && vuln!=""` |
| 测试环境 | `cybersec_cloud_mcp_cyberspace-search: hostname="*test*" \|\| hostname="*uat*"` |
| ICP 查询 | `cybersec_cloud_mcp_intel_icp_lookup: domain` |
| 端口扫描 | `cybersec_cloud_mcp_ops_portscan: target, ports` |

---

## 常见场景

### 场景 1: 新目标监控

用户: "监控 example.com"

1. 创建目标: `asm_create_target`
2. ICP 查询: `cybersec_cloud_mcp_intel_icp_lookup`
3. 子域名发现: `cybersec_cloud_mcp_subdomain_discovery domain="example.com" limit=1000`
4. 端口扫描: `cybersec_cloud_mcp_ops_portscan`
5. 保存结果: `asm_create_assets`
6. 验证统计: `asm_get_stats`

### 场景 2: 查看资产状态

用户: "查看资产" 或 "资产列表"

```
asm_get_stats -> 总览
asm_list_assets -> 详细列表
asm_list_changes -> 最近变更
```

### 场景 3: 处理告警

用户: "资产变更" 或 "有什么新发现"

```
asm_list_changes: is_acknowledged=false, severity=high
asm_acknowledge_change: id=xxx  // 处理后确认
```

---

## 关联技能调用

| 发现的资产 | 调用技能 |
|-----------|---------|
| 可疑域名 | `domain-analysis` |
| 外部 IP | `ip-analysis` |
| Web 服务 | `url-analysis` |

---

## 参考文件

- [references/report-format.md](references/report-format.md) - 报告格式规范
- [references/risk-assessment.md](references/risk-assessment.md) - 风险评估标准
- [references/baseline-detection.md](references/baseline-detection.md) - 两高一弱检测详情
