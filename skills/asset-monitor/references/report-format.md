# 资产发现报告格式规范

## 报告结构

### 1. 报告头部

```markdown
## 资产发现报告

**目标**: [目标名称/域名]
**扫描时间**: YYYY-MM-DD HH:MM:SS
**扫描类型**: [full/quick/subdomain/port]
**报告生成**: AI 自动生成
```

### 2. 发现统计

```markdown
### 发现统计

| 类型 | 数量 | 较上次变化 |
|------|------|------------|
| 子域名 | 15 | +3 |
| IP 地址 | 8 | +1 |
| 开放端口 | 23 | -2 |
| 高危资产 | 5 | +2 |
```

### 3. 新增资产

```markdown
### 新增资产 (N)

#### 子域名
- 🆕 api.example.com (1.2.3.4)
  - 端口: 443 (HTTPS)
  - 标题: API Gateway

#### 开放端口
- 🆕 1.2.3.4:8080 (HTTP)
  - 服务: nginx/1.18.0
```

### 4. 风险提示

```markdown
### 风险提示 (N)

#### 🔴 高危 (Critical/High)
- ⚠️ 1.2.3.4:22 - SSH 服务暴露在公网
  - 风险: 暴力破解、未授权访问
  - 建议: 限制访问 IP，使用密钥认证

#### 🟡 中危 (Medium)
- ⚠️ admin.example.com - 管理后台暴露
  - 风险: 凭证猜测
  - 建议: 添加 IP 白名单或 VPN 访问
```

### 5. 变更记录

```markdown
### 变更记录 (N)

| 时间 | 类型 | 资产 | 变更内容 |
|------|------|------|----------|
| 2024-01-01 | IP变更 | admin.example.com | 1.2.3.3 → 1.2.3.6 |
| 2024-01-01 | 资产移除 | old.example.com | 已无法访问 |
```

### 6. 资产清单

```markdown
### 资产清单

<details>
<summary>子域名列表 (15)</summary>

| 子域名 | IP | 端口 | 标题 | 风险 |
|--------|-----|------|------|------|
| www.example.com | 1.2.3.4 | 443 | 官网 | 低 |
| api.example.com | 1.2.3.5 | 443 | API | 低 |
...
</details>
```

## 风险标记

| 图标 | 含义 |
|------|------|
| 🆕 | 新发现资产 |
| ⚠️ | 风险提示 |
| 📝 | 属性变更 |
| 🗑️ | 资产移除 |
| 🔴 | 高危/严重 |
| 🟡 | 中危 |
| 🟢 | 低危/安全 |

## 输出格式选项

### Markdown（默认）
用于 AI 对话输出，支持富文本展示。

### JSON
```json
{
  "report_id": "rpt_xxx",
  "target": "example.com",
  "scan_time": "2024-01-01T12:00:00Z",
  "summary": {
    "total_assets": 46,
    "new_assets": 3,
    "high_risk": 5
  },
  "assets": [...],
  "changes": [...],
  "risks": [...]
}
```

### CSV
用于导入其他安全工具或表格分析。

```csv
subdomain,ip,port,service,title,risk_level,first_seen
api.example.com,1.2.3.4,443,nginx,API Gateway,low,2024-01-01
```
