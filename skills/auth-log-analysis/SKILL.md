---
name: auth-log-analysis
description: 当用户要求"分析登录日志"、"检测异常登录"、"分析认证日志"、"检测暴力破解"、"检测凭据填充"、"分析邮件登录"、"不可能旅行检测"时使用此技能。
metadata:
  version: 1.0.0
  builtin: true
---

# 认证日志威胁分析

分析认证日志（邮件、VPN、SSO 等）中的异常行为和安全威胁。

## 依赖要求

**Python 版本**: 3.8+

**必需库**:
```bash
pip install pandas
```

## 快速使用

```bash
# 完整分析
python3 scripts/auth_log_analyze.py login.csv

# JSON 输出
python3 scripts/auth_log_analyze.py -j login.csv

# 指定列名映射
python3 scripts/auth_log_analyze.py login.csv \
  --time-col "登录时间" --user-col "账号" --ip-col "IP地址" --location-col "地理位置"
```

## 威胁类型

| 类型 | 特征 | 检测方法 |
|------|------|---------|
| **凭据填充** | 单 IP 访问多用户，每用户 1-2 次 | IP-用户关联分析 |
| **暴力破解** | 单用户短时间大量尝试 | 频率阈值检测 |
| **账户盗用** | 不可能旅行、异常地理位置 | 地理异常检测 |
| **内部威胁** | 非工作时间、异常访问模式 | 行为基线偏离 |
| **代理滥用** | 云服务 IP、VPN 出口 | IP 类型识别 |

## 分析工作流

### Phase 1: 数据加载
```bash
python3 scripts/auth_log_analyze.py login.csv
```
输出：日志概览、字段识别

### Phase 2: 威胁检测
- 凭据填充检测 (单 IP 多用户)
- 暴力破解检测 (高频登录)
- 不可能旅行检测 (地理异常)
- 高风险国家分析
- 用户行为分析

### Phase 3: IOC 提取与关联
发现可疑 IP → 调用 `ip-analysis`

### Phase 4: 报告生成
按 `references/report-format.md` 输出报告

## 工具命令速查

| 任务 | 命令 |
|------|------|
| 完整分析 | `python3 auth_log_analyze.py log.csv` |
| JSON 输出 | `python3 auth_log_analyze.py -j log.csv` |
| 凭据填充检测 | `--detect credential-stuffing` |
| 暴力破解检测 | `--detect brute-force` |
| 不可能旅行检测 | `--detect impossible-travel` |
| 指定时间列 | `--time-col "登录时间"` |
| 指定用户列 | `--user-col "账号"` |
| 指定 IP 列 | `--ip-col "IP地址"` |

## 关键阈值速查

### 凭据填充
| 指标 | 正常值 | 可疑值 |
|------|--------|--------|
| 单 IP 用户数 | 1-3 | > 5 |
| 每用户尝试次数 | 正常使用 | 1-2 次 |

### 暴力破解
| 时间窗口 | 告警阈值 | 严重阈值 |
|---------|---------|---------|
| 1 分钟 | > 10 次 | > 50 次 |
| 1 小时 | > 100 次 | > 500 次 |

### 不可能旅行
| 地理跨度 | 最短合理时间 |
|---------|-------------|
| 同国家不同城市 | 1-3 小时 |
| 跨洲 | 8-15 小时 |

## 关联技能调用

| 发现的 IOC | 调用技能 | 说明 |
|-----------|---------|------|
| 攻击来源 IP | `ip-analysis` | 分析 IP 威胁情报 |
| VPN/代理 IP | `ip-analysis` | 识别匿名化服务 |

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 📋 报告格式规范（必读）
- [references/analysis-phases.md](references/analysis-phases.md) - 分析阶段详解
- [references/detection-rules.md](references/detection-rules.md) - 详细阈值配置

---

## AI 建议

发现邮箱地址时，可建议用户使用 `email-osint` 技能进行深入调查。
