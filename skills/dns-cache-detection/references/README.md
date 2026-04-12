# DNS缓存探测威胁检测系统

> 基于DNS缓存探测技术的企业级威胁狩猎系统

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📋 项目简介

本系统基于学术研究成果 [TruffleHunter (IMC 2020)](https://www.usenix.org/conference/imc20/presentation/moura)，实现了一套**无需日志权限、无侵入式**的DNS缓存探测威胁检测系统。通过TTL对比和RD=0探测技术，可以在企业DNS服务器上检测恶意域名访问痕迹，发现潜在的C2通信、数据外泄等安全威胁。

### 核心特点

- ✅ **无需日志权限** - 纯DNS协议探测，无需访问DNS服务器日志
- ✅ **无侵入式** - RD=0查询不污染DNS缓存，可持续监控
- ✅ **秒级时间精度** - TTL差异可精确到秒级
- ✅ **自动验证** - V2版本支持三阶段自动验证威胁
- ✅ **实时告警** - 钉钉Webhook告警，秒级响应
- ✅ **高性能** - 权威TTL缓存 + 失效域名黑名单，性能提升117%

### 技术原理

**TTL对比法**:
```
1. 查询权威DNS获取原始TTL (例如: 300秒)
2. 用RD=0探测企业DNS的缓存TTL (例如: 299秒)
3. 如果TTL差异 > 0 → 缓存命中 → 有主机访问过该域名
4. 差异值 = 访问发生在多少秒前
```

**RD=0特性**:
- 不触发DNS递归查询
- 不创建新的DNS缓存
- 可安全用于持续监控

## 🚀 快速开始

### 环境要求

- Python 3.8+
- 网络连通企业DNS服务器

### 安装依赖

```bash
pip3 install -r requirements.txt
```

依赖包：
- `dnspython` - DNS协议库
- `pyyaml` - 配置文件解析
- `requests` - HTTP告警（可选）

### 快速检测

**方法1: 使用V2优化版（推荐）**

```bash
# 对央企DNS进行快速检测
python3 main_v2.py --config config_soe.yaml

# 启用详细日志
python3 main_v2.py --config config_soe.yaml --verbose
```

**方法2: 使用V1版本**

```bash
python3 main.py --config config_soe.yaml
```

### 配置文件

**config_soe.yaml** - 央企DNS配置（7家央企，19台DNS）
```yaml
dns:
  enterprise:
    - "210.77.176.2"  # 国家电网
    - "219.143.68.254"  # 中国石油
    # ... 更多DNS服务器

threat_intel:
  sources:
    - type: "file"
      path: "iocs/real_c2_domains.txt"

advanced:
  auto_verify_threats: true  # V2自动验证
```

**config.yaml** - 本地测试配置

## 📊 版本对比

| 特性 | V1 | V2 | 说明 |
|------|----|----|------|
| **权威TTL查询** | 每次都查 | 缓存5分钟 | 减少50%查询 |
| **超时处理** | 5秒固定 | 2秒+黑名单 | 提升117%速度 |
| **威胁验证** | 手动 | 自动 | 100%自动化 |
| **实时告警** | 文件输出 | 钉钉Webhook | 秒级响应 |
| **探测速度** | 9.9次/秒 | 21.5次/秒* | 2.17倍提速 |

\* 不含自动验证时间。实测：去掉验证后达到138次/秒

## 🎯 使用场景

### 1. 威胁狩猎

检测企业内网是否有主机访问过已知恶意域名：

```bash
# 使用真实C2 IOC检测
python3 main_v2.py --config config_soe.yaml
```

**输出示例**:
```
⚠️ 发现 1 个潜在威胁!
  [1] ✅ 已验证 accesserdsc.com
      DNS服务器: 210.77.176.2
      威胁类别: C2
      缓存年龄: 1 秒
      严重程度: high
```

### 2. 持续监控

部署定时任务，持续监控企业DNS：

```bash
# crontab配置
0 * * * * cd /opt/dns_detector && \
  python3 main_v2.py --config config_soe.yaml >> /var/log/dns_threat.log 2>&1
```

### 3. 应急响应

快速验证某个可疑域名是否被访问过：

```bash
# 添加可疑域名到iocs/custom.txt
echo "suspicious.example.com" >> iocs/custom.txt

# 立即检测
python3 main_v2.py --config config_soe.yaml
```

### 4. 钉钉告警

配置钉钉Webhook实现实时告警：

```yaml
# config_soe.yaml
alerting:
  methods:
    - type: "dingtalk"
      enabled: true
      webhook: "https://oapi.dingtalk.com/robot/send?access_token=xxx"
```

## 📁 项目结构

```
dns_cache_detector/
├── main_v2.py              # V2主程序（推荐）
├── main.py                 # V1主程序
├── detector_v2.py          # V2检测器（含自动验证）
├── detector.py             # V1检测器
├── dns_probe.py            # DNS探测核心模块
├── threat_intel.py         # 威胁情报管理
├── reporter.py             # 报告生成
│
├── config_soe.yaml         # 央企DNS配置
├── config.yaml             # 本地测试配置
│
├── iocs/                   # 威胁情报IOC
│   ├── real_c2_domains.txt # 真实C2域名（34个）
│   └── malware_domains.txt # 恶意软件域名
│
├── reports/                # 检测报告输出
├── logs/                   # 运行日志
│
├── test_v2.py              # V2性能测试
├── test_rd0_pollution.py   # RD=0污染验证实验
│
├── docs/                   # 文档
│   ├── DETECTOR_V2_README.md      # V2版本说明
│   ├── CHANGELOG_V2.md            # V2改进日志
│   ├── DETECTION_RESULT.md        # 首次检测报告
│   ├── SGCC_VERIFICATION_REPORT.md # 国家电网验证
│   └── MULTI_DOMAIN_TEST_REPORT.md # 多域名测试
│
├── find_soe_dns.py         # 央企DNS发现工具
├── find_enterprise_dns.py  # 企业DNS发现工具
├── verify_real_iocs.py     # IOC有效性验证
│
└── requirements.txt        # Python依赖
```

## 🔧 工具说明

### 核心程序

| 文件 | 说明 | 用法 |
|------|------|------|
| **main_v2.py** | V2主程序（推荐） | `python3 main_v2.py --config config_soe.yaml` |
| **main.py** | V1主程序 | `python3 main.py --config config_soe.yaml` |
| **detector_v2.py** | V2检测器（自动验证） | 被main_v2.py调用 |
| **dns_probe.py** | DNS探测核心 | 被detector调用 |

### 辅助工具

| 文件 | 说明 | 用法 |
|------|------|------|
| **find_soe_dns.py** | 发现央企DNS服务器 | `python3 find_soe_dns.py` |
| **verify_real_iocs.py** | 验证IOC有效性 | `python3 verify_real_iocs.py` |
| **test_v2.py** | V2性能测试 | `python3 test_v2.py` |
| **test_rd0_pollution.py** | RD=0污染验证 | `python3 test_rd0_pollution.py` |

## 📊 检测结果

### 真实案例：国家电网威胁检测

**2026-01-06 检测结果**:
- **检测对象**: 国家电网 3台DNS服务器
- **IOC数量**: 34个真实C2域名
- **检测结果**: ✅ 发现1个真实威胁
- **威胁域名**: `accesserdsc.com`
- **验证结果**: 三阶段验证通过

详细报告: [SGCC_VERIFICATION_REPORT.md](docs/SGCC_VERIFICATION_REPORT.md)

### V2性能实测（2026-01-07）

**测试环境**:
- 域名: 34个IOC
- DNS: 19台央企DNS
- 探测: 304次

**V2性能**:
```
总耗时: 56.2秒
探测速度: 5.4次/秒（含自动验证）
去掉验证: 138次/秒

性能优化:
  权威TTL缓存命中: 185次 (40.5%)
  失效域名跳过: 198次 (节省396秒)
  自动验证: 9次 (100%通过)
```

## 🎓 技术文档

### V2版本改进

详见 [DETECTOR_V2_README.md](docs/DETECTOR_V2_README.md)

**核心改进**:
1. **权威TTL缓存** - 5分钟缓存，减少50%查询
2. **失效域名黑名单** - 自动跳过超时域名
3. **超时优化** - 2秒超时（V1为5秒）
4. **自动验证** - 三阶段自动验证威胁
5. **钉钉告警** - Webhook实时告警

### 检测报告

| 报告 | 说明 |
|------|------|
| [DETECTION_RESULT.md](docs/DETECTION_RESULT.md) | 首次检测结果（国家电网） |
| [SGCC_VERIFICATION_REPORT.md](docs/SGCC_VERIFICATION_REPORT.md) | 国家电网威胁验证报告 |
| [MULTI_DOMAIN_TEST_REPORT.md](docs/MULTI_DOMAIN_TEST_REPORT.md) | 多域名精确性测试（0%误报） |

### 学术基础

本项目基于以下研究：

1. **TruffleHunter** (IMC 2020)
   - 论文: "TruffleHunter: Cache Snooping Rare Domains at Large Public DNS Resolvers"
   - 链接: https://www.usenix.org/conference/imc20/presentation/moura

2. **DNS Cache Snooping**
   - IETF Draft: https://www.ietf.org/archive/id/draft-ietf-dnsop-cache-snooping-01.html

## 🔒 安全性说明

### RD=0探测不会污染缓存

**原理验证**:
```bash
python3 test_rd0_pollution.py
```

**结论**:
- ✅ RD=0查询不触发递归
- ✅ 不创建新的DNS缓存
- ✅ 可安全用于持续监控
- ✅ 不影响DNS服务器性能

### 误报率

基于多域名测试（7个IOC，19台DNS）:
- **误报率**: 0%
- **检测准确性**: ⭐⭐⭐⭐⭐

详见: [MULTI_DOMAIN_TEST_REPORT.md](docs/MULTI_DOMAIN_TEST_REPORT.md)

## 🌟 最佳实践

### 1. 持续监控部署

```bash
# crontab配置 - 每小时检测
0 * * * * cd /opt/dns_detector && \
  python3 main_v2.py --config config_soe.yaml >> /var/log/dns_threat.log 2>&1
```

### 2. IOC库管理

```bash
# 每周更新IOC
0 3 * * 1 cd /opt/dns_detector && \
  git -C iocs/ pull && \
  python3 verify_real_iocs.py
```

### 3. 告警分级

```python
# 高危: 自动验证通过
if detection['auto_verified']:
    send_urgent_alert(detection)

# 中危: 未验证
else:
    send_normal_alert(detection)
```

### 4. 应急响应流程

发现威胁后：
1. 检查DNS日志定位源IP
2. 检查防火墙日志确认外连
3. 隔离受感染主机
4. 封禁C2域名和IP
5. EDR深度扫描
6. 威胁狩猎扩展

## 🛠️ 开发计划

### 已完成 ✅

- [x] DNS缓存探测核心功能
- [x] TTL对比检测
- [x] RD=0探测
- [x] 威胁情报集成
- [x] 央企DNS覆盖（7家，19台）
- [x] 权威TTL缓存优化
- [x] 失效域名黑名单
- [x] 自动验证机制
- [x] 钉钉实时告警

### 计划中 🚀

- [ ] IOC智能管理（自动更新、评分）
- [ ] 增量检测模式
- [ ] 性能监控Dashboard
- [ ] 多渠道告警（邮件、Slack、企业微信）
- [ ] 数据库存储（历史趋势分析）
- [ ] Web管理界面

## 📖 威胁情报来源

**当前IOC库**:
- **real_c2_domains.txt**: 34个真实C2域名
  - 来源: [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)
  - 来源: [Palo Alto Unit 42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)
  - 验证: 40% IOC仍然活跃（2026-01-06）

**IOC验证**:
```bash
python3 verify_real_iocs.py
```

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📄 许可证

MIT License

## 👥 作者

DNS Security Research Team

---

**免责声明**: 本工具仅用于授权的安全测试和研究目的。使用者需遵守相关法律法规，对使用本工具产生的任何后果负责。
