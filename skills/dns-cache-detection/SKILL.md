---
name: dns-cache-detection
description: 当用户要求"DNS缓存探测"、"检测DNS缓存威胁"、"DNS威胁狩猎"、"检测企业DNS恶意访问"、"C2域名检测"、"央企DNS检测"、"检测内网威胁"时使用此技能。
metadata:
  version: 2.1.0
  builtin: true
---

# DNS缓存探测威胁检测技能

基于TruffleHunter (IMC 2020)学术研究的企业DNS威胁检测技能。通过DNS缓存探测技术检测企业内网是否有主机访问过恶意域名，发现潜在的C2通信、数据外泄等安全威胁。

## 核心能力

| 能力 | 脚本 | 说明 |
|------|------|------|
| **快速威胁检测** | `main_v2.py --mode quick` | V2优化版，权威TTL缓存+自动验证 |
| **深度威胁检测** | `main_v2.py --mode deep` | 完整检测+三阶段验证 |
| **央企DNS检测** | `--config config_soe.yaml` | 7家央企19台DNS服务器 |
| **自定义DNS检测** | `--config config.yaml` | 自定义DNS服务器列表 |
| **IOC有效性验证** | `verify_real_iocs.py` | 验证IOC域名是否仍然活跃 |
| **央企DNS发现** | `find_soe_dns.py` | 自动发现央企DNS服务器 |

## 技术特点

### ✅ 无需日志权限
- 纯DNS协议探测，无需访问DNS服务器日志
- 适用于权限受限环境

### ✅ 无侵入式探测
- 使用RD=0（Recursion Desired = 0）非递归查询
- **不污染DNS缓存**，可安全用于持续监控
- 实验验证：`python scripts/test_rd0_pollution.py`

### ✅ 秒级时间精度
- TTL差异可精确到秒级
- 可计算威胁访问时间：`缓存年龄 = 权威TTL - 缓存TTL`

### ✅ 自动验证威胁
- V2版本支持三阶段自动验证
- 初次检测 → 等待2秒 → 二次探测 → 观察TTL衰减
- 验证通过率：100%（实测9/9）

### ✅ 高性能优化
- 权威TTL缓存：减少50%查询
- 失效域名黑名单：自动跳过超时域名
- 超时优化：2秒超时（V1为5秒）
- 性能提升：117%（9.9→21.5次/秒）

## 依赖要求

**Python版本**: 3.8+

**依赖包**:
```bash
pip install dnspython pyyaml requests
```

或直接安装：
```bash
cd scripts && pip install -r requirements.txt
```

## 快速使用

### 1. 快速检测央企DNS

```bash
# V2优化版（推荐）
python scripts/main_v2.py --config scripts/config_soe.yaml

# 启用详细日志
python scripts/main_v2.py --config scripts/config_soe.yaml --verbose
```

**预期输出**:
```
========== 性能统计 ==========
权威TTL缓存命中: 185
失效域名已跳过: 198
自动验证次数: 9
验证确认威胁: 9

========== 检测结果 ==========
⚠️ 发现 1 个潜在威胁!
  [1] ✅ 已验证 accesserdsc.com
      DNS服务器: 210.77.176.2
      威胁类别: C2
      缓存年龄: 1 秒
      严重程度: high
```

### 2. 验证特定域名

```bash
# 添加可疑域名到临时IOC
echo "suspicious.example.com" > /tmp/custom_iocs.txt

# 检测该域名
python scripts/main_v2.py --config scripts/config_soe.yaml
```

### 3. 查看检测报告

```bash
# JSON格式
cat scripts/reports/dns_detection_*.json | jq .

# CSV格式（Excel可打开）
open scripts/reports/dns_detection_*.csv
```

### 4. IOC有效性验证

```bash
# 验证IOC库中的域名是否仍然活跃
python scripts/verify_real_iocs.py
```

**输出示例**:
```
[✓] accesserdsc.com - 可解析 (104.21.25.11)
[✓] aiaggregator.com - 可解析 (172.67.221.140)
[✗] badbutperfect.com - 无法解析（已失效）

总计: 34个域名
活跃: 14个 (41.2%)
失效: 20个 (58.8%)
```

## 检测原理

### TTL对比法

**核心思想**: 对比权威TTL和缓存TTL，差异表示访问时间

**检测流程**:
```
1. 查询权威DNS获取原始TTL (例如: 300秒)
   └─ 使用公共DNS: 223.5.5.5 (阿里云)

2. 用RD=0探测企业DNS的缓存TTL (例如: 299秒)
   └─ 非递归查询，不触发新的DNS解析

3. 判定
   └─ 如果TTL差异 > 0 → 缓存命中 → 有主机访问过该域名
   └─ 差异值 = 访问发生在多少秒前 (1秒前)

4. 自动验证（V2新增）
   └─ 等待2秒后再次探测
   └─ 连续观察TTL衰减
   └─ 验证TTL衰减是否正常
```

### RD=0特性

**RD=0 (Recursion Desired = 0)** 是DNS协议中的标志位：

```python
# DNS查询构造
query = dns.message.make_query(domain, dns.rdatatype.A)
query.flags &= ~dns.flags.RD  # 清除RD标志位

# DNS服务器行为
if has_cache:
    return cached_result  # 返回缓存
else:
    return REFUSED        # 拒绝查询，不向上游递归
```

**关键特性**:
- ✅ 不触发DNS递归查询
- ✅ 不创建新的DNS缓存
- ✅ 可安全用于持续监控

**实验验证**:
```bash
python scripts/test_rd0_pollution.py
```

### 自动验证机制（V2）

**三阶段验证流程**:

```
[Stage 1] 初次检测
    ↓
缓存命中? → No → 结束
    ↓ Yes
等待2秒
    ↓
[Stage 2] 二次探测
    ↓
仍命中? → No → 可能误报
    ↓ Yes
[Stage 3] 连续观察TTL衰减
    ↓
观察3次，间隔2秒
    ↓
TTL衰减正常? → Yes → ✅ 威胁确认
    ↓ No
⚠️ 需人工复核
```

**示例**:
```
[自动验证] accesserdsc.com @ 210.77.176.2
  初次检测: TTL=299秒 (缓存命中)
  等待2秒
  二次探测: TTL=297秒 (仍命中)
  观察TTL衰减:
    [1] TTL=297秒
    [2] TTL=295秒 (-2秒)
    [3] TTL=293秒 (-2秒)

  TTL衰减: 4秒 (期望6秒)
  验证结果: ✅ 威胁确认 (误差±2秒可接受)
```

## 覆盖的DNS服务器

### 央企DNS（config_soe.yaml）

| 央企 | DNS数量 | 代表服务器 |
|------|---------|-----------|
| 国家电网 | 3台 | 210.77.176.2 |
| 中国石油 | 2台 | 219.143.68.254 |
| 工商银行 | 3台 | 219.142.91.125 |
| 建设银行 | 2台 | 124.126.72.2 |
| 中国移动 | 2台 | 211.136.20.201 |
| 中石化 | 2台 | 114.246.38.132 |
| 中国建筑 | 5台 | 61.162.101.1 |
| **总计** | **19台** | - |

### 自定义DNS（config.yaml）

可在配置文件中自定义要检测的DNS服务器列表。

## IOC威胁情报库

### real_c2_domains.txt (34个)

**来源**:
- [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)
- [Palo Alto Unit 42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)

**活跃度**（2026-01-06验证）:
- 活跃: 14个 (41.2%)
- 失效: 20个 (58.8%)

**域名示例**:
```
accesserdsc.com          - C2域名，Cloudflare托管
aiaggregator.com         - 多家族C2
allocatinow.sbs          - Lumma Stealer窃密软件
7p1e0901tm70n.cfc-execute.bj.baidubce.com - 百度云函数C2
```

## 真实检测案例

### 案例1: 国家电网C2检测

**检测时间**: 2026-01-06 17:50:13

**检测对象**: 国家电网 3台DNS服务器

**检测结果**:
```yaml
域名: accesserdsc.com
类型: C2域名
命中DNS:
  - 210.77.176.2 (dl-dns1.sgcc.cn)
  - 210.77.177.2 (dl-dns2.sgcc.cn)
缓存年龄: 1秒前解析
C2服务器: 104.21.25.11, 172.67.221.140 (Cloudflare)
```

**验证过程**:
1. **初次检测**: TTL差异1秒 → 缓存命中
2. **二次验证**: TTL=300秒（刚解析）→ 期间有新查询
3. **连续实验**: TTL从232秒衰减到213秒 → 缓存真实存在

**威胁评估**: ⭐⭐⭐⭐⭐ 真实威胁

**详细报告**: `references/SGCC_VERIFICATION_REPORT.md`

### 案例2: 多域名精确性测试

**测试目的**: 验证系统是否产生假阳性

**测试域名**: 7个IOC域名

**测试结果**:
```
测试域名: 7个
缓存命中: 1个 (accesserdsc.com)
正确判定: 6个 (无威胁)
误报率: 0%
```

**结论**: 系统精确性验证通过 ✅

**详细报告**: `references/MULTI_DOMAIN_TEST_REPORT.md`

### 案例3: V2性能实测

**测试环境**:
- 域名: 34个IOC
- DNS: 19台央企DNS
- 探测: 304次

**V2性能**:
```
总耗时: 56.2秒
探测速度: 5.4次/秒（含自动验证）
纯探测速度: 138次/秒（去掉验证）

性能优化效果:
  权威TTL缓存命中: 185次 (40.5%)
  失效域名跳过: 198次 (节省396秒)
  自动验证: 9次 (100%通过)
```

## 应急响应建议

### 发现威胁后的处置流程

#### 立即行动（0-2小时）

**1. 检查DNS日志定位源IP**
```bash
# 在DNS服务器上
grep "accesserdsc.com" /var/log/named/queries.log | \
  awk '{print $1, $2, $6}' | \
  grep "17:50\|18:0[01]"

# 预期输出
# 2026-01-06 17:50:12 192.168.1.100
```

**2. 检查防火墙日志确认外连**
```bash
# 搜索C2服务器IP
grep "104.21.25.11\|172.67.221.140" /var/log/firewall.log
```

**3. 隔离受感染主机**
```bash
# 方案1: iptables
iptables -A INPUT -s 192.168.1.100 -j DROP
iptables -A OUTPUT -d 192.168.1.100 -j DROP

# 方案2: 交换机端口shutdown
# interface GigabitEthernet0/1
# shutdown
```

**4. 封禁C2域名和IP**
```bash
# DNS黑洞
cat >> /etc/bind/named.conf.local <<EOF
zone "accesserdsc.com" {
    type master;
    file "/etc/bind/db.null";
};
EOF

# 防火墙封禁
iptables -A OUTPUT -d 104.21.25.11 -j DROP
iptables -A OUTPUT -d 172.67.221.140 -j DROP

# 重启BIND
systemctl restart bind9
```

#### 短期措施（2-24小时）

**5. 主机取证**
- 内存镜像（Volatility分析）
- 磁盘镜像（恶意文件提取）
- 进程列表、网络连接
- 注册表/启动项/计划任务

**6. 威胁狩猎**
```bash
# 全网搜索该域名
# Windows Sysmon日志
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=3  # 网络连接
} | Where-Object {
    $_.Message -match "accesserdsc.com|104.21.25.11"
}
```

**7. IOC扩展**
- 查询VirusTotal关联IOC
- 提取主机其他通信域名/IP
- 更新威胁情报库

#### 中长期措施（1周-1个月）

**8. 持续监控**
```bash
# crontab: 每小时检测
0 * * * * cd /opt/dns_detector && \
  python scripts/main_v2.py --config scripts/config_soe.yaml >> /var/log/dns_threat.log 2>&1
```

**9. SIEM集成**
- 接入企业SIEM（Splunk/ELK）
- 配置告警规则
- 自动化响应流程

**10. 防御加固**
- DNS RPZ (Response Policy Zone)
- DNSSEC验证
- DNS over HTTPS (DoH)
- 端点EDR全覆盖

## 配置文件说明

### config_soe.yaml（央企DNS）

```yaml
# DNS服务器配置
dns:
  enterprise:
    - "210.77.176.2"  # 国家电网
    - "219.143.68.254"  # 中国石油
    # ... 更多DNS

# 威胁情报
threat_intel:
  sources:
    - type: "file"
      path: "iocs/real_c2_domains.txt"

# V2高级选项
advanced:
  auto_verify_threats: true  # 启用自动验证

# 钉钉告警（可选）
alerting:
  methods:
    - type: "dingtalk"
      enabled: false
      webhook: ""  # 填入钉钉Webhook URL
```

### config.yaml（自定义）

```yaml
dns:
  enterprise:
    - "8.8.8.8"  # Google DNS（测试用）
    - "1.1.1.1"  # Cloudflare DNS

threat_intel:
  sources:
    - type: "file"
      path: "iocs/malware_domains.txt"
```

## V2版本改进

### 性能优化（117%提升）

| 指标 | V1 | V2 | 提升 |
|------|----|----|------|
| 探测速度 | 9.9次/秒 | 21.5次/秒 | +117% |
| 权威TTL查询 | 646次 | ~322次 | -50% |
| 超时时间 | 5秒 | 2秒 | -60% |

### 新增功能

✅ **权威TTL缓存** - 5分钟缓存，减少重复查询
✅ **失效域名黑名单** - 自动跳过超时域名
✅ **自动验证机制** - 三阶段自动验证威胁
✅ **钉钉实时告警** - Webhook告警，秒级响应

**详细说明**: `references/DETECTOR_V2_README.md`

## 最佳实践

### 1. 持续监控部署

```bash
# crontab配置 - 每小时检测
0 * * * * cd /opt/dns_detector && \
  python scripts/main_v2.py --config scripts/config_soe.yaml >> /var/log/dns_threat.log 2>&1
```

### 2. IOC库管理

```bash
# 每周验证IOC有效性
python scripts/verify_real_iocs.py

# 每周更新IOC库
git -C iocs/ pull
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

### 4. 钉钉告警配置

```yaml
# config_soe.yaml
alerting:
  methods:
    - type: "dingtalk"
      enabled: true
      webhook: "https://oapi.dingtalk.com/robot/send?access_token=xxx"
```

**告警效果**:
```markdown
### 🚨 DNS威胁检测告警

**检测时间**: 2026-01-07 09:30:15
**威胁数量**: 1 个

**✅ accesserdsc.com**
DNS服务器: 210.77.176.2
威胁类别: C2
缓存年龄: 1秒
```

## 安全性说明

### RD=0探测不会污染缓存

**实验验证**:
```bash
python scripts/test_rd0_pollution.py
```

**预期输出**:
```
========== 实验：RD=0探测是否污染DNS缓存 ==========

[1] RD=0探测（初始）: MISS
[2] RD=0探测（再次）: MISS

✅ 验证通过：RD=0探测不污染缓存！

对比实验：RD=1会污染缓存
[1] RD=0探测（初始）: MISS
[2] RD=1查询（污染）: HIT
[3] RD=0探测（验证）: HIT（被RD=1污染）
```

**结论**:
- ✅ RD=0查询不触发递归
- ✅ 不创建新的DNS缓存
- ✅ 可安全用于持续监控

### 误报率

基于多域名测试（7个IOC，19台DNS）:
- **误报率**: 0%
- **检测准确性**: ⭐⭐⭐⭐⭐

**详细报告**: `references/MULTI_DOMAIN_TEST_REPORT.md`

## 故障排查

### 问题1: 钉钉告警不工作

**检查清单**:
- [ ] Webhook URL是否正确
- [ ] `enabled: true` 是否设置
- [ ] 网络是否可达 oapi.dingtalk.com
- [ ] 机器人安全设置（IP白名单/关键词）

**测试方法**:
```python
import requests
webhook = "YOUR_WEBHOOK_URL"
message = {
    "msgtype": "text",
    "text": {"content": "测试消息"}
}
requests.post(webhook, json=message)
```

### 问题2: 自动验证未生效

**检查配置**:
```yaml
advanced:
  auto_verify_threats: true  # 确保为true
```

**查看日志**:
```bash
grep "自动验证" logs/dns_detector_v2.log
```

### 问题3: 性能未提升

**可能原因**:
- 域名缓存未命中（首次运行）
- 网络延迟过高
- DNS服务器限速

**诊断命令**:
```bash
python scripts/test_v2.py --verbose
```

## 技术参考

### 学术基础

1. **TruffleHunter** (IMC 2020)
   - 论文: "TruffleHunter: Cache Snooping Rare Domains at Large Public DNS Resolvers"
   - 链接: https://www.usenix.org/conference/imc20/presentation/moura

2. **DNS Cache Snooping**
   - IETF Draft: https://www.ietf.org/archive/id/draft-ietf-dnsop-cache-snooping-01.html

3. **MITRE ATT&CK - C2**
   - 链接: https://attack.mitre.org/tactics/TA0011/

### 威胁情报来源

- [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)
- [Palo Alto Unit 42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel)
- [VirusTotal](https://www.virustotal.com)

## 附加资源

### 技术报告

详见 `references/` 目录：

1. **DETECTOR_V2_README.md** - V2版本完整说明
2. **DETECTION_RESULT.md** - 首次检测结果报告
3. **SGCC_VERIFICATION_REPORT.md** - 国家电网威胁验证报告
4. **MULTI_DOMAIN_TEST_REPORT.md** - 多域名精确性测试报告
5. **CHANGELOG_V2.md** - V2改进日志

### 工具脚本

- `main_v2.py` - V2主程序（推荐）
- `main.py` - V1主程序
- `detector_v2.py` - V2检测器
- `dns_probe.py` - DNS探测核心
- `verify_real_iocs.py` - IOC验证工具
- `find_soe_dns.py` - 央企DNS发现工具
- `test_v2.py` - V2性能测试
- `test_rd0_pollution.py` - RD=0污染验证

---

**免责声明**: 本技能仅用于授权的安全测试和研究目的。使用者需遵守相关法律法规，对使用本技能产生的任何后果负责。

---

## ATT&CK 技术映射表

DNS缓存探测威胁检测覆盖攻击者的 C2 通信和命令控制阶段。

| 战术 | 技术 | 子技术 | DNS缓存检测关联 |
|------|------|--------|----------------|
| Command and Control | T1071 | Application Layer Protocol | DNS作为C2通道的检测 |
| Command and Control | T1071.004 | DNS | DNS隧道和DNS C2通信检测（核心） |
| Command and Control | T1568 | Dynamic Resolution | C2域名动态解析检测 |
| Command and Control | T1568.002 | Domain Generation Algorithms | DGA域名DNS查询检测 |
| Command and Control | T1105 | Ingress Tool Transfer | 通过DNS下载恶意载荷的缓存痕迹 |
| Command and Control | T1573 | Encrypted Channel | DoH/DoT加密DNS通信规避检测 |
| Command and Control | T1573.002 | Asymmetric Cryptography | DNS over HTTPS/TLS加密C2 |
| Defense Evasion | T1567 | Exfiltration Over Web Service | DNS作为数据外传通道检测 |
| Defense Evasion | T1567.004 | Exfiltration Over Webhook | DNS外传到C2 Webhook |
| Exfiltration | T1048 | Exfiltration Over Alternative Protocol | DNS TXT记录数据外传 |
| Exfiltration | T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | DoH加密外传 |
| Discovery | T1046 | Network Service Discovery | 内网DNS服务器枚举 |
| Discovery | T1018 | Remote System Discovery | 通过DNS缓存发现内网主机活动 |
| Reconnaissance | T1590 | Gather Victim Host Information | DNS缓存暴露内网通信目标 |
| Reconnaissance | T1590.002 | DNS | DNS配置和历史暴露攻击面 |
| Reconnaissance | T1592 | Gather Victim Host Info | DNS缓存泄露主机访问行为 |
| Initial Access | T1566 | Phishing | 钓鱼链接触发的DNS解析缓存 |
| Initial Access | T1190 | Exploit Public-Facing Application | 漏洞利用载荷的DNS下载痕迹 |
| Execution | T1106 | Native API | 恶意程序调用DNS API通信 |
| Persistence | T1547 | Boot or Logon Autostart Execution | DNS C2持久化通信的周期性缓存 |

### ATT&CK 缓解措施

| Mitigation ID | 名称 | DNS缓存检测关联 |
|--------------|------|----------------|
| M1037 | Filter Network Traffic | DNS过滤和RPZ响应策略 |
| M1031 | Network Intrusion Prevention | DNS层威胁拦截（RPZ/DoH拦截） |
| M1021 | Restrict Web-Based Network Content | DNS黑名单和域名分类过滤 |
| M1057 | Data Loss Prevention | DNS外传数据检测和阻断 |
| M1041 | Encrypt Sensitive Information | DNS通信加密（DoH/DoT）虽保护隐私但需监控 |

---

## OWASP Top 10 映射表

DNS威胁检测与Web安全的交叉映射。

| OWASP 类别 | CWE | ATT&CK | DNS缓存检测关联 |
|------------|-----|--------|----------------|
| A01 — Broken Access Control | CWE-284 | T1071.004 | 内网主机未授权访问恶意DNS域名 |
| A02 — Cryptographic Failures | CWE-319 | T1573.002 | DNS明文查询暴露通信目标，需DoH/DoT加密 |
| A03 — Injection | CWE-89 | T1568.002 | DGA域名注入DNS缓存规避黑名单 |
| A04 — Insecure Design | CWE-209 | T1590.002 | DNS配置泄露内部网络拓扑信息 |
| A05 — Security Misconfiguration | CWE-16 | T1046 | DNS服务器递归查询开放导致放大攻击 |
| A06 — Vulnerable & Outdated Components | CWE-1035 | T1071 | 过时DNS软件版本存在已知漏洞 |
| A07 — Identification & Authentication Failures | CWE-287 | T1071.004 | DNS域传送(AXFR)未授权区域复制 |
| A08 — Software & Data Integrity Failures | CWE-506 | T1568 | DNS响应投毒（DNS Cache Poisoning） |
| A09 — Security Logging & Monitoring Failures | CWE-778 | T1048 | DNS查询日志缺失导致外传不可追溯 |
| A10 — SSRF | CWE-918 | T1071.004 | 利用DNS重绑定发起SSRF攻击 |

---

## Sigma 检测规则

### 规则1: DNS C2 通信检测（缓存探测发现）

```yaml
title: DNS缓存探测发现C2域名命中
id: d3f4a5b6-7c8d-4e9f-0a1b-2c3d4e5f6a7b
status: experimental
description: TruffleHunter DNS缓存探测检测到内网主机访问已知C2域名
description: 检测DNS日志中已知C2域名的解析请求或防火墙日志中的C2 IP通信
author: dns-cache-detection
logsource:
    product: dns
    service: query
detection:
    selection_c2_domain:
        query|endswith:
            - accesserdsc.com
            - aiaggregator.com
            - allocatinow.sbs
    condition: selection_c2_domain
falsepositives:
    - 安全研究分析（需白名单）
    - 威胁情报采集系统
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.004
    - attack.t1568
    - owasp.a05.2021
```

### 规则2: DNS隧道数据外传检测

```yaml
title: DNS隧道数据外传行为检测
id: e4a5b6c7-8d9e-4f0a-1b2c-3d4e5f6a7b8c
status: experimental
description: 检测DNS日志中的隧道外传行为（超长子域名+高频TXT查询+可疑TLD）
description: 基于DNS查询模式检测数据外传行为
author: dns-cache-detection
logsource:
    product: dns
    service: query
detection:
    selection_long_subdomain:
        query|re: .*[a-zA-Z0-9]{40,}.*
    selection_txt_highfreq:
        record_type: TXT
        query|endswith:
            - .xyz
            - .top
            - .click
            - .tk
            - .ml
            - .ga
            - .cf
    condition: selection_long_subdomain or selection_txt_highfreq
falsepositives:
    - 合法SDK的DNS验证记录（需白名单）
    - CDN健康检查
level: high
timeframe: 5m
tags:
    - attack.exfiltration
    - attack.t1048
    - attack.t1567
    - attack.t1071.004
    - owasp.a09.2021
```

---

## YARA 规则

### 规则1: DNS隧道恶意软件特征

```yara
rule DNS_Tunneling_Malware_Feature {
    meta:
        description = "检测使用DNS隧道的恶意软件特征（dnscat2/iodine/Cobalt Strike DNS Beacon）"
        author = "dns-cache-detection"
        date = "2026-06-22"
    strings:
        $dnscat2 = "dnscat2" nocase
        $iodine = "iodine" nocase
        $dns_beacon = "dns_beacon" nocase
        $base32_pattern = /[A-Z2-7]{30,}/
        $hex_pattern = /[0-9a-f]{32,}/
    condition:
        any of ($dnscat2, $iodine, $dns_beacon) or $base32_pattern or $hex_pattern
}
```

### 规则2: DNS C2配置文件特征

```yara
rule DNS_C2_Config_Patterns {
    meta:
        description = "检测DNS C2配置文件和硬编码域名"
        author = "dns-cache-detection"
        date = "2026-06-22"
    strings:
        $c2_domain_1 = "accesserdsc.com" nocase
        $c2_domain_2 = "aiaggregator.com" nocase
        $dns_tunnel = ".tunnel." nocase
        $dga_pattern = /[a-z0-9]{8,20}\.(xyz|top|click|tk|ml|ga|cf)/
    condition:
        any of them
}
```

---

## CVE 参考表

| CVE | 漏洞名称 | DNS缓存检测关联 |
|-----|---------|----------------|
| CVE-2020-1350 | SIGRed (DNS BIND RCE) | DNS服务器漏洞影响缓存完整性 |
| CVE-2017-3143 | BIND TSIG缺陷 | DNS服务器认证绕过影响探测可信度 |
| CVE-2018-5740 | BIND Denial of Service | DNS服务器可用性影响检测结果 |
| CVE-2021-25215 | BIND DNS over TCP RCE | TCP DNS通信漏洞影响检测面 |
| CVE-2023-28287 | Windows Server DNS RCE | Windows DNS服务器漏洞风险 |

---

## IOC 采集指引

| IOC 类型 | 采集来源 | 格式 | 优先级 | 处置 |
|---------|---------|------|--------|------|
| C2 域名 | DNS缓存探测命中 | FQDN | 🔴 高 | 转发 → `domain-analysis` |
| C2 IP | 域名解析结果 | IPv4/IPv6 | 🔴 高 | 转发 → `ip-analysis` |
| DNS 隧道域名 | 高频TXT查询/超长子域名 | FQDN | 🔴 高 | 转发 → `url-analysis` |
| DGA 域名 | 域名生成算法特征 | FQDN Pattern | 🟡 中 | 记录 → IOC库 |
| 受感染主机IP | DNS日志关联 | IPv4 Internal | 🔴 高 | 转发 → `linux-ir` / `windows-ir` / `macos-ir` |
| DNS服务器指纹 | 版本和配置探测 | String | 🟡 中 | 记录 → 资产属性 |
| 威胁类别标签 | IOC分类(C2/钓鱼/矿池) | String | 🟡 中 | 记录 → 威胁标签 |
| 检测时间戳 | 缓存TTL计算 | ISO8601 | 🟢 低 | 记录 → 检测报告 |

---

## 合规标准参考

| 标准 | 章节 | DNS缓存检测关联 |
|------|------|----------------|
| ISO 27001 | A.12.5 运行软件技术漏洞 | DNS服务器漏洞检测和修补 |
| ISO 27001 | A.13.1 网络安全管理 | DNS作为网络基础设施安全监控 |
| NIST SP 800-53 | SC-7 边界保护 | DNS层流量过滤和威胁检测 |
| NIST SP 800-53 | SI-4 信息系统监控 | DNS查询监控和异常检测 |
| NIST SP 800-53 | SC-8 传输保密性 | DNS通信加密(DoH/DoT)评估 |
| NIST SP 800-137 | 信息安全持续监控 | DNS缓存持续监控是网络层持续监控的核心组件 |
| NIST CSF | Detect (DE.CM) | DNS威胁检测是持续监控的核心能力 |
| GDPR | Art.32 | DNS日志可能包含个人数据，需安全处理 |
| 等保2.0 | 第八章 网络通信安全 | DNS安全是网络通信安全的核心组件 |
| 等保2.0 | 第九章 环境安全 | DNS服务器安全基线和持续监控 |

---

## 跨技能工作流

### 工作流1: DNS检测 → 威胁分析

```
dns-cache-detection (检测C2命中)
  ├→ domain-analysis (C2域名深度分析)
  ├→ ip-analysis (C2服务器IP关联分析)
  ├→ url-analysis (C2 URL分析)
  └→ ttp-extractor (提取攻击者TTP)
```

### 工作流2: DNS检测 → 应急响应

```
dns-cache-detection (发现受感染主机)
  ├→ linux-ir / windows-ir / macos-ir (主机应急响应)
  ├→ traffic-analysis (关联流量异常)
  └→ phishing-analysis (钓鱼攻击关联)
```

### 工作流3: DNS检测 → 情报沉淀

```
dns-cache-detection (检测报告)
  ├→ asset-monitor (更新资产风险标记)
  ├→ researching-vulnerabilities (DNS漏洞关联)
  ├→ pdf-report (生成威胁报告)
  └→ data-desensitize (报告脱敏处理)
```

---

**版本**: 2.1.0
**更新时间**: 2026-06-22
**维护者**: DNS Security Research Team
