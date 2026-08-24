---
name: traffic-analysis
description: 当用户要求"分析 PCAP"、"流量分析"、"网络抓包分析"、"检测恶意流量"、"提取网络 IOC"、"分析网络通信"、"C2 检测"、"威胁狩猎"、"事件响应"、"取证分析"时使用此技能。
metadata:
  version: 2.0.0
  builtin: true
---

# 网络流量分析

## 依赖要求

**Python 版本**: 3.8+

**工具发现优先级**（从高到低）：

1. `CYBERSEC_TSHARK_PATH` / `CYBERSEC_CAPINFOS_PATH` 环境变量（应用注入）
2. `shutil.which()` PATH 查找
3. Windows 标准路径：`C:\Program Files\Wireshark\`

**分析引擎优先级**：

| 引擎 | 优先级 | 功能 | 安装方式 |
|------|--------|------|---------|
| tshark | 主引擎 | 完整功能（协议分布/TCP会话/DNS/HTTP/TLS/IOC） | Wireshark 附带 |
| scapy | 兜底引擎 | 基础功能（协议/IP/端口/DNS/TLS SNI/HTTP），无 TCP 会话统计 | `pip install scapy` |

**其他工具**:
| 工具 | 用途 | 发现方式 |
|------|------|---------|
| capinfos | 文件元信息 | wireshark 附带，同 tshark 路径 |
| rg | 内容搜索 | `brew install ripgrep` / PATH |

**安装方式**：
- **Windows（推荐）**：通过应用安装包安装 Wireshark，应用自动注入环境变量
- **macOS**：`brew install wireshark`
- **Linux**：`sudo apt install wireshark`
- **scapy 兜底**：`pip install scapy`（tshark 不可用时自动降级）

## 使用方法

```bash
# 环境检测
python3 <SKILL_DIR>/scripts/check_env.py

# 快速概览（自动选择引擎：tshark > scapy 兜底）
python3 <SKILL_DIR>/scripts/pcap_analyze.py <file.pcap>

# JSON 输出
python3 <SKILL_DIR>/scripts/pcap_analyze.py -j <file.pcap>

# 纯 scapy 兜底（tshark 不可用时手动调用）
python3 <SKILL_DIR>/scripts/pcap_scapy_fallback.py <file.pcap>
```

**自动降级逻辑**：`pcap_analyze.py` 在检测到 tshark 不可用时，自动调用 scapy 进行分析，无需手动切换。

---

## 分析工作流

### Phase 1: 确认目标与概览
```bash
capinfos file.pcap                    # 文件信息
tshark -r file.pcap -q -z io,phs      # 协议分布
tshark -r file.pcap -q -z conv,tcp    # TCP 会话
```

| 目标 | 关注点 | 方法 |
|------|--------|------|
| **恶意软件分析** | C2 通信、外泄、感染链 | 协议分析 + 行为模式 |
| **威胁狩猎** | 异常模式、未知威胁 | 统计分析 + 基线对比 |
| **事件响应** | 时间线、攻击范围 | 时序分析 + 关联 |
| **CTF/取证** | 隐藏数据、flag | 内容搜索 + 文件提取 |

### Phase 2: 快速概览

**获取基本信息：**
```bash
# 文件信息
capinfos file.pcap

# 协议分布
tshark -r file.pcap -q -z io,phs

# 会话统计
tshark -r file.pcap -q -z conv,tcp
```

**关键问题：**
- 时间范围？持续多久？
- 主要协议？TCP/UDP/其他？
- 多少个唯一 IP？内网还是外网？

### Phase 3: 根据目标深入分析

#### 目标 A：恶意软件/C2 分析

**1. 识别 C2 通信模式**
```bash
# 长连接 (C2 常见)
tshark -r file.pcap -q -z conv,tcp | sort -t'|' -k5 -rn | head

# 周期性连接 (Beaconing)
tshark -r file.pcap -Y "tcp.flags.syn==1" -T fields -e frame.time_relative -e ip.dst | sort -n

# 非标准端口的 HTTP/TLS
tshark -r file.pcap -Y "http and tcp.port != 80" -T fields -e ip.dst -e tcp.dstport
tshark -r file.pcap -Y "tls and tcp.port != 443" -T fields -e ip.dst -e tcp.dstport
```

**2. 检查数据外泄**
```bash
# 大量上传 (外泄特征)
tshark -r file.pcap -q -z conv,tcp | awk -F'|' '{if($4>$5) print}'

# FTP 上传
tshark -r file.pcap -Y "ftp.request.command == STOR" -T fields -e ftp.request.arg

# DNS 隧道 (超长查询)
tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | awk 'length>50'
```

**3. 提取文件**
```bash
# tshark 导出 HTTP 对象
tshark -r file.pcap --export-objects http,./exported/

# 导出 FTP 文件
tshark -r file.pcap --export-objects ftp,./exported/

# 导出 SMB 文件
tshark -r file.pcap --export-objects smb,./exported/
```

#### 目标 B：威胁狩猎

**1. 统计异常检测**
```bash
# 连接频率异常 (同一目标大量连接)
tshark -r file.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head

# 端口扫描特征 (同一源访问多端口)
tshark -r file.pcap -T fields -e ip.src -e tcp.dstport | sort | uniq | cut -f1 | uniq -c | sort -rn

# 失败连接 (RST/无响应)
tshark -r file.pcap -Y "tcp.flags.rst==1" -T fields -e ip.dst | sort | uniq -c | sort -rn
```

**2. 协议异常检测**
```bash
# 非标准端口 HTTP
tshark -r file.pcap -Y "http and tcp.port != 80 and tcp.port != 8080" -T fields -e ip.dst -e tcp.dstport

# 非标准端口 TLS
tshark -r file.pcap -Y "tls and tcp.port != 443" -T fields -e ip.dst -e tcp.dstport

# DNS 异常 (TXT 记录常用于隧道)
tshark -r file.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name
```

#### 目标 C：事件响应

**1. 建立时间线**
```bash
# 首个和最后一个包时间
capinfos -a -e file.pcap

# 按时间排序关键事件
tshark -r file.pcap -Y "http.request or dns.qry.name or tls.handshake" \
  -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info | head -50
```

**2. 确定感染源**
```bash
# 首个外部连接
tshark -r file.pcap -Y "ip.dst != 10.0.0.0/8 and ip.dst != 172.16.0.0/12 and ip.dst != 192.168.0.0/16" \
  -T fields -e frame.time -e ip.src -e ip.dst -c 10
```

**3. 横向移动检测**
```bash
# 内网 SMB/RDP
tshark -r file.pcap -Y "tcp.port==445 or tcp.port==3389" -T fields -e ip.src -e ip.dst | sort -u
```

#### 目标 D：CTF/取证

**1. 搜索关键字**
```bash
# 在 PCAP 中搜索字符串 (使用 rg)
rg -a "flag" file.pcap
rg -a "password|secret|key" file.pcap
rg -a -o "[A-Za-z0-9+/]{20,}={0,2}" file.pcap  # Base64

# tshark 过滤包含特定内容的包
tshark -r file.pcap -Y "frame contains \"flag\""
```

**2. 提取隐藏数据**
```bash
# HTTP 文件
tshark -r file.pcap --export-objects http,./http_files/

# FTP 文件
tshark -r file.pcap --export-objects ftp,./ftp_files/

# 原始 TCP 流
tshark -r file.pcap -z follow,tcp,raw,0 | xxd -r -p > stream0.bin
```

**3. 协议异常**
```bash
# ICMP 隧道
tshark -r file.pcap -Y "icmp" -T fields -e data

# DNS TXT 记录 (常藏数据)
tshark -r file.pcap -Y "dns.txt" -T fields -e dns.txt
```

### Phase 4: IOC 提取与报告

提取 IOC 后按 `references/report-format.md` 输出报告。

---

## 通用异常识别

### 流量模式异常

| 模式 | 正常 | 异常 |
|------|------|------|
| **连接时长** | 短暂请求响应 | 长时间保持连接 |
| **数据方向** | 请求小/响应大 | 请求大/响应小 (外泄) |
| **时间分布** | 工作时间为主 | 凌晨/周末活跃 |
| **连接频率** | 随机间隔 | 固定周期 (信标) |
| **端口使用** | 标准端口 | 高位随机端口 |

### 协议异常

| 协议 | 正常 | 异常 |
|------|------|------|
| **DNS** | 短域名、常见 TLD | 超长域名、奇怪 TLD |
| **HTTP** | GET/POST 常规路径 | 奇怪 URI、大量 POST |
| **TLS** | 知名 CA、常规 SNI | 自签名、IP 直连 |
| **ICMP** | 小数据包 | 大数据包 (隧道) |

---

## IOC 提取清单

分析完成后，提取以下 IOC：

```bash
# IP 地址 (排除内网)
tshark -r file.pcap -T fields -e ip.dst | sort -u | grep -v "^10\.\|^172\.1[6-9]\.\|^172\.2\|^172\.3[01]\.\|^192\.168\."

# 域名 (DNS + TLS SNI)
tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | sort -u
tshark -r file.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name | sort -u

# URL
tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u

# User-Agent
tshark -r file.pcap -Y "http.user_agent" -T fields -e http.user_agent | sort -u

# JA3 指纹
tshark -r file.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.ja3 | sort -u

# 文件哈希 (提取后计算)
tshark -r file.pcap --export-objects http,./out/ && shasum -a 256 ./out/*
```

---

## 工具速查

| 任务 | 命令 |
|------|------|
| 文件信息 | `capinfos file.pcap` |
| 协议分布 | `tshark -r file.pcap -q -z io,phs` |
| TCP 会话 | `tshark -r file.pcap -q -z conv,tcp` |
| DNS 查询 | `tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name` |
| HTTP 请求 | `tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri` |
| TLS SNI | `tshark -r file.pcap -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name` |
| 跟踪 TCP 流 | `tshark -r file.pcap -z follow,tcp,ascii,0` |
| 导出文件 | `tshark -r file.pcap --export-objects http,./out/` |
| 内容搜索 | `rg -a "keyword" file.pcap` |

---

## 与其他技能的关联

**分析过程中发现 IOC 时的处理：**

| 提取到的 IOC | 调用的技能 | 说明 |
|-------------|-----------|------|
| C2 IP | `ip-analysis` | 分析回连 IP 威胁情报 |
| C2 域名 | `domain-analysis` | 分析 DNS 查询中的恶意域名 |
| HTTP URL | `url-analysis` | 分析恶意下载链接 |
| Office 文件 | `office-malware-analyzer` | 分析下载的 Office 文档 |
| 可执行文件 | `binary-reverse-engineering` | 分析下载的恶意程序 |

**上游技能**（可能调用本技能）：
- `binary-reverse-engineering` - 动态分析需要抓包
- `ip-analysis` - 分析 IP 关联的流量
- `domain-analysis` - 分析域名关联的流量
- `url-analysis` - 分析 URL 关联的流量

**下游技能**（本技能输出流向）：
- `linux-ir` / `windows-ir` - IR 流程中的流量分析步骤
- `ttp-extractor` - 从流量中提取的 TTP 映射
- `pdf-report` - 流量分析报告生成
- `data-desensitize` - 检查流量中是否有未脱敏数据外泄

**调用时机：**
1. 提取到外部 IP 后，对每个 IP 调用 `ip-analysis`
2. 提取 DNS 查询的域名后，调用 `domain-analysis`
3. 提取 HTTP URL 后，调用 `url-analysis`
4. 导出文件后，根据类型调用对应分析技能
5. 发现可疑可执行文件时，调用 `binary-reverse-engineering`

## 参考文件

- **[references/report-format.md](references/report-format.md)** - 📋 报告格式规范（必读）

---

## MITRE ATT&CK 技术映射表

流量分析覆盖攻击者的完整网络活动链路，从侦察到外泄。

| 战术 | 技术ID | 技术名称 | 流量分析场景 |
|------|--------|----------|-------------|
| **Reconnaissance** | T1595.001 | Scanning IP Blocks | 端口扫描、SYN flood 检测 |
| **Reconnaissance** | T1595.002 | Scanning Vulnerability | 漏洞扫描流量特征（大量 404/403 响应） |
| **Initial Access** | T1566.002 | Phishing Link | 钓鱼邮件中的恶意 URL 流量 |
| **Initial Access** | T1190 | Exploit Public-Facing Application | Web 攻击流量（SQLi/XSS/RCE Payload） |
| **Execution** | T1059 | Command and Scripting Interpreter | C2 通道中的命令执行流量 |
| **Persistence** | T1098 | Account Manipulation | 异常认证流量 |
| **Defense Evasion** | T1090.001 | Internal Proxy | 内网代理跳转流量 |
| **Defense Evasion** | T1090.003 | Tor Proxy | Tor 出口节点流量 |
| **Defense Evasion** | T1027 | Obfuscated Files or Information | 加密/编码的恶意载荷传输 |
| **Discovery** | T1046 | Network Service Discovery | 内网端口扫描（SMB/RDP/SSH） |
| **Discovery** | T1018 | Remote System Discovery | ARP 扫描、ICMP sweep |
| **Collection** | T1056 | Input Capture | 数据包中的键盘记录/屏幕截图外传 |
| **Command and Control** | T1071.001 | Web Protocols | HTTP/HTTPS C2 通信 |
| **Command and Control** | T1071.004 | DNS | DNS 隧道、DNS Beaconing |
| **Command and Control** | T1573.002 | Asymmetric Cryptography | TLS C2 加密通信 |
| **Command and Control** | T1095 | Non-Application Layer Protocol | ICMP 隧道、UDP C2 |
| **Command and Control** | T1105 | Ingress Tool Transfer | 恶意文件下载流量 |
| **Command and Control** | T1571 | Non-Standard Port | 非标准端口通信（如 4444/8443） |
| **Lateral Movement** | T1021.002 | SMB/AdminShares | SMB 横向移动流量 |
| **Lateral Movement** | T1021.001 | Remote Desktop Protocol | RDP 横向移动 |
| **Exfiltration** | T1041 | Exfiltration Over C2 Channel | 通过 C2 通道外泄数据 |
| **Exfiltration** | T1048.002 | Exfiltration Over Asymmetric Protocol | HTTPS/TLS 数据外泄 |
| **Exfiltration** | T1567.002 | Exfiltration to Cloud Storage | 上传到云存储（AWS S3/OneDrive） |
| **Impact** | T1498 | Network Denial of Service | DDoS 攻击流量 |
| **Impact** | T1499.004 | Application or System Exploitation | 服务崩溃攻击 |

### ATT&CK 缓解措施参考

| Mitigation ID | 名称 | 与流量分析的关系 |
|---------------|------|-----------------|
| M0317 | Network Intrusion Prevention | 流量分析是 IPS 规则调优的基础 |
| M0017 | Training | 流量分析结果用于安全意识培训 |
| M0021 | Disable or Remove Feature | 根据流量分析禁用不需要的服务 |
| M0029 | Remote Data Storage | 监控异常的云存储上传流量 |

---

## OWASP Top 10 + CWE 映射表

流量分析可检测 Web 攻击流量，对应 OWASP 风险类别：

| OWASP 2021 | CWE | 攻击流量特征 | 检测方法 |
|-----------|------|-------------|----------|
| **A01** Broken Access Control | CWE-285, CWE-862 | 越权访问 API 请求 | 检测异常的 API 调用序列 |
| **A02** Cryptographic Failures | CWE-327, CWE-295 | 弱加密/过期 TLS | 检查 TLS 版本和密码套件 |
| **A03** Injection | CWE-89, CWE-79 | SQLi/XSS Payload 流量 | HTTP 请求内容匹配攻击模式 |
| **A04** Insecure Design | CWE-209 | 信息泄露响应 | 异常的错误响应消息体 |
| **A05** Security Misconfiguration | CWE-16 | 默认凭据/暴露管理接口 | 非常规端口的管理面板访问 |
| **A06** Vulnerable Components | CWE-1035 | 已知漏洞利用 Payload | 匹配 CVE 特征的请求模式 |
| **A07** Auth Failures | CWE-287, CWE-307 | 暴力破解/凭据填充 | 高频登录请求 + 失败率分析 |
| **A08** Software/Data Integrity | CWE-502 | 反序列化攻击 | 异常的序列化数据传输 |
| **A09** Logging Failures | CWE-778 | 缺少审计日志的敏感操作 | 对比流量与日志的差异 |
| **A10** SSRF | CWE-918 | 服务端请求伪造 | 检测内网源 IP 的异常出站请求 |

---

## CVE 参考表（网络流量可检测的漏洞利用）

| CVE | 漏洞名称 | 流量特征 | 检测关键字段 |
|-----|----------|----------|-------------|
| CVE-2021-44228 | Log4Shell (Log4j RCE) | HTTP 请求中含 `${jndi:ldap://}` | HTTP Header/Body 内容 |
| CVE-2017-5638 | Apache Struts 2 RCE | Content-Type 中含 OGNL 表达式 | Content-Type Header |
| CVE-2019-0708 | BlueKeep (RDP RCE) | 特制 RDP 协商包 | RDP 连接初始包 |
| CVE-2021-34527 | PrintNightmare | MS-RPRN RPC 请求异常 | MS-RPRN Bind/Request |
| CVE-2023-23397 | Outlook Elevation | 特制 MAPI 属性消息 | MAPI/HTTP 流量 |
| CVE-2023-4911 | Looney Tunables (Linux) | 特制 ELF 加载流量 | 文件传输特征 |
| CVE-2024-3094 | XZ Utils Backdoor | SSH 连接特制握手 | SSH 协议特征 |

---

## Sigma 检测规则

### Sigma 规则 1: 可疑 C2 Beaconing 检测

```yaml
title: Suspicious Network Beaconing Pattern
id: 7e151c5b-6e9a-4f1a-a6b5-1f4d6e7c8a01
status: experimental
description: >
  检测周期性的网络连接模式（Beaconing），可能指示 C2 通信。
  基于 TCP 连接时间间隔分析，固定间隔的连接是 C2 框架的典型特征。
author: SecSkill Evolution System
references:
  - https://attack.mitre.org/techniques/T1571/
  - https://attack.mitre.org/techniques/T1071/001/
tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1571
  - attack.t1573.002
logsource:
  product: firewall
  service: connection
detection:
  selection:
    action: 'connection'
    destination_port:
      - 443
      - 8443
      - 4444
      - 8080
  timeframe: 10m
  condition: selection | count() by destination_ip >= 5
  # 同一目标 IP 在 10 分钟内连接 5 次以上
falsepositives:
  - 合法的 keep-alive 连接
  - API 轮询
  - 监控系统检查
level: medium
```

### Sigma 规则 2: DNS 隧道检测

```yaml
title: DNS Tunneling Detection
type: detect
id: 8b2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: >
  检测 DNS 隧道行为。超长域名、高频 TXT 查询、异常 TLD 是 DNS 隧道的典型特征。
  常见于 dnscat2、iodine、cobaltstrike 等 C2 工具。
author: SecSkill Evolution System
references:
  - https://attack.mitre.org/techniques/T1071/004/
  - https://attack.mitre.org/techniques/T1568/002/
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.defense_evasion
logsource:
  product: dns
  service: query
detection:
  long_query:
    query_name|re: '.{50,}'
  txt_records:
    query_type: 'TXT'
  suspicious_tld:
    query_name|endswith:
      - '.xyz'
      - '.top'
      - '.click'
      - '.work'
      - '.tk'
  timeframe: 1m
  condition: long_query or (txt_records and suspicious_tld) or txt_records | count() by source_ip >= 10
falsepositives:
  - DKIM/SPF TXT 记录查询
  - 合法的长域名 CDN
  - 企业 DNS 配置工具
level: high
```

---

## YARA 规则

### YARA 规则: PCAP 中的恶意载荷特征

```yara
rule Malware_Payload_In_PCAP {
  meta:
    description = "检测 PCAP 文件中的常见恶意载荷特征"
    author = "SecSkill Evolution System"
    date = "2026-06-21"
    reference = "https://attack.mitre.org/techniques/T1105/"
  strings:
    // PowerShell 下载命令
    $ps_download = /powershell.*DownloadFile|Invoke-WebRequest|iwr.*http/i nocase
    // Certutil 下载
    $certutil = /certutil.*-urlcache.*-split.*http/i nocase
    // BITSAdmin 下载
    $bitsadmin = /bitsadmin.*/transfer.*http/i nocase
    // CobaltStrike Beacon 特征
    $beacon = /%s\/.*\/[A-Za-z0-9+\/]{20,}={0,2}/
    // Metasploit Meterpreter
    $meterpreter = /meterpreter\.dll|metsrv\.dll/
    // Base64 编码的命令
    $b64_cmd = /powershell.*-enc\s+[A-Za-z0-9+/]{100,}={0,2}/ nocase
  condition:
    any of them
}

rule C2_Cert_Anomaly {
  meta:
    description = "检测异常 TLS 证书特征"
    author = "SecSkill Evolution System"
    date = "2026-06-21"
    reference = "https://attack.mitre.org/techniques/T1071/001/"
  strings:
    // 自签名证书
    $self_signed = /Issuer:.*Subject:.*/
    // Let's Encrypt 在非标准端口（可能合法但值得标记）
    $letsencrypt = /Let's Encrypt/ nocase
    // 临时 CA
    $temp_ca = /CN=.*temp|CN=.*test|CN=.*local/i
  condition:
    any of them
}
```

---

## 合规标准参考表

| 标准 | 相关章节 | 流量分析的角色 |
|------|---------|---------------|
| **ISO 27001** | A.13 通信安全 | 监控网络流量检测安全事件 |
| **ISO 27001** | A.12.4 事件日志 | 流量日志作为事件证据源 |
| **NIST SP 800-94** | 全文 | 网络流量入侵检测指南（核心标准） |
| **NIST SP 800-83** | 全文 | 恶意代码事件预防和处理指南 |
| **NIST SP 800-137** | 全文 | 信息安全持续监控 |
| **PCI DSS v4.0** | 11.5 | 入侵检测和监控网络流量 |
| **等保 2.0** | 第八章 - 网络通信安全 | 网络流量监控和入侵检测要求 |
| **GDPR** | Art.32 | 安全措施包括网络监控以保护数据处理 |

---

## IOC 采集指引（扩展）

### 高优先级 IOC

| 类型 | 提取方法 | 质量评估 |
|------|---------|----------|
| **C2 IP:Port** | TCP 长连接 + 非标准端口 | 端口越异常，置信度越高 |
| **C2 域名** | DNS 查询 + TLS SNI | DGA 域名 > 短域名 > 常见域名 |
| **JA3 指纹** | TLS Client Hello | 匹配已知恶意 JA3 库 |
| **JA3S 指纹** | TLS Server Hello | 服务端指纹，识别 C2 框架 |
| **JARM 指纹** | TLS 主动扫描 | 主动扫描 C2 服务器 |
| **文件哈希** | 导出 HTTP/SMB 文件 | SHA256 优先 |

### 中优先级 IOC

| 类型 | 提取方法 | 用途 |
|------|---------|------|
| **User-Agent** | HTTP UA 字段 | 异常 UA = 工具特征 |
| **HTTP Cookie** | Set-Cookie / Cookie | C2 会话标识 |
| **HTTP URI Pattern** | HTTP 请求路径 | C2 框架 URI 模式 |
| **TLS 密码套件** | TLS Handshake | C2 框架指纹 |
| **DNS TXT 记录** | DNS 响应 | 可能携带数据或 C2 指令 |
| **MAC 地址** | Ethernet 帧 | 设备指纹 |

### IOC 安全标记

- `defanged` — IP/URL 使用 [.] 消毒标记
- `TLP:CLEAR` — 可自由分享
- `TLP:AMBER` — 仅限受信任方
- `TLP:RED` — 仅限接收方

---

## 跨技能工作流

### 工作流 1: 恶意软件网络行为全链路分析
```
邮件附件 → office-malware-analyzer → [沙箱抓包] → traffic-analysis → ttp-extractor
     ↓                                          ↓
email-osint                              ip-analysis → domain-analysis
```

### 工作流 2: 事件响应 - 从 PCAP 到溯源
```
告警触发 → traffic-analysis (PCAP) → IOC 提取
     ↓                              ↓
     ↓                     ┌────────┼────────┐
     ↓                     ↓        ↓        ↓
     ↓              ip-analysis  url-analysis  domain-analysis
     ↓                     └────────┼────────┘
     ↓                              ↓
linux-ir/windows-ir         ttp-extractor → pdf-report
```

### 工作流 3: 数据外泄调查
```
DLP 告警 → traffic-analysis (出站流量)
     ↓
     ├→ data-desensitize (检测未脱敏数据)
     ├→ url-analysis (外传 URL 分析)
     └→ ip-analysis (目的 IP 溯源)
```

---

## AI 建议

发现邮箱地址时，可建议用户使用 `email-osint` 技能进行深入调查。
