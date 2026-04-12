# 威胁标签说明

威胁情报中常见的 IP 标签及其含义。

## 攻击类型标签

| 标签 | 含义 | 风险等级 |
|------|------|---------|
| `c2` / `command_and_control` | 命令控制服务器 | 严重 |
| `botnet` | 僵尸网络节点 | 严重 |
| `malware` | 恶意软件分发 | 高 |
| `ransomware` | 勒索软件相关 | 严重 |
| `phishing` | 钓鱼攻击 | 高 |
| `spam` | 垃圾邮件发送 | 中 |
| `scanner` / `scanning` | 扫描探测 | 中 |
| `brute_force` | 暴力破解 | 高 |
| `exploit` | 漏洞利用 | 高 |
| `ddos` | DDoS 攻击源 | 高 |

## 服务类型标签

| 标签 | 含义 | 风险等级 |
|------|------|---------|
| `tor_exit` | Tor 出口节点 | 中 |
| `tor_relay` | Tor 中继节点 | 低 |
| `vpn` | VPN 服务 | 低 |
| `proxy` | 代理服务 | 中 |
| `hosting` | 托管服务 | 低 |
| `bulletproof` | 防弹主机 | 高 |
| `residential` | 住宅 IP | 低 |
| `datacenter` | 数据中心 | 低 |
| `mobile` | 移动网络 | 低 |

## APT 组织标签

| 标签 | 关联组织 | 风险等级 |
|------|---------|---------|
| `apt28` / `fancy_bear` | APT28 (俄罗斯) | 严重 |
| `apt29` / `cozy_bear` | APT29 (俄罗斯) | 严重 |
| `apt41` | APT41 (中国) | 严重 |
| `lazarus` | Lazarus Group (朝鲜) | 严重 |
| `apt33` / `elfin` | APT33 (伊朗) | 严重 |

## 恶意软件家族标签

| 标签 | 恶意软件 | 类型 |
|------|---------|------|
| `cobalt_strike` | Cobalt Strike | 渗透工具 |
| `emotet` | Emotet | 银行木马/下载器 |
| `trickbot` | TrickBot | 银行木马 |
| `qakbot` / `qbot` | QakBot | 银行木马 |
| `dridex` | Dridex | 银行木马 |
| `icedid` | IcedID | 银行木马 |
| `lockbit` | LockBit | 勒索软件 |
| `conti` | Conti | 勒索软件 |
| `revil` | REvil | 勒索软件 |

## C2 框架标签

| 标签 | 工具 | 默认端口 | 风险等级 |
|------|------|---------|---------|
| `cobalt_strike` | Cobalt Strike | 50050, 50055 | 严重 |
| `metasploit` / `meterpreter` | Metasploit | 4444 | 严重 |
| `sliver` | Sliver C2 | 31337, 8888 | 严重 |
| `havoc` | Havoc C2 | 40056 | 严重 |
| `empire` | PowerShell Empire | 1337 | 严重 |
| `mythic` | Mythic C2 | 7443 | 严重 |
| `brute_ratel` / `brc4` | Brute Ratel C4 | 443, 8443 | 严重 |
| `covenant` | Covenant | 7443 | 严重 |
| `poshc2` | PoshC2 | 443, 8443 | 严重 |

## RAT (远程访问木马) 标签

| 标签 | 恶意软件 | 默认端口 | 风险等级 |
|------|---------|---------|---------|
| `asyncrat` | AsyncRAT | 6606, 7707, 8808, 4782 | 严重 |
| `remcos` | Remcos RAT | 2404, 5000, 5060 | 严重 |
| `poison_ivy` | Poison Ivy | 3460 | 严重 |
| `quasar` / `quasarrat` | QuasarRAT | 4782, 4444 | 严重 |
| `njrat` / `bladabindi` | njRAT | 5552, 1177 | 严重 |
| `darkcomet` | DarkComet | 1604 | 严重 |
| `gh0st` / `ghost_rat` | Gh0st RAT | 8000 | 严重 |
| `nanocore` | NanoCore | 54984 | 严重 |
| `warzone` / `ave_maria` | Warzone RAT | 5200, 6703 | 严重 |
| `orcus` | Orcus RAT | 10134 | 严重 |
| `limerat` | LimeRAT | 可配置 | 严重 |
| `netwire` | NetWire RAT | 3360, 3380 | 严重 |

## 挖矿软件标签

| 标签 | 恶意软件 | 默认端口 | 风险等级 |
|------|---------|---------|---------|
| `cryptominer` / `miner` | 通用挖矿 | 3333, 7777 | 高 |
| `xmrig` | XMRig | 999, 18081 | 高 |
| `coinhive` | CoinHive | 80, 443 | 高 |
| `teamtnt` | TeamTNT | 可变 | 高 |

## 僵尸网络标签

| 标签 | 恶意软件 | 默认端口 | 风险等级 |
|------|---------|---------|---------|
| `mirai` | Mirai | 23, 2323 | 严重 |
| `mozi` | Mozi | 可变 | 严重 |
| `hajime` | Hajime | 可变 | 高 |
| `bashlite` / `gafgyt` | Bashlite | 23, 2323 | 高 |

## 置信度说明

威胁情报通常包含置信度评分：

| 置信度 | 含义 | 建议操作 |
|-------|------|---------|
| 90-100% | 确认恶意 | 立即阻断 |
| 70-89% | 高度可疑 | 建议阻断 |
| 50-69% | 可疑 | 深入调查 |
| 30-49% | 低置信度 | 持续监控 |
| < 30% | 不确定 | 仅供参考 |

## 时效性说明

威胁情报的时效性很重要：

| 时间范围 | 说明 |
|---------|------|
| 24 小时内 | 活跃威胁，高优先级 |
| 7 天内 | 近期威胁，需关注 |
| 30 天内 | 中期威胁，可监控 |
| 30 天以上 | 历史数据，仅供参考 |

IP 地址可能被回收或更换用途，历史恶意记录不代表当前状态。
