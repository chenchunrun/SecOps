# MITRE ATT&CK 框架参考

## 14个战术阶段

| ID | 战术 | 描述 |
|----|------|------|
| TA0043 | 侦察 (Reconnaissance) | 收集目标信息 |
| TA0042 | 资源开发 (Resource Development) | 建立攻击资源 |
| TA0001 | 初始访问 (Initial Access) | 进入目标网络 |
| TA0002 | 执行 (Execution) | 运行恶意代码 |
| TA0003 | 持久化 (Persistence) | 维持访问权限 |
| TA0004 | 提权 (Privilege Escalation) | 获取更高权限 |
| TA0005 | 防御绕过 (Defense Evasion) | 规避安全检测 |
| TA0006 | 凭证访问 (Credential Access) | 窃取凭证 |
| TA0007 | 发现 (Discovery) | 探索目标环境 |
| TA0008 | 横向移动 (Lateral Movement) | 在网络中移动 |
| TA0009 | 收集 (Collection) | 收集目标数据 |
| TA0011 | 命令控制 (Command and Control) | C2通信 |
| TA0010 | 数据渗出 (Exfiltration) | 窃取数据 |
| TA0040 | 影响 (Impact) | 造成破坏 |

## 威胁狩猎方法

### 假设驱动狩猎
1. 提出假设（如"攻击者可能使用PowerShell进行横向移动"）
2. 确定数据源（Windows事件日志、Sysmon）
3. 编写查询（ELK/Splunk/SQL）
4. 分析结果
5. 验证或否定假设

### IoC驱动狩猎
1. 收集威胁情报IoC
2. 在历史日志中搜索匹配
3. 关联分析找到攻击链
4. 生成新的检测规则

### 行为分析狩猎
1. 建立正常行为基线
2. 检测异常偏离
3. 关联多个异常事件
4. 构建攻击时间线

## 检测数据源

### Windows
- Security Event Log (4688, 4624, 4625, 4672)
- Sysmon (1, 3, 7, 8, 10, 11, 13)
- PowerShell日志 (4103, 4104)
- WMI日志
- 任务计划日志

### Linux
- /var/log/auth.log
- /var/log/syslog
- /var/log/audit/audit.log
- ~/.bash_history
- /var/log/nginx/access.log

### 网络
- DNS查询日志
- HTTP/HTTPS代理日志
- NetFlow数据
- 防火墙日志

## 报告格式

```
## 威胁狩猎报告
- 日期: YYYY-MM-DD
- 猎手: [姓名]
- 假设: [描述]
- 数据源: [列出]
- 发现:
  - [IoC列表]
  - [异常行为]
  - [ATT&CK映射]
- 结论: [确认/否定/待定]
- 建议: [检测规则/修复措施]
```
