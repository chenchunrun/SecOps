# 从“会写代码”到“会守系统”：SecOps Agent（基于 Crush）正式可用

> 作者：chenchunrun  
> 项目：SecOps Agent（Crush 安全运维增强版）

很多团队已经在用 AI 写代码，但到了生产环境，真正高频的问题是告警、排障、配置漂移、漏洞与合规。  
SecOps Agent 的目标很直接：把 AI 从“编码助手”升级为“安全运维协同专家”。

![封面图：SecOps Agent 主界面](/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/cover-main-ui.png)

---

## 一、为什么要做 SecOps Agent

传统安全运维流程里，常见痛点是：

- 工具分散：监控、日志、漏洞、合规各自独立
- 处置慢：告警到定位再到修复链路太长
- 风险难控：AI 能执行，但缺少严格门禁
- 复盘困难：缺少完整可追溯的证据链

SecOps Agent 要做的是一条闭环：**观测 -> 分析 -> 决策 -> 执行 -> 审计**。

---

## 二、核心能力（可落地）

### 1）18 类 SecOps 工具统一接入

覆盖日志分析、监控查询、安全扫描、合规检查、证书与密钥审计、告警与事件时间线等核心能力。  
AI 可以在统一上下文中调用，不再在多个平台间来回切换。

![图1：SecOps 功能总览](/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/01-secops-overview.png)

### 2）能力门禁 + 风险决策

对高风险操作进行强制门禁，支持阻断、审批、会话级放行等策略。  
这样“能做事”，也“不会乱做事”。

![图2：权限确认弹窗](/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/02-permission-dialog.png)

### 3）双专家智能体协作

- `OpsAgent`：偏稳定性、可用性、恢复路径
- `SecurityExpertAgent`：偏威胁判断、合规与安全建议

两者可在同一流程内协作，减少单一视角误判。

![图3：双专家工作流示意](/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/03-dual-agent-flow.png)

### 4）审计与 SIEM 对接

关键操作、风险决策、工具调用链路可留痕，便于合规审计、复盘与对账。

![图4：审计与报告视图](/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/04-audit-siem.png)

---

## 三、一个真实工作场景

**场景：凌晨核心业务延迟突增，持续告警。**

SecOps Agent 的标准动作：

1. 拉取指标，定位异常时间窗
2. 联动日志提取错误模式
3. 触发安全扫描排查异常行为
4. 对照配置基线识别漂移
5. 输出分级处置建议并留存审计记录

相比传统人肉串联，多数场景下可显著缩短定位时间。

![图5：告警联动排查界面](/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/05-alert-investigation.png)

---

## 四、跨平台一键安装（macOS / Linux / Windows）

已支持跨平台发布包生成与一键安装。

维护者发布：

```bash
./scripts/package_cross_platform.sh
```

用户安装（macOS / Linux）：

```bash
chmod +x install.sh
./install.sh
```

用户安装（Windows）：

```powershell
Set-ExecutionPolicy -Scope Process Bypass
./install.ps1
```

---

## 五、总结

SecOps Agent 不是再做一个“能聊天”的 AI，而是让 AI 真正进入安全运维主流程：

- 能执行
- 可控风险
- 可审计
- 可复盘

如果你的团队正在推进智能化运维或安全运营，这是一条可以直接试点落地的路径。

---

## 配图清单（请把截图放到以下文件名）

- `cover-main-ui.png`
- `01-secops-overview.png`
- `02-permission-dialog.png`
- `03-dual-agent-flow.png`
- `04-audit-siem.png`
- `05-alert-investigation.png`

目录：`/Users/newmba/Downloads/SecOpsCode/crush-main/docs/wechat/assets/`
