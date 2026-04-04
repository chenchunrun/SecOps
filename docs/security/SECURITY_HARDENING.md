# Security Hardening — crush-main

本目录记录 crush-main 代码库的安全加固记录，对应 [Charm](https://github.com/chenchunrun/SecOps) 的终端 AI 编程助手项目。

---

## v0.x — Security Hardening Patch

**日期**: 2026-03-22
**提交**: `6b27da5`, `d64b6a7`, `ad49b1a`
**范围**: 内部安全审计，覆盖 SQL 注入、命令注入、路径遍历、凭证暴露、 unsafe 反序列化、错误处理、输入验证

---

### Critical — 关键级 (4 项)

#### 1. 权限审计日志中 Params 未脱敏

**文件**: `internal/permission/secops_permission.go`

**问题**: `AuditLog` 将完整的 `PermissionRequest`（含 `Params` 字段）存入内存审计日志。`Params` 可能包含文件内容、凭证、API 密钥等敏感数据，直接落盘存在泄露风险。

**修复**: `AuditLog` 方法中设置 `sanitized.Params = nil`，仅保留元数据（工具名、操作、路径、风险评分、决策）。`Params` 永不持久化。

```go
// Before
ds.auditLog = append(ds.auditLog, auditRecord{
    Request: req,  // 包含完整 Params
    ...
})

// After
sanitized := *req
sanitized.Params = nil  // 敏感数据清除
ds.auditLog = append(ds.auditLog, auditRecord{
    Request: &sanitized,
    ...
})
```

---

#### 2. secops_adapter 类型混淆绕过能力检查

**文件**: `internal/agent/secops_adapter.go`

**问题**: `ExecuteTool` 使用类型断言 `params.(*SecOpsParams)` 将参数转换为 `SecOpsParams`，若传入非 `SecOpsParams` 类型（如空 `map[string]interface{}`），类型断言成功但字段为零值，可能绕过 capability 检查。

**修复**: 在类型断言前增加接口完整性校验，确保传入参数实现了所有必需字段。

```go
// Before
params := call.Params.(type)  // 直接断言，无校验

// After
params, ok := call.Params.(*SecOpsParams)
if !ok || params == nil {
    return nil, ErrInvalidParams
}
```

---

#### 3. Sandbox 审计日志暴露凭证

**文件**: `internal/sandbox/security.go`

**问题**: 命令审计日志记录完整命令内容，若命令包含凭证（如 `--password=xxx`、`--api-key=xxx`），敏感信息直接写入日志。

**修复**: 在写入审计日志前，对命令参数字段进行正则匹配脱敏，覆盖常见凭证模式（password、api_key、secret、token、credential 等）。

---

#### 4. SIEM 导出时凭证字段未清理

**文件**: `internal/audit/siem_export.go`

**问题**: 导出审计事件到 SIEM 时，未对 `Params` 和事件内容中的凭证字段（如 `password`、`api_key`、`token`）进行清理，敏感数据直接发送至外部系统。

**修复**:
- 导出前清理所有事件的 `Params` 字段
- 对事件内容中匹配凭证正则模式的字段值进行脱敏
- HTTP Exporter 强制启用 TLS（`TLSEnabled: true`）

---

### High — 高危级 (3 项)

#### 5. BannedCommands 未与 bash blocklist 对齐

**文件**: `internal/security/risk_assessment.go`

**问题**: 风险评估的禁用命令列表（BannedCommands）与 bash 的实际 blocklist 不一致，攻击者可通过 bash 内置命令绕过检测。

**修复**: 将 BannedCommands 列表与 [bash source](https://ftp.gnu.org/gnu/bash/) 中的禁用命令对齐，确保覆盖所有危险的 bash 内置命令。

---

#### 6. SIEM HTTP Exporter 未强制 TLS

**文件**: `internal/audit/siem_export.go`

**问题**: HTTP 导出器（ELK、Splunk）默认未启用 TLS，审计数据在传输过程中以明文发送，存在中间人攻击风险。

**修复**: 所有 HTTP Exporter 实例强制设置 `TLSEnabled: true`，默认使用 HTTPS。

---

#### 7. OAuth Token 和 API Key 未加密存储

**文件**: `internal/config/config.go` / `internal/security/`

**问题**: 配置文件中存储的 OAuth token 和 API Key 以明文保存，磁盘数据泄露时直接暴露。

**修复**: 实现 AES-256-GCM 对称加密，所有敏感配置项（token、api_key、secret）在写入配置文件前加密，读取时解密。

---

### Medium — 中危级 (5 项)

#### 8. edit.go 路径遍历（符号链接绕过）

**文件**: `internal/agent/tools/edit.go`

**问题**: 编辑工具未在安全边界检查前解析符号链接，攻击者可创建指向工作目录外的符号链接绕过路径限制。

**修复**: 在执行任何文件操作前使用 `filepath.EvalSymlinks` 解析路径，对工作目录和文件路径双方均进行解析，确保边界检查使用规范化路径。同时保留原始路径用于 filetracker 查找，避免 macOS `/tmp` → `/private/tmp` 路径差异导致的兼容性问题。

```go
// 解析符号链接用于安全边界检查
realFilePath := params.FilePath
if resolved, evalErr := filepath.EvalSymlinks(params.FilePath); evalErr == nil {
    realFilePath = resolved
}
realWorkingDir := workingDir
if resolved, evalErr := filepath.EvalSymlinks(workingDir); evalErr == nil {
    realWorkingDir = resolved
}

// 边界检查使用规范化路径，文件操作使用原始路径
if !strings.HasPrefix(realFilePath, realWorkingDir) {
    return errorResponse, nil
}
```

---

#### 9. grep.go 路径遍历（符号链接绕过）

**文件**: `internal/agent/tools/grep.go`

**问题**: 当 `ripgrep` 不可用时的降级正则搜索器未对符号链接目标进行边界检查，攻击者可创建指向工作目录外的符号链接进行任意文件读取。

**修复**: 在遍历文件前解析 `rootPath` 的符号链接，遍历过程中对每个路径实时解析符号链接并验证是否仍在边界内。越界时跳过该文件或目录。

```go
realRoot, err := filepath.EvalSymlinks(rootPath)
err = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
    realPath, evalErr := filepath.EvalSymlinks(path)
    if evalErr != nil || !strings.HasPrefix(realPath, realRoot) {
        if info.IsDir() {
            return filepath.SkipDir
        }
        return nil // 跳过符号链接越界的文件
    }
    ...
})
```

---

#### 10. PromQL 查询无长度限制（ReDoS / 资源耗尽）

**文件**: `internal/agent/tools/secops/monitoring_query.go`

**问题**: 监控查询工具接受任意长度的 PromQL 查询，攻击者可提交超长查询或构造 ReDoS 模式查询，导致监控后端资源耗尽。

**修复**: 强制查询长度上限 2000 字符，超出返回错误。覆盖 `ValidateParams` 和 `Execute` 两处入口。

```go
if len(p.Query) > 2000 {
    return fmt.Errorf("query exceeds maximum length of 2000 characters")
}
```

---

#### 11. 端口扫描无上限（DoS 风险）

**文件**: `internal/agent/tools/secops/network_diagnostic.go`

**问题**: 端口扫描工具接受无限制的端口列表，攻击者可提交数万个端口导致工具运行时间过长或资源耗尽。

**修复**: 强制端口列表上限 100 个，超出返回错误。

```go
if len(p.Ports) > 100 {
    return fmt.Errorf("port list exceeds maximum of 100 ports")
}
```

---

#### 12. 审计日志无内存上限

**文件**: `internal/permission/secops_permission.go`

**问题**: 权限服务内存审计日志（`auditLog` slice）无上限，长时间运行场景下持续追加可能导致内存耗尽。

**修复**: 引入 `maxAuditLogEntries = 10000` 常量，每次追加后检查上限，超出时从头部淘汰最旧记录（FIFO）。

```go
const maxAuditLogEntries = 10000

func (ds *DefaultService) AuditLog(...) {
    ds.auditLog = append(ds.auditLog, auditRecord{...})
    if len(ds.auditLog) > maxAuditLogEntries {
        ds.auditLog = ds.auditLog[len(ds.auditLog)-maxAuditLogEntries:]
    }
}
```

---

## 风险等级说明

| 等级 | 分值 | 说明 |
|------|------|------|
| **Critical** | ≥80 | 立即修复：可直接利用，导致严重后果 |
| **High** | 60–79 | 紧急修复：需要用户交互或特殊条件触发 |
| **Medium** | 40–59 | 高优先级：存在利用路径，需要防御纵深 |
| **Low** | <40 | 建议修复：提升攻击成本 |

---

## 修复验证

所有修复均通过测试覆盖：

```bash
# 全部测试通过
go test ./...

# 权限服务测试
go test ./internal/permission/...

# 安全模块测试
go test ./internal/security/...

# SecOps 工具测试
go test ./internal/agent/tools/secops/...

# 集成测试
go test ./internal/integration/...
```
