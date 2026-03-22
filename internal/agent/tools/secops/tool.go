package secops

// ToolType 工具类型
type ToolType string

const (
	ToolTypeLogAnalyze           ToolType = "log_analyze"
	ToolTypeMonitoringQuery      ToolType = "monitoring_query"
	ToolTypeComplianceCheck      ToolType = "compliance_check"
	ToolTypeCertificateAudit     ToolType = "certificate_audit"
	ToolTypeSecurityScan         ToolType = "security_scan"
	ToolTypeConfigurationAudit   ToolType = "configuration_audit"
	ToolTypeNetworkDiagnostic    ToolType = "network_diagnostic"
)

// SecOpsTool 工具接口
type SecOpsTool interface {
	// 获取工具类型
	Type() ToolType

	// 获取工具名称
	Name() string

	// 获取工具描述
	Description() string

	// 获取所需能力
	RequiredCapabilities() []string

	// 执行工具
	Execute(params interface{}) (interface{}, error)

	// 验证参数
	ValidateParams(params interface{}) error
}

// SecOpsToolRegistry 工具注册表
type SecOpsToolRegistry struct {
	tools map[string]SecOpsTool
}

// NewSecOpsToolRegistry 创建工具注册表
func NewSecOpsToolRegistry() *SecOpsToolRegistry {
	return &SecOpsToolRegistry{
		tools: make(map[string]SecOpsTool),
	}
}

// Register 注册工具
func (tr *SecOpsToolRegistry) Register(tool SecOpsTool) error {
	if tool.Type() == "" {
		return ErrEmptyToolType
	}
	tr.tools[string(tool.Type())] = tool
	return nil
}

// Get 获取工具
func (tr *SecOpsToolRegistry) Get(toolType ToolType) (SecOpsTool, bool) {
	tool, exists := tr.tools[string(toolType)]
	return tool, exists
}

// GetAll 获取所有工具
func (tr *SecOpsToolRegistry) GetAll() map[string]SecOpsTool {
	return tr.tools
}

// List 列出所有工具
func (tr *SecOpsToolRegistry) List() []SecOpsTool {
	tools := make([]SecOpsTool, 0, len(tr.tools))
	for _, tool := range tr.tools {
		tools = append(tools, tool)
	}
	return tools
}

// Backward-compatible var alias for callers using NewSecOpsToolRegistry
var NewToolRegistry = NewSecOpsToolRegistry
