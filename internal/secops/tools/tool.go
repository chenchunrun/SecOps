package tools

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

// Tool 工具接口
type Tool interface {
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

// ToolRegistry 工具注册表
type ToolRegistry struct {
	tools map[string]Tool
}

// NewToolRegistry 创建工具注册表
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{
		tools: make(map[string]Tool),
	}
}

// Register 注册工具
func (tr *ToolRegistry) Register(tool Tool) error {
	if tool.Type() == "" {
		return ErrEmptyToolType
	}
	tr.tools[string(tool.Type())] = tool
	return nil
}

// Get 获取工具
func (tr *ToolRegistry) Get(toolType ToolType) (Tool, bool) {
	tool, exists := tr.tools[string(toolType)]
	return tool, exists
}

// GetAll 获取所有工具
func (tr *ToolRegistry) GetAll() map[string]Tool {
	return tr.tools
}

// List 列出所有工具
func (tr *ToolRegistry) List() []Tool {
	tools := make([]Tool, 0, len(tr.tools))
	for _, tool := range tr.tools {
		tools = append(tools, tool)
	}
	return tools
}
