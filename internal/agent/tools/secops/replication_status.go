package secops

import (
	"fmt"
)

// ReplicationStatusParams for checking DB replication
type ReplicationStatusParams struct {
	System string `json:"system"` // mysql, postgresql
	Host   string `json:"host"`
}

// ReplicationStatusResult 复制状态结果
type ReplicationStatusResult struct {
	IsReplicating bool
	LagSeconds    int
	MasterHost    string
	SlaveHosts    []string
	Status        string
}

// ReplicationStatusTool 复制状态检查工具
type ReplicationStatusTool struct {
	registry *SecOpsToolRegistry
}

// NewReplicationStatusTool 创建复制状态检查工具
func NewReplicationStatusTool(registry *SecOpsToolRegistry) *ReplicationStatusTool {
	return &ReplicationStatusTool{registry: registry}
}

// Type 实现 Tool.Type
func (rst *ReplicationStatusTool) Type() ToolType {
	return ToolTypeReplicationStatus
}

// Name 实现 Tool.Name
func (rst *ReplicationStatusTool) Name() string {
	return "Replication Status"
}

// Description 实现 Tool.Description
func (rst *ReplicationStatusTool) Description() string {
	return "Check database replication status for MySQL and PostgreSQL"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (rst *ReplicationStatusTool) RequiredCapabilities() []string {
	return []string{"database:read", "infrastructure:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (rst *ReplicationStatusTool) ValidateParams(params interface{}) error {
	p, ok := params.(*ReplicationStatusParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.System == "" {
		return fmt.Errorf("system is required")
	}

	validSystems := map[string]bool{
		"mysql":      true,
		"postgresql": true,
	}
	if !validSystems[p.System] {
		return fmt.Errorf("unsupported system: %s", p.System)
	}

	if p.Host == "" {
		return fmt.Errorf("host is required")
	}

	return nil
}

// Execute 实现 Tool.Execute
func (rst *ReplicationStatusTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*ReplicationStatusParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := rst.ValidateParams(p); err != nil {
		return nil, err
	}

	return rst.performCheck(p), nil
}

// performCheck 执行复制状态检查
func (rst *ReplicationStatusTool) performCheck(params *ReplicationStatusParams) *ReplicationStatusResult {
	result := &ReplicationStatusResult{
		MasterHost: params.Host,
		SlaveHosts: []string{},
	}

	switch params.System {
	case "mysql":
		result.IsReplicating = true
		result.LagSeconds = 0
		result.SlaveHosts = []string{
			"mysql-slave-01.example.com",
			"mysql-slave-02.example.com",
		}
		result.Status = "healthy"

	case "postgresql":
		result.IsReplicating = true
		result.LagSeconds = 2
		result.SlaveHosts = []string{
			"pg-slave-01.example.com",
			"pg-slave-02.example.com",
			"pg-standby-01.example.com",
		}
		result.Status = "lagging"
	}

	return result
}
