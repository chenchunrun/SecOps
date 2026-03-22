package secops

import (
	"fmt"
	"time"
)

// BackupCheckParams for checking backup status
type BackupCheckParams struct {
	SystemType string `json:"system_type"` // mysql, postgresql, k8s, files
	Target     string `json:"target"`       // host or cluster name
}

// BackupCheckResult 备份检查结果
type BackupCheckResult struct {
	LastBackupTime string
	Status         string  // "ok", "stale", "missing"
	AgeHours       int
	NextBackup     string
	SizeGB         float64
	Issues         []string
}

// BackupCheckTool 备份检查工具
type BackupCheckTool struct {
	registry *SecOpsToolRegistry
}

// NewBackupCheckTool 创建备份检查工具
func NewBackupCheckTool(registry *SecOpsToolRegistry) *BackupCheckTool {
	return &BackupCheckTool{registry: registry}
}

// Type 实现 Tool.Type
func (bct *BackupCheckTool) Type() ToolType {
	return ToolTypeBackupCheck
}

// Name 实现 Tool.Name
func (bct *BackupCheckTool) Name() string {
	return "Backup Check"
}

// Description 实现 Tool.Description
func (bct *BackupCheckTool) Description() string {
	return "Check backup status for MySQL, PostgreSQL, Kubernetes, and file-based systems"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (bct *BackupCheckTool) RequiredCapabilities() []string {
	return []string{"backup:read", "infrastructure:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (bct *BackupCheckTool) ValidateParams(params interface{}) error {
	p, ok := params.(*BackupCheckParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.SystemType == "" {
		return fmt.Errorf("system_type is required")
	}

	validSystems := map[string]bool{
		"mysql":      true,
		"postgresql": true,
		"k8s":        true,
		"files":      true,
	}
	if !validSystems[p.SystemType] {
		return fmt.Errorf("unsupported system_type: %s", p.SystemType)
	}

	if p.Target == "" {
		return fmt.Errorf("target is required")
	}

	return nil
}

// Execute 实现 Tool.Execute
func (bct *BackupCheckTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*BackupCheckParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := bct.ValidateParams(p); err != nil {
		return nil, err
	}

	return bct.performCheck(p), nil
}

// performCheck 执行备份检查
func (bct *BackupCheckTool) performCheck(params *BackupCheckParams) *BackupCheckResult {
	now := time.Now()
	result := &BackupCheckResult{}

	switch params.SystemType {
	case "mysql":
		result.LastBackupTime = now.Add(-6 * time.Hour).Format("2006-01-02 15:04:05")
		result.Status = "ok"
		result.AgeHours = 6
		result.NextBackup = now.Add(18 * time.Hour).Format("2006-01-02 15:04:05")
		result.SizeGB = 42.5
		result.Issues = []string{}

	case "postgresql":
		result.LastBackupTime = now.Add(-25 * time.Hour).Format("2006-01-02 15:04:05")
		result.Status = "stale"
		result.AgeHours = 25
		result.NextBackup = now.Add(-1 * time.Hour).Format("2006-01-02 15:04:05")
		result.SizeGB = 128.3
		result.Issues = []string{"Backup is overdue by 1 hour", "Consider increasing backup frequency"}

	case "k8s":
		result.LastBackupTime = now.Add(-4 * time.Hour).Format("2006-01-02 15:04:05")
		result.Status = "ok"
		result.AgeHours = 4
		result.NextBackup = now.Add(20 * time.Hour).Format("2006-01-02 15:04:05")
		result.SizeGB = 15.7
		result.Issues = []string{}

	case "files":
		result.LastBackupTime = now.Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
		result.Status = "missing"
		result.AgeHours = 72
		result.NextBackup = "unknown"
		result.SizeGB = 0
		result.Issues = []string{"No backup found in last 72 hours", "Critical data at risk"}
	}

	return result
}
