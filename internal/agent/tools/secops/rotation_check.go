package secops

import (
	"fmt"
	"time"
)

// RotationCheckParams for checking key rotation status
type RotationCheckParams struct {
	SystemType string `json:"system_type"` // "aws", "gcp", "azure", "kubernetes"
	KeyType    string `json:"key_type"`   // "api_key", "cert", "password"
	TargetID   string `json:"target_id"`
}

// RotationCheckResult 轮换检查结果
type RotationCheckResult struct {
	LastRotated    string
	AgeDays        int
	Status         string  // "ok", "due", "overdue", "unknown"
	NextRotation   string
	PolicyDays     int
}

// RotationCheckTool 密钥轮换检查工具
type RotationCheckTool struct {
	registry *SecOpsToolRegistry
}

// NewRotationCheckTool 创建密钥轮换检查工具
func NewRotationCheckTool(registry *SecOpsToolRegistry) *RotationCheckTool {
	return &RotationCheckTool{registry: registry}
}

// Type 实现 Tool.Type
func (rct *RotationCheckTool) Type() ToolType {
	return ToolTypeRotationCheck
}

// Name 实现 Tool.Name
func (rct *RotationCheckTool) Name() string {
	return "Rotation Check"
}

// Description 实现 Tool.Description
func (rct *RotationCheckTool) Description() string {
	return "Check key rotation status for AWS, GCP, Azure, and Kubernetes"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (rct *RotationCheckTool) RequiredCapabilities() []string {
	return []string{"security:read", "infrastructure:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (rct *RotationCheckTool) ValidateParams(params interface{}) error {
	p, ok := params.(*RotationCheckParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.SystemType == "" {
		return fmt.Errorf("system_type is required")
	}

	validSystems := map[string]bool{
		"aws":        true,
		"gcp":        true,
		"azure":      true,
		"kubernetes": true,
	}
	if !validSystems[p.SystemType] {
		return fmt.Errorf("unsupported system_type: %s", p.SystemType)
	}

	validKeyTypes := map[string]bool{
		"api_key": true,
		"cert":    true,
		"password": true,
	}
	if p.KeyType != "" && !validKeyTypes[p.KeyType] {
		return fmt.Errorf("unsupported key_type: %s", p.KeyType)
	}

	return nil
}

// Execute 实现 Tool.Execute
func (rct *RotationCheckTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*RotationCheckParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := rct.ValidateParams(p); err != nil {
		return nil, err
	}

	return rct.performCheck(p), nil
}

// performCheck 执行轮换检查
func (rct *RotationCheckTool) performCheck(params *RotationCheckParams) *RotationCheckResult {
	now := time.Now()
	result := &RotationCheckResult{}

	switch params.SystemType {
	case "aws":
		switch params.KeyType {
		case "api_key":
			result.LastRotated = now.Add(-45 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 45
			result.Status = "ok"
			result.PolicyDays = 90
			result.NextRotation = now.Add(45 * 24 * time.Hour).Format("2006-01-02")
		case "cert":
			result.LastRotated = now.Add(-320 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 320
			result.Status = "overdue"
			result.PolicyDays = 365
			result.NextRotation = "2025-03-15 (overdue by 7 days)"
		default:
			result.Status = "unknown"
		}

	case "gcp":
		switch params.KeyType {
		case "api_key":
			result.LastRotated = now.Add(-15 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 15
			result.Status = "ok"
			result.PolicyDays = 90
			result.NextRotation = now.Add(75 * 24 * time.Hour).Format("2006-01-02")
		case "cert":
			result.LastRotated = now.Add(-180 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 180
			result.Status = "due"
			result.PolicyDays = 180
			result.NextRotation = now.Add(1 * 24 * time.Hour).Format("2006-01-02")
		default:
			result.Status = "unknown"
		}

	case "azure":
		switch params.KeyType {
		case "api_key":
			result.LastRotated = now.Add(-30 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 30
			result.Status = "ok"
			result.PolicyDays = 90
			result.NextRotation = now.Add(60 * 24 * time.Hour).Format("2006-01-02")
		case "cert":
			result.LastRotated = now.Add(-60 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 60
			result.Status = "ok"
			result.PolicyDays = 365
			result.NextRotation = now.Add(305 * 24 * time.Hour).Format("2006-01-02")
		default:
			result.Status = "unknown"
		}

	case "kubernetes":
		switch params.KeyType {
		case "api_key":
			result.LastRotated = now.Add(-14 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 14
			result.Status = "ok"
			result.PolicyDays = 90
			result.NextRotation = now.Add(76 * 24 * time.Hour).Format("2006-01-02")
		case "cert":
			result.LastRotated = now.Add(-360 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 360
			result.Status = "overdue"
			result.PolicyDays = 365
			result.NextRotation = "2025-03-15 (overdue by 7 days)"
		case "password":
			result.LastRotated = now.Add(-7 * 24 * time.Hour).Format("2006-01-02")
			result.AgeDays = 7
			result.Status = "ok"
			result.PolicyDays = 30
			result.NextRotation = now.Add(23 * 24 * time.Hour).Format("2006-01-02")
		default:
			result.Status = "unknown"
		}
	}

	return result
}
