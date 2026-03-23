package secops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RotationCheckParams for checking key rotation status
type RotationCheckParams struct {
	SystemType      string `json:"system_type"` // "aws", "gcp", "azure", "kubernetes"
	KeyType         string `json:"key_type"`    // "api_key", "cert", "password"
	TargetID        string `json:"target_id"`
	RemoteHost      string `json:"remote_host,omitempty"`
	RemoteUser      string `json:"remote_user,omitempty"`
	RemotePort      int    `json:"remote_port,omitempty"`
	RemoteKeyPath   string `json:"remote_key_path,omitempty"`
	RemoteProxyJump string `json:"remote_proxy_jump,omitempty"`
}

// RotationCheckResult 轮换检查结果
type RotationCheckResult struct {
	LastRotated  string
	AgeDays      int
	Status       string // "ok", "due", "overdue", "unknown"
	NextRotation string
	PolicyDays   int
	DataSource   string `json:"data_source,omitempty"`   // metadata, target_file, fallback_sample
	FallbackReason string `json:"fallback_reason,omitempty"`
}

// RotationCheckTool 密钥轮换检查工具
type RotationCheckTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewRotationCheckTool 创建密钥轮换检查工具
func NewRotationCheckTool(registry *SecOpsToolRegistry) *RotationCheckTool {
	return &RotationCheckTool{
		registry: registry,
		runCmd:   runRotationCommand,
	}
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
		"api_key":  true,
		"cert":     true,
		"password": true,
	}
	if p.KeyType != "" && !validKeyTypes[p.KeyType] {
		return fmt.Errorf("unsupported key_type: %s", p.KeyType)
	}
	if err := validateRemoteSSHParams(p.RemoteHost, p.RemoteUser, p.RemoteKeyPath, p.RemoteProxyJump, p.RemotePort); err != nil {
		return err
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
	if result := rct.rotationFromMetadata(params); result != nil {
		result.DataSource = "metadata"
		return result
	}
	if result := rct.rotationFromTarget(params); result != nil {
		result.DataSource = "target_file"
		return result
	}

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
	result.DataSource = "fallback_sample"
	result.FallbackReason = "rotation metadata/target file unavailable; returned built-in baseline policy estimate"

	return result
}

type rotationMetadataRecord struct {
	SystemType  string `json:"system_type"`
	KeyType     string `json:"key_type"`
	TargetID    string `json:"target_id"`
	LastRotated string `json:"last_rotated"`
	PolicyDays  int    `json:"policy_days"`
}

func (rct *RotationCheckTool) rotationFromMetadata(params *RotationCheckParams) *RotationCheckResult {
	path := strings.TrimSpace(os.Getenv("SECOPS_ROTATION_METADATA_FILE"))
	if path == "" {
		return nil
	}
	var data []byte
	if strings.TrimSpace(params.RemoteHost) != "" {
		remoteCmd := "cat " + shellQuoteRotation(path)
		out, _, err := rct.runRemoteCommand(params, remoteCmd)
		if err != nil || len(out) == 0 {
			return nil
		}
		data = out
	} else {
		out, err := os.ReadFile(path)
		if err != nil || len(out) == 0 {
			return nil
		}
		data = out
	}

	if rec := findRotationRecordFromArray(data, params); rec != nil {
		return materializeRotationRecord(*rec)
	}
	if rec := findRotationRecordFromMap(data, params); rec != nil {
		return materializeRotationRecord(*rec)
	}
	return nil
}

func (rct *RotationCheckTool) rotationFromTarget(params *RotationCheckParams) *RotationCheckResult {
	target := strings.TrimSpace(params.TargetID)
	if target == "" {
		return nil
	}
	var last time.Time
	if strings.TrimSpace(params.RemoteHost) != "" {
		remoteCmd := "if [ -f " + shellQuoteRotation(target) + " ]; then " +
			"stat -c %Y " + shellQuoteRotation(target) + " 2>/dev/null || " +
			"stat -f %m " + shellQuoteRotation(target) + "; fi"
		out, _, err := rct.runRemoteCommand(params, remoteCmd)
		if err != nil || len(strings.TrimSpace(string(out))) == 0 {
			return nil
		}
		sec, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return nil
		}
		last = time.Unix(sec, 0)
	} else {
		info, err := os.Stat(target)
		if err != nil || info.IsDir() {
			return nil
		}
		last = info.ModTime()
	}

	policy := defaultPolicyDays(params.SystemType, params.KeyType)
	age := int(time.Since(last).Hours() / 24)
	next := last.Add(time.Duration(policy) * 24 * time.Hour)

	return &RotationCheckResult{
		LastRotated:  last.Format("2006-01-02"),
		AgeDays:      age,
		Status:       statusByAge(age, policy),
		NextRotation: next.Format("2006-01-02"),
		PolicyDays:   policy,
	}
}

func findRotationRecordFromArray(data []byte, params *RotationCheckParams) *rotationMetadataRecord {
	var records []rotationMetadataRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil
	}
	for _, r := range records {
		if strings.EqualFold(strings.TrimSpace(r.SystemType), strings.TrimSpace(params.SystemType)) &&
			strings.EqualFold(strings.TrimSpace(r.KeyType), strings.TrimSpace(params.KeyType)) &&
			strings.TrimSpace(r.TargetID) == strings.TrimSpace(params.TargetID) {
			return &r
		}
	}
	return nil
}

func findRotationRecordFromMap(data []byte, params *RotationCheckParams) *rotationMetadataRecord {
	var records map[string]rotationMetadataRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil
	}
	if rec, ok := records[strings.TrimSpace(params.TargetID)]; ok {
		if strings.EqualFold(strings.TrimSpace(rec.SystemType), strings.TrimSpace(params.SystemType)) &&
			strings.EqualFold(strings.TrimSpace(rec.KeyType), strings.TrimSpace(params.KeyType)) {
			return &rec
		}
	}
	return nil
}

func materializeRotationRecord(rec rotationMetadataRecord) *RotationCheckResult {
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(rec.LastRotated))
	if err != nil {
		// Backward-compatible date only format.
		last, err = time.Parse("2006-01-02", strings.TrimSpace(rec.LastRotated))
		if err != nil {
			return nil
		}
	}

	policy := rec.PolicyDays
	if policy <= 0 {
		policy = 90
	}
	age := int(time.Since(last).Hours() / 24)
	next := last.Add(time.Duration(policy) * 24 * time.Hour)

	return &RotationCheckResult{
		LastRotated:  last.Format("2006-01-02"),
		AgeDays:      age,
		Status:       statusByAge(age, policy),
		NextRotation: next.Format("2006-01-02"),
		PolicyDays:   policy,
	}
}

func defaultPolicyDays(systemType, keyType string) int {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "password":
		return 30
	case "cert":
		if strings.EqualFold(systemType, "gcp") {
			return 180
		}
		return 365
	default:
		return 90
	}
}

func statusByAge(ageDays, policyDays int) string {
	if policyDays <= 0 {
		return "unknown"
	}
	if ageDays > policyDays {
		return "overdue"
	}
	if float64(ageDays) >= 0.8*float64(policyDays) {
		return "due"
	}
	return "ok"
}

func (rct *RotationCheckTool) runRemoteCommand(params *RotationCheckParams, remoteCmd string) ([]byte, []byte, error) {
	if rct.runCmd == nil {
		rct.runCmd = runRotationCommand
	}
	sshArgs, err := buildRotationSSHArgs(params, remoteCmd)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return rct.runCmd(ctx, "ssh", sshArgs...)
}

func runRotationCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err == nil {
		return out, nil, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return out, ee.Stderr, err
	}
	return out, nil, err
}

func buildRotationSSHArgs(params *RotationCheckParams, remoteCmd string) ([]string, error) {
	if params == nil {
		return nil, fmt.Errorf("remote params are required")
	}
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return nil, fmt.Errorf("remote_host is required")
	}

	target := host
	user := strings.TrimSpace(params.RemoteUser)
	if user != "" {
		target = user + "@" + host
	}

	sshArgs := defaultSSHOptionArgs()
	if params.RemotePort > 0 {
		sshArgs = append(sshArgs, "-p", strconv.Itoa(params.RemotePort))
	}
	if key := strings.TrimSpace(params.RemoteKeyPath); key != "" {
		sshArgs = append(sshArgs, "-i", key)
	}
	if jump := strings.TrimSpace(params.RemoteProxyJump); jump != "" {
		sshArgs = append(sshArgs, "-J", jump)
	}
	sshArgs = append(sshArgs, target, "sh", "-lc", remoteCmd)
	return sshArgs, nil
}

func shellQuoteRotation(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}
