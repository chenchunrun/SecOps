package secops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BackupCheckParams for checking backup status
type BackupCheckParams struct {
	SystemType string `json:"system_type"` // mysql, postgresql, k8s, files
	Target     string `json:"target"`      // host or cluster name
}

// BackupCheckResult 备份检查结果
type BackupCheckResult struct {
	LastBackupTime string
	Status         string // "ok", "stale", "missing"
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
	result := &BackupCheckResult{
		Status:     "missing",
		NextBackup: "unknown",
		Issues:     []string{},
	}

	latest, sizeGB, found := bct.findLatestBackup(params)
	if !found {
		result.LastBackupTime = "unknown"
		result.AgeHours = 0
		result.Issues = []string{"No backup artifacts found at configured path"}
		return result
	}

	ageHours := int(now.Sub(latest).Hours())
	result.LastBackupTime = latest.Format("2006-01-02 15:04:05")
	result.AgeHours = ageHours
	result.SizeGB = sizeGB
	result.NextBackup = latest.Add(24 * time.Hour).Format("2006-01-02 15:04:05")

	staleThreshold := 24
	if params.SystemType == "files" {
		staleThreshold = 48
	}

	if ageHours <= staleThreshold {
		result.Status = "ok"
		return result
	}

	result.Status = "stale"
	result.Issues = []string{
		fmt.Sprintf("Backup age %dh exceeds threshold %dh", ageHours, staleThreshold),
		"Investigate backup scheduler/retention policy",
	}
	return result
}

func (bct *BackupCheckTool) findLatestBackup(params *BackupCheckParams) (time.Time, float64, bool) {
	candidates := backupPathCandidates(params)
	latest := time.Time{}
	var latestSize int64
	found := false

	for _, p := range candidates {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		info, err := os.Stat(p)
		if err != nil {
			continue
		}

		if info.Mode().IsRegular() {
			if !isBackupFile(p) {
				continue
			}
			if !found || info.ModTime().After(latest) {
				found = true
				latest = info.ModTime()
				latestSize = info.Size()
			}
			continue
		}

		if !info.IsDir() {
			continue
		}

		_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !isBackupFile(path) {
				return nil
			}
			fi, statErr := d.Info()
			if statErr != nil {
				return nil
			}
			if !found || fi.ModTime().After(latest) {
				found = true
				latest = fi.ModTime()
				latestSize = fi.Size()
			}
			return nil
		})
	}

	if !found {
		return time.Time{}, 0, false
	}
	return latest, float64(latestSize) / (1024 * 1024 * 1024), true
}

func backupPathCandidates(params *BackupCheckParams) []string {
	candidates := make([]string, 0, 4)
	if strings.TrimSpace(params.Target) != "" {
		candidates = append(candidates, params.Target)
	}

	switch params.SystemType {
	case "mysql":
		candidates = append(candidates, os.Getenv("SECOPS_BACKUP_MYSQL_PATH"), "/var/backups/mysql")
	case "postgresql":
		candidates = append(candidates, os.Getenv("SECOPS_BACKUP_POSTGRES_PATH"), "/var/backups/postgresql")
	case "k8s":
		candidates = append(candidates, os.Getenv("SECOPS_BACKUP_K8S_PATH"), "/var/backups/k8s")
	case "files":
		candidates = append(candidates, os.Getenv("SECOPS_BACKUP_FILES_PATH"))
	}
	return candidates
}

func isBackupFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))
	if strings.Contains(base, "backup") || strings.Contains(base, "dump") || strings.Contains(base, "snapshot") {
		return true
	}
	switch ext {
	case ".sql", ".dump", ".bak", ".tar", ".gz", ".tgz", ".zip", ".snap":
		return true
	default:
		return false
	}
}
