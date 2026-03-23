package secops

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AccessReviewParams for auditing user/group access
type AccessReviewParams struct {
	SystemType      string `json:"system_type"` // "aws", "gcp", "linux", "database"
	ReviewType      string `json:"review_type"` // "users", "permissions", "service_accounts"
	Target          string `json:"target"`
	RemoteHost      string `json:"remote_host,omitempty"`
	RemoteUser      string `json:"remote_user,omitempty"`
	RemotePort      int    `json:"remote_port,omitempty"`
	RemoteKeyPath   string `json:"remote_key_path,omitempty"`
	RemoteProxyJump string `json:"remote_proxy_jump,omitempty"`
}

// AccessEntry 访问条目
type AccessEntry struct {
	Principal  string
	Permission string
	Resource   string
	AgeDays    int
	LastUsed   string
	Risk       string // "low", "medium", "high"
}

// AccessReviewResult 访问审计结果
type AccessReviewResult struct {
	Entries       []AccessEntry
	HighRiskCount int
	StaleCount    int
	TotalCount    int
	DataSource    string `json:"data_source,omitempty"`     // live, fallback_sample
	FallbackReason string `json:"fallback_reason,omitempty"`
}

// AccessReviewTool 访问审计工具
type AccessReviewTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewAccessReviewTool 创建访问审计工具
func NewAccessReviewTool(registry *SecOpsToolRegistry) *AccessReviewTool {
	return &AccessReviewTool{
		registry: registry,
		runCmd:   runAccessCommand,
	}
}

// Type 实现 Tool.Type
func (art *AccessReviewTool) Type() ToolType {
	return ToolTypeAccessReview
}

// Name 实现 Tool.Name
func (art *AccessReviewTool) Name() string {
	return "Access Review"
}

// Description 实现 Tool.Description
func (art *AccessReviewTool) Description() string {
	return "Audit user, group, and service account permissions across AWS, GCP, Linux, and databases"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (art *AccessReviewTool) RequiredCapabilities() []string {
	return []string{"iam:read", "security:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (art *AccessReviewTool) ValidateParams(params interface{}) error {
	p, ok := params.(*AccessReviewParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.SystemType == "" {
		return fmt.Errorf("system_type is required")
	}

	validSystems := map[string]bool{
		"aws":      true,
		"gcp":      true,
		"linux":    true,
		"database": true,
	}
	if !validSystems[p.SystemType] {
		return fmt.Errorf("unsupported system_type: %s", p.SystemType)
	}

	validReviewTypes := map[string]bool{
		"users":            true,
		"permissions":      true,
		"service_accounts": true,
	}
	if p.ReviewType != "" && !validReviewTypes[p.ReviewType] {
		return fmt.Errorf("unsupported review_type: %s", p.ReviewType)
	}
	if p.RemotePort < 0 || p.RemotePort > 65535 {
		return fmt.Errorf("remote_port must be between 1 and 65535")
	}
	if strings.TrimSpace(p.RemoteHost) == "" {
		if strings.TrimSpace(p.RemoteUser) != "" || p.RemotePort > 0 ||
			strings.TrimSpace(p.RemoteKeyPath) != "" || strings.TrimSpace(p.RemoteProxyJump) != "" {
			return fmt.Errorf("remote_host is required when remote ssh options are set")
		}
	}

	return nil
}

// Execute 实现 Tool.Execute
func (art *AccessReviewTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*AccessReviewParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := art.ValidateParams(p); err != nil {
		return nil, err
	}

	return art.performReview(p), nil
}

// performReview 执行访问审计
func (art *AccessReviewTool) performReview(params *AccessReviewParams) *AccessReviewResult {
	result := &AccessReviewResult{
		Entries: make([]AccessEntry, 0),
	}

	switch params.SystemType {
	case "aws":
		if entries := art.getAWSAccessEntries(params); len(entries) > 0 {
			result.Entries = entries
			result.DataSource = "live"
			break
		}
		result.DataSource = "fallback_sample"
		result.FallbackReason = "aws iam data unavailable; returned built-in sample entries"
		result.Entries = []AccessEntry{
			{
				Principal:  "user:admin@example.com",
				Permission: "iam:*",
				Resource:   "*",
				AgeDays:    180,
				LastUsed:   time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "user:devops@example.com",
				Permission: "ec2:RunInstances",
				Resource:   "arn:aws:ec2:*:*:instance/*",
				AgeDays:    90,
				LastUsed:   time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
			{
				Principal:  "role:prod-deployment",
				Permission: "eks:DescribeCluster",
				Resource:   "arn:aws:eks:*:*:cluster/prod-*",
				AgeDays:    30,
				LastUsed:   time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
			{
				Principal:  "user:former-employee@example.com",
				Permission: "s3:*",
				Resource:   "arn:aws:s3:::company-secrets/*",
				AgeDays:    365,
				LastUsed:   time.Now().Add(-60 * 24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "service:lambda-processor",
				Permission: "sqs:ReceiveMessage",
				Resource:   "arn:aws:sqs:*:*:task-queue",
				AgeDays:    7,
				LastUsed:   time.Now().Add(-30 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
		}

	case "gcp":
		if entries := art.getGCPAccessEntries(params); len(entries) > 0 {
			result.Entries = entries
			result.DataSource = "live"
			break
		}
		result.DataSource = "fallback_sample"
		result.FallbackReason = "gcp iam data unavailable; returned built-in sample entries"
		result.Entries = []AccessEntry{
			{
				Principal:  "user:admin@example.com",
				Permission: "roles/owner",
				Resource:   "projects/*",
				AgeDays:    180,
				LastUsed:   time.Now().Add(-3 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "serviceAccount:compute@project.iam.gserviceaccount.com",
				Permission: "roles/editor",
				Resource:   "projects/project-id",
				AgeDays:    60,
				LastUsed:   time.Now().Add(-1 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
		}

	case "linux":
		if entries := art.getLinuxAccessEntries(params); len(entries) > 0 {
			result.Entries = entries
			result.DataSource = "live"
			break
		}
		result.DataSource = "fallback_sample"
		result.FallbackReason = "linux account data unavailable; returned built-in sample entries"
		result.Entries = []AccessEntry{
			{
				Principal:  "user:root",
				Permission: "sudo ALL=(ALL) NOPASSWD: ALL",
				Resource:   "/etc/sudoers",
				AgeDays:    730,
				LastUsed:   time.Now().Add(-10 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
			{
				Principal:  "user:deploy",
				Permission: "sudo systemctl restart nginx",
				Resource:   "/etc/sudoers.d/deploy",
				AgeDays:    90,
				LastUsed:   time.Now().Add(-2 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
			{
				Principal:  "user:contractor-old",
				Permission: "sudo su -",
				Resource:   "/etc/sudoers.d/contractors",
				AgeDays:    400,
				LastUsed:   time.Now().Add(-120 * 24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
		}

	case "database":
		result.DataSource = "fallback_sample"
		result.FallbackReason = "database access review uses built-in sample entries when no provider is configured"
		result.Entries = []AccessEntry{
			{
				Principal:  "user:app_readonly",
				Permission: "SELECT",
				Resource:   "public.*",
				AgeDays:    30,
				LastUsed:   time.Now().Add(-1 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "low",
			},
			{
				Principal:  "user:app_writer",
				Permission: "SELECT, INSERT, UPDATE, DELETE",
				Resource:   "app_data.*",
				AgeDays:    60,
				LastUsed:   time.Now().Add(-5 * time.Minute).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
			{
				Principal:  "user:dba_admin",
				Permission: "ALL PRIVILEGES",
				Resource:   "*.*",
				AgeDays:    180,
				LastUsed:   time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "high",
			},
			{
				Principal:  "user:temp_user",
				Permission: "SELECT",
				Resource:   "analytics.*",
				AgeDays:    90,
				LastUsed:   time.Now().Add(-30 * 24 * time.Hour).Format("2006-01-02 15:04"),
				Risk:       "medium",
			},
		}
	}
	if result.DataSource == "" {
		result.DataSource = "live"
	}

	result.TotalCount = len(result.Entries)
	for _, e := range result.Entries {
		if e.Risk == "high" {
			result.HighRiskCount++
		}
		if e.AgeDays > 90 && e.LastUsed != "" {
			result.StaleCount++
		}
	}

	return result
}

func (art *AccessReviewTool) getAWSAccessEntries(params *AccessReviewParams) []AccessEntry {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil
	}
	out, err := exec.Command("aws", "iam", "list-users", "--output", "json").Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload struct {
		Users []struct {
			UserName         string `json:"UserName"`
			Arn              string `json:"Arn"`
			CreateDate       string `json:"CreateDate"`
			PasswordLastUsed string `json:"PasswordLastUsed"`
		} `json:"Users"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}
	entries := make([]AccessEntry, 0, len(payload.Users))
	for _, u := range payload.Users {
		age := 0
		if t, err := time.Parse(time.RFC3339, u.CreateDate); err == nil {
			age = int(time.Since(t).Hours() / 24)
		}
		last := strings.TrimSpace(u.PasswordLastUsed)
		if last == "" {
			last = time.Now().Add(-180 * 24 * time.Hour).Format("2006-01-02 15:04")
		}
		risk := "low"
		if age > 365 {
			risk = "high"
		} else if age > 120 {
			risk = "medium"
		}
		entries = append(entries, AccessEntry{
			Principal:  "user:" + u.UserName,
			Permission: "iam:user",
			Resource:   defaultIfEmpty(u.Arn, "*"),
			AgeDays:    age,
			LastUsed:   formatRFC3339OrNow(last),
			Risk:       risk,
		})
	}
	return entries
}

func (art *AccessReviewTool) getGCPAccessEntries(params *AccessReviewParams) []AccessEntry {
	if _, err := exec.LookPath("gcloud"); err != nil {
		return nil
	}
	project := strings.TrimSpace(params.Target)
	if project == "" {
		return nil
	}
	out, err := exec.Command("gcloud", "projects", "get-iam-policy", project, "--format=json").Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var payload struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return nil
	}
	entries := make([]AccessEntry, 0)
	for _, b := range payload.Bindings {
		for _, m := range b.Members {
			risk := "low"
			if strings.Contains(b.Role, "owner") || strings.Contains(b.Role, "admin") {
				risk = "high"
			} else if strings.Contains(b.Role, "editor") {
				risk = "medium"
			}
			entries = append(entries, AccessEntry{
				Principal:  m,
				Permission: b.Role,
				Resource:   "projects/" + project,
				AgeDays:    0,
				LastUsed:   time.Now().Format("2006-01-02 15:04"),
				Risk:       risk,
			})
		}
	}
	return entries
}

func (art *AccessReviewTool) getLinuxAccessEntries(params *AccessReviewParams) []AccessEntry {
	if strings.TrimSpace(params.RemoteHost) != "" {
		return art.getLinuxAccessEntriesRemote(params)
	}

	passwdPath := strings.TrimSpace(os.Getenv("SECOPS_LINUX_PASSWD_PATH"))
	if passwdPath == "" {
		passwdPath = "/etc/passwd"
	}
	data, err := os.ReadFile(passwdPath)
	if err != nil || len(data) == 0 {
		return nil
	}

	sudoersRules := readLinuxSudoers()
	lines := strings.Split(string(data), "\n")
	entries := make([]AccessEntry, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		user := fields[0]
		uid, _ := strconv.Atoi(fields[2])
		shell := fields[6]
		if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
			continue
		}

		perm := "shell:user"
		resource := passwdPath
		risk := "low"
		ageDays := 0

		if uid == 0 || user == "root" {
			perm = "sudo ALL=(ALL) NOPASSWD: ALL"
			risk = "high"
		} else if strings.Contains(sudoersRules, user) {
			perm = "sudo privilege"
			risk = "medium"
		}

		entries = append(entries, AccessEntry{
			Principal:  "user:" + user,
			Permission: perm,
			Resource:   resource,
			AgeDays:    ageDays,
			LastUsed:   time.Now().Format("2006-01-02 15:04"),
			Risk:       risk,
		})
	}

	return entries
}

func (art *AccessReviewTool) getLinuxAccessEntriesRemote(params *AccessReviewParams) []AccessEntry {
	passwdRaw, err := art.runRemoteCommand(params, "cat /etc/passwd 2>/dev/null")
	if err != nil || strings.TrimSpace(passwdRaw) == "" {
		return nil
	}
	sudoersRaw, _ := art.runRemoteCommand(params, "cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null")

	lines := strings.Split(passwdRaw, "\n")
	entries := make([]AccessEntry, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		user := fields[0]
		uid, _ := strconv.Atoi(fields[2])
		shell := fields[6]
		if strings.Contains(shell, "nologin") || strings.Contains(shell, "false") {
			continue
		}

		perm := "shell:user"
		resource := "ssh://" + formatAccessRemoteTarget(params.RemoteUser, params.RemoteHost) + "/etc/passwd"
		risk := "low"

		if uid == 0 || user == "root" {
			perm = "sudo ALL=(ALL) NOPASSWD: ALL"
			risk = "high"
		} else if strings.Contains(sudoersRaw, user) {
			perm = "sudo privilege"
			risk = "medium"
		}

		entries = append(entries, AccessEntry{
			Principal:  "user:" + user,
			Permission: perm,
			Resource:   resource,
			AgeDays:    0,
			LastUsed:   time.Now().Format("2006-01-02 15:04"),
			Risk:       risk,
		})
	}
	return entries
}

func readLinuxSudoers() string {
	paths := []string{"/etc/sudoers"}
	if override := strings.TrimSpace(os.Getenv("SECOPS_LINUX_SUDOERS_PATH")); override != "" {
		paths = append([]string{override}, paths...)
	}
	paths = append(paths, "/etc/sudoers.d")

	var sb strings.Builder
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			_ = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				b, readErr := os.ReadFile(path)
				if readErr == nil {
					sb.WriteString("\n")
					sb.Write(b)
				}
				return nil
			})
			continue
		}
		b, readErr := os.ReadFile(p)
		if readErr == nil {
			sb.WriteString("\n")
			sb.Write(b)
		}
	}
	return sb.String()
}

func formatRFC3339OrNow(v string) string {
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(v)); err == nil {
		return t.Format("2006-01-02 15:04")
	}
	return time.Now().Format("2006-01-02 15:04")
}

func (art *AccessReviewTool) runRemoteCommand(params *AccessReviewParams, command string) (string, error) {
	if art.runCmd == nil {
		art.runCmd = runAccessCommand
	}
	sshArgs, err := buildAccessSSHArgs(params, command)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	stdout, stderr, cmdErr := art.runCmd(ctx, "ssh", sshArgs...)
	if cmdErr != nil && len(strings.TrimSpace(string(stdout))) == 0 {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = cmdErr.Error()
		}
		return "", fmt.Errorf("remote command failed: %s", msg)
	}
	return string(stdout), nil
}

func runAccessCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
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

func buildAccessSSHArgs(params *AccessReviewParams, remoteCmd string) ([]string, error) {
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

	sshArgs := []string{"-o", "BatchMode=yes"}
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

func formatAccessRemoteTarget(user, host string) string {
	host = strings.TrimSpace(host)
	user = strings.TrimSpace(user)
	if user == "" {
		return host
	}
	return user + "@" + host
}
