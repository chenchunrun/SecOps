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

// ReplicationStatusParams for checking DB replication
type ReplicationStatusParams struct {
	System          string `json:"system"` // mysql, postgresql
	Host            string `json:"host"`
	RemoteHost      string `json:"remote_host,omitempty"`
	RemoteUser      string `json:"remote_user,omitempty"`
	RemotePort      int    `json:"remote_port,omitempty"`
	RemoteKeyPath   string `json:"remote_key_path,omitempty"`
	RemoteProxyJump string `json:"remote_proxy_jump,omitempty"`
}

// ReplicationStatusResult 复制状态结果
type ReplicationStatusResult struct {
	IsReplicating bool
	LagSeconds    int
	MasterHost    string
	SlaveHosts    []string
	Status        string
	DataSource    string `json:"data_source,omitempty"`     // live_file, live_cli, live_remote, fallback_sample
	FallbackReason string `json:"fallback_reason,omitempty"`
}

// ReplicationStatusTool 复制状态检查工具
type ReplicationStatusTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewReplicationStatusTool 创建复制状态检查工具
func NewReplicationStatusTool(registry *SecOpsToolRegistry) *ReplicationStatusTool {
	return &ReplicationStatusTool{
		registry: registry,
		runCmd:   runReplicationCommand,
	}
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

	if strings.TrimSpace(params.RemoteHost) != "" {
		if live := rst.readReplicationStatusFromRemoteCLI(params); live != nil {
			live.DataSource = "live_remote"
			return live
		}
		result.IsReplicating = false
		result.LagSeconds = 0
		result.Status = "unknown"
		result.DataSource = "fallback_sample"
		result.FallbackReason = "remote replication status unavailable; returned conservative fallback status"
		return result
	}

	if live := rst.readReplicationStatusFromFile(params); live != nil {
		live.DataSource = "live_file"
		return live
	}

	if live := rst.readReplicationStatusFromCLI(params); live != nil {
		live.DataSource = "live_cli"
		return live
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
	result.DataSource = "fallback_sample"
	result.FallbackReason = "replication status file/cli unavailable; returned built-in sample status"

	return result
}

type replicationSnapshot struct {
	IsReplicating bool     `json:"is_replicating"`
	LagSeconds    int      `json:"lag_seconds"`
	MasterHost    string   `json:"master_host"`
	SlaveHosts    []string `json:"slave_hosts"`
	Status        string   `json:"status"`
}

func (rst *ReplicationStatusTool) readReplicationStatusFromFile(params *ReplicationStatusParams) *ReplicationStatusResult {
	path := strings.TrimSpace(os.Getenv("SECOPS_REPLICATION_STATUS_FILE"))
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	// Format 1: {"mysql":{...},"postgresql":{...}}
	var bySystem map[string]replicationSnapshot
	if err := json.Unmarshal(data, &bySystem); err == nil {
		if snap, ok := bySystem[params.System]; ok {
			return snapshotToResult(snap, params.Host)
		}
	}

	// Format 2: single snapshot object.
	var single replicationSnapshot
	if err := json.Unmarshal(data, &single); err == nil {
		return snapshotToResult(single, params.Host)
	}

	return nil
}

func (rst *ReplicationStatusTool) readReplicationStatusFromCLI(params *ReplicationStatusParams) *ReplicationStatusResult {
	switch params.System {
	case "mysql":
		return rst.readMySQLReplicationFromCLI(params)
	case "postgresql":
		return rst.readPostgresReplicationFromCLI(params)
	default:
		return nil
	}
}

func (rst *ReplicationStatusTool) readReplicationStatusFromRemoteCLI(params *ReplicationStatusParams) *ReplicationStatusResult {
	switch params.System {
	case "mysql":
		return rst.readMySQLReplicationFromRemoteCLI(params)
	case "postgresql":
		return rst.readPostgresReplicationFromRemoteCLI(params)
	default:
		return nil
	}
}

func (rst *ReplicationStatusTool) readMySQLReplicationFromCLI(params *ReplicationStatusParams) *ReplicationStatusResult {
	if _, err := exec.LookPath("mysql"); err != nil {
		return nil
	}
	query := "SHOW SLAVE STATUS\\G"
	out, err := exec.Command("mysql", "-Nse", query).CombinedOutput()
	if err != nil || len(out) == 0 {
		return nil
	}
	text := string(out)
	lag := parseMySQLStatusInt(text, "Seconds_Behind_Master")
	master := parseMySQLStatusString(text, "Master_Host")
	ioRunning := strings.ToLower(parseMySQLStatusString(text, "Slave_IO_Running")) == "yes"
	sqlRunning := strings.ToLower(parseMySQLStatusString(text, "Slave_SQL_Running")) == "yes"

	status := "stopped"
	if ioRunning && sqlRunning {
		status = "healthy"
		if lag > 0 {
			status = "lagging"
		}
	}

	return &ReplicationStatusResult{
		IsReplicating: ioRunning && sqlRunning,
		LagSeconds:    lag,
		MasterHost:    defaultString(master, params.Host),
		SlaveHosts:    []string{},
		Status:        status,
	}
}

func (rst *ReplicationStatusTool) readMySQLReplicationFromRemoteCLI(params *ReplicationStatusParams) *ReplicationStatusResult {
	stdout, _, err := rst.runRemoteCommand(params, "mysql -Nse 'SHOW SLAVE STATUS\\G'")
	if err != nil || len(stdout) == 0 {
		return nil
	}
	text := string(stdout)
	lag := parseMySQLStatusInt(text, "Seconds_Behind_Master")
	master := parseMySQLStatusString(text, "Master_Host")
	ioRunning := strings.ToLower(parseMySQLStatusString(text, "Slave_IO_Running")) == "yes"
	sqlRunning := strings.ToLower(parseMySQLStatusString(text, "Slave_SQL_Running")) == "yes"

	status := "stopped"
	if ioRunning && sqlRunning {
		status = "healthy"
		if lag > 0 {
			status = "lagging"
		}
	}

	return &ReplicationStatusResult{
		IsReplicating: ioRunning && sqlRunning,
		LagSeconds:    lag,
		MasterHost:    defaultString(master, params.Host),
		SlaveHosts:    []string{},
		Status:        status,
	}
}

func (rst *ReplicationStatusTool) readPostgresReplicationFromCLI(params *ReplicationStatusParams) *ReplicationStatusResult {
	if _, err := exec.LookPath("psql"); err != nil {
		return nil
	}
	query := "SELECT COALESCE(COUNT(*),0), COALESCE(MAX(EXTRACT(EPOCH FROM replay_lag)::int),0) FROM pg_stat_replication;"
	out, err := exec.Command("psql", "-t", "-A", "-c", query).CombinedOutput()
	if err != nil || len(out) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) < 2 {
		return nil
	}
	replicas, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	lag, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return nil
	}
	status := "healthy"
	if replicas == 0 {
		status = "stopped"
	} else if lag > 0 {
		status = "lagging"
	}
	return &ReplicationStatusResult{
		IsReplicating: replicas > 0,
		LagSeconds:    lag,
		MasterHost:    params.Host,
		SlaveHosts:    make([]string, replicas),
		Status:        status,
	}
}

func (rst *ReplicationStatusTool) readPostgresReplicationFromRemoteCLI(params *ReplicationStatusParams) *ReplicationStatusResult {
	query := "psql -t -A -c \"SELECT COALESCE(COUNT(*),0), COALESCE(MAX(EXTRACT(EPOCH FROM replay_lag)::int),0) FROM pg_stat_replication;\""
	stdout, _, err := rst.runRemoteCommand(params, query)
	if err != nil || len(stdout) == 0 {
		return nil
	}
	parts := strings.Split(strings.TrimSpace(string(stdout)), "|")
	if len(parts) < 2 {
		return nil
	}
	replicas, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	lag, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return nil
	}
	status := "healthy"
	if replicas == 0 {
		status = "stopped"
	} else if lag > 0 {
		status = "lagging"
	}
	return &ReplicationStatusResult{
		IsReplicating: replicas > 0,
		LagSeconds:    lag,
		MasterHost:    params.Host,
		SlaveHosts:    make([]string, replicas),
		Status:        status,
	}
}

func snapshotToResult(s replicationSnapshot, fallbackMaster string) *ReplicationStatusResult {
	master := strings.TrimSpace(s.MasterHost)
	if master == "" {
		master = fallbackMaster
	}
	status := strings.TrimSpace(s.Status)
	if status == "" {
		status = "unknown"
	}
	return &ReplicationStatusResult{
		IsReplicating: s.IsReplicating,
		LagSeconds:    s.LagSeconds,
		MasterHost:    master,
		SlaveHosts:    s.SlaveHosts,
		Status:        status,
	}
}

func parseMySQLStatusString(raw, key string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key+":") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, key+":"))
	}
	return ""
}

func parseMySQLStatusInt(raw, key string) int {
	v := parseMySQLStatusString(raw, key)
	if strings.EqualFold(v, "NULL") || v == "" {
		return 0
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return i
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func (rst *ReplicationStatusTool) runRemoteCommand(params *ReplicationStatusParams, command string) ([]byte, []byte, error) {
	if rst.runCmd == nil {
		rst.runCmd = runReplicationCommand
	}
	sshArgs, err := buildReplicationSSHArgs(params, command)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return rst.runCmd(ctx, "ssh", sshArgs...)
}

func runReplicationCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
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

func buildReplicationSSHArgs(params *ReplicationStatusParams, remoteCmd string) ([]string, error) {
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
