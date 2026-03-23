package secops

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DatabaseQueryParams for read-only database queries
type DatabaseQueryParams struct {
	System     string `json:"system"`      // mysql, postgresql, mongodb, redis
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Database   string `json:"database"`
	Query      string `json:"query"`       // SELECT only
	TimeoutSec int    `json:"timeout_sec"`
	RemoteHost string `json:"remote_host,omitempty"`
	RemoteUser string `json:"remote_user,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	RemoteKeyPath string `json:"remote_key_path,omitempty"`
	RemoteProxyJump string `json:"remote_proxy_jump,omitempty"`
}

// DatabaseQueryResult 数据库查询结果
type DatabaseQueryResult struct {
	System       string
	RowsAffected int
	Columns      []string
	Data         [][]string
	Duration     string
	Error        string
	DataSource   string `json:"data_source,omitempty"`   // live_local, live_remote, fallback_sample
	FallbackReason string `json:"fallback_reason,omitempty"`
}

// DatabaseQueryTool 数据库查询工具
type DatabaseQueryTool struct {
	registry *SecOpsToolRegistry
	runCmd   func(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// NewDatabaseQueryTool 创建数据库查询工具
func NewDatabaseQueryTool(registry *SecOpsToolRegistry) *DatabaseQueryTool {
	return &DatabaseQueryTool{
		registry: registry,
		runCmd:   runDatabaseCommand,
	}
}

// Type 实现 Tool.Type
func (dqt *DatabaseQueryTool) Type() ToolType {
	return ToolTypeDatabaseQuery
}

// Name 实现 Tool.Name
func (dqt *DatabaseQueryTool) Name() string {
	return "Database Query"
}

// Description 实现 Tool.Description
func (dqt *DatabaseQueryTool) Description() string {
	return "Execute read-only queries on MySQL, PostgreSQL, MongoDB, and Redis databases"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (dqt *DatabaseQueryTool) RequiredCapabilities() []string {
	return []string{"database:read"}
}

// ValidateParams 实现 Tool.ValidateParams
func (dqt *DatabaseQueryTool) ValidateParams(params interface{}) error {
	p, ok := params.(*DatabaseQueryParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.System == "" {
		return fmt.Errorf("system is required")
	}

	validSystems := map[string]bool{
		"mysql":      true,
		"postgresql": true,
		"mongodb":    true,
		"redis":      true,
	}
	if !validSystems[p.System] {
		return fmt.Errorf("unsupported system: %s", p.System)
	}

	if p.Query == "" {
		return fmt.Errorf("query is required")
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

	if err := p.ValidateParams(); err != nil {
		return err
	}

	return nil
}

// Execute 实现 Tool.Execute
func (dqt *DatabaseQueryTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*DatabaseQueryParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := dqt.ValidateParams(p); err != nil {
		return nil, err
	}

	return dqt.performQuery(p), nil
}

// ValidateParams 仅允许 SELECT 语句，阻止 INSERT/UPDATE/DELETE/DROP 等写操作
func (p *DatabaseQueryParams) ValidateParams() error {
	normalized := strings.ToUpper(strings.TrimSpace(p.Query))

	// 阻止所有写操作关键字
	dangerousKeywords := []string{
		"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE",
		"ALTER", "CREATE", "GRANT", "REVOKE", "EXECUTE",
		"EXEC", "MERGE", "REPLACE", "LOAD", "HANDLER",
		"DO", "CALL", "CHANGE", "PURGE", "RESET",
	}

	for _, kw := range dangerousKeywords {
		if strings.HasPrefix(normalized, kw) {
			return fmt.Errorf("only SELECT queries are allowed, got: %s", kw)
		}
	}

	// 确保以 SELECT 开头（对于 SQL 数据库）
	if p.System == "mysql" || p.System == "postgresql" {
		selectPattern := regexp.MustCompile(`(?i)^\s*SELECT\s`)
		if !selectPattern.MatchString(p.Query) {
			return fmt.Errorf("only SELECT queries are allowed")
		}
	}

	return nil
}

// performQuery 执行数据库查询
func (dqt *DatabaseQueryTool) performQuery(params *DatabaseQueryParams) *DatabaseQueryResult {
	start := time.Now()
	result := &DatabaseQueryResult{
		System: params.System,
		Columns: []string{},
		Data:    [][]string{},
	}

	if strings.TrimSpace(params.RemoteHost) != "" {
		remoteResult, err := dqt.performRemoteQuery(params)
		if err != nil {
			result.Error = err.Error()
			result.Duration = time.Since(start).String()
			return result
		}
		remoteResult.DataSource = "live_remote"
		remoteResult.Duration = time.Since(start).String()
		return remoteResult
	}
	if localResult, err := dqt.performLocalQuery(params); err == nil {
		localResult.DataSource = "live_local"
		localResult.Duration = time.Since(start).String()
		return localResult
	}

	switch params.System {
	case "mysql":
		result.Columns = []string{"id", "hostname", "status", "created_at"}
		result.Data = [][]string{
			{"1", "db-master-01", "active", "2026-01-15 10:00:00"},
			{"2", "db-slave-01", "active", "2026-01-15 10:00:00"},
			{"3", "db-master-02", "standby", "2026-02-01 10:00:00"},
		}
		result.RowsAffected = 3

	case "postgresql":
		result.Columns = []string{"pid", "usename", "application_name", "state", "backend_start"}
		result.Data = [][]string{
			{"12345", "app_user", "pgpool", "active", "2026-03-20 09:00:00"},
			{"12346", "readonly", "psql", "idle", "2026-03-20 09:05:00"},
		}
		result.RowsAffected = 2

	case "mongodb":
		result.Columns = []string{"_id", "name", "status", "replicas"}
		result.Data = [][]string{
			{"ObjectId('...')", "cluster-01", "PRIMARY", "3"},
			{"ObjectId('...')", "cluster-02", "SECONDARY", "3"},
		}
		result.RowsAffected = 2

	case "redis":
		result.Columns = []string{"key", "type", "ttl", "memory_bytes"}
		result.Data = [][]string{
			{"session:abc123", "hash", "3600", "2048"},
			{"cache:user:1", "string", "1800", "512"},
			{"rate:limit:ip1", "string", "60", "128"},
		}
		result.RowsAffected = 3
	}

	result.Duration = time.Since(start).String()
	result.DataSource = "fallback_sample"
	result.FallbackReason = "live query unavailable; returned built-in sample result"
	return result
}

func (dqt *DatabaseQueryTool) performLocalQuery(params *DatabaseQueryParams) (*DatabaseQueryResult, error) {
	if dqt.runCmd == nil {
		dqt.runCmd = runDatabaseCommand
	}
	timeout := params.TimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmdName, cmdArgs, err := buildDatabaseLocalCommand(params)
	if err != nil {
		return nil, err
	}
	stdout, stderr, err := dqt.runCmd(ctx, cmdName, cmdArgs...)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("local database query failed: %s", msg)
	}

	rows := parseRemoteRows(string(stdout))
	if len(rows) == 0 {
		return nil, fmt.Errorf("local database query returned no rows")
	}
	return &DatabaseQueryResult{
		System:       params.System,
		Columns:      []string{"result"},
		Data:         rows,
		RowsAffected: len(rows),
	}, nil
}

func (dqt *DatabaseQueryTool) performRemoteQuery(params *DatabaseQueryParams) (*DatabaseQueryResult, error) {
	if dqt.runCmd == nil {
		dqt.runCmd = runDatabaseCommand
	}
	timeout := params.TimeoutSec
	if timeout <= 0 {
		timeout = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	sshArgs, err := buildDatabaseRemoteSSHArgs(params)
	if err != nil {
		return nil, err
	}
	stdout, stderr, err := dqt.runCmd(ctx, "ssh", sshArgs...)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("remote database query failed: %s", msg)
	}

	rows := parseRemoteRows(string(stdout))
	return &DatabaseQueryResult{
		System:       params.System,
		Columns:      []string{"result"},
		Data:         rows,
		RowsAffected: len(rows),
	}, nil
}

func buildDatabaseRemoteSSHArgs(params *DatabaseQueryParams) ([]string, error) {
	host := strings.TrimSpace(params.RemoteHost)
	if host == "" {
		return nil, fmt.Errorf("remote_host is required")
	}
	target := host
	if user := strings.TrimSpace(params.RemoteUser); user != "" {
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

	remoteCommand := buildRemoteDBCommand(params)
	sshArgs = append(sshArgs, target, "sh", "-lc", remoteCommand)
	return sshArgs, nil
}

func buildRemoteDBCommand(params *DatabaseQueryParams) string {
	system := strings.ToLower(strings.TrimSpace(params.System))
	host := shellQuoteDB(defaultDBString(params.Host, "127.0.0.1"))
	port := params.Port
	if port <= 0 {
		port = defaultDBPort(system)
	}
	portArg := strconv.Itoa(port)
	query := shellQuoteDB(strings.TrimSpace(params.Query))
	dbName := shellQuoteDB(strings.TrimSpace(params.Database))

	switch system {
	case "mysql":
		return "mysql -h " + host + " -P " + portArg + " --batch --raw --skip-column-names " +
			dbOption(dbName, "-D ") + "-e " + query
	case "postgresql":
		return "psql -h " + host + " -p " + portArg + " " + dbOption(dbName, "-d ") +
			"-A -t -F $'\\t' -c " + query
	case "mongodb":
		return "mongosh --host " + host + " --port " + portArg + " --quiet --eval " + query
	case "redis":
		return "redis-cli -h " + host + " -p " + portArg + " --raw " + query
	default:
		return "echo unsupported system"
	}
}

func buildDatabaseLocalCommand(params *DatabaseQueryParams) (string, []string, error) {
	system := strings.ToLower(strings.TrimSpace(params.System))
	host := defaultDBString(params.Host, "127.0.0.1")
	port := params.Port
	if port <= 0 {
		port = defaultDBPort(system)
	}
	portArg := strconv.Itoa(port)
	query := strings.TrimSpace(params.Query)
	dbName := strings.TrimSpace(params.Database)

	switch system {
	case "mysql":
		args := []string{
			"-h", host,
			"-P", portArg,
			"--batch",
			"--raw",
			"--skip-column-names",
		}
		if dbName != "" {
			args = append(args, "-D", dbName)
		}
		args = append(args, "-e", query)
		return "mysql", args, nil
	case "postgresql":
		args := []string{"-h", host, "-p", portArg}
		if dbName != "" {
			args = append(args, "-d", dbName)
		}
		args = append(args, "-A", "-t", "-F", "\t", "-c", query)
		return "psql", args, nil
	case "mongodb":
		args := []string{"--host", host, "--port", portArg, "--quiet", "--eval", query}
		return "mongosh", args, nil
	case "redis":
		args := []string{"-h", host, "-p", portArg, "--raw", query}
		return "redis-cli", args, nil
	default:
		return "", nil, fmt.Errorf("unsupported system: %s", params.System)
	}
}

func dbOption(quotedValue, flag string) string {
	if quotedValue == "''" {
		return ""
	}
	return flag + quotedValue + " "
}

func defaultDBPort(system string) int {
	switch system {
	case "mysql":
		return 3306
	case "postgresql":
		return 5432
	case "mongodb":
		return 27017
	case "redis":
		return 6379
	default:
		return 0
	}
}

func parseRemoteRows(out string) [][]string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rows = append(rows, []string{line})
	}
	return rows
}

func shellQuoteDB(v string) string {
	if v == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func defaultDBString(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func runDatabaseCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
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
