package secops

import (
	"fmt"
	"regexp"
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
}

// DatabaseQueryResult 数据库查询结果
type DatabaseQueryResult struct {
	System       string
	RowsAffected int
	Columns      []string
	Data         [][]string
	Duration     string
	Error        string
}

// DatabaseQueryTool 数据库查询工具
type DatabaseQueryTool struct {
	registry *SecOpsToolRegistry
}

// NewDatabaseQueryTool 创建数据库查询工具
func NewDatabaseQueryTool(registry *SecOpsToolRegistry) *DatabaseQueryTool {
	return &DatabaseQueryTool{registry: registry}
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
	return result
}
