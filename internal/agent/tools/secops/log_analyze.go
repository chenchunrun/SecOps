package secops

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LogSource 日志来源
type LogSource string

const (
	LogSourceSyslog      LogSource = "syslog"
	LogSourceSystemLog   LogSource = "system"
	LogSourceApplication LogSource = "application"
	LogSourceAudit       LogSource = "audit"
)

// LogLevel 日志级别
type LogLevel string

const (
	LogLevelEmergency LogLevel = "EMERGENCY"
	LogLevelAlert     LogLevel = "ALERT"
	LogLevelCritical  LogLevel = "CRITICAL"
	LogLevelError     LogLevel = "ERROR"
	LogLevelWarning   LogLevel = "WARNING"
	LogLevelNotice    LogLevel = "NOTICE"
	LogLevelInfo      LogLevel = "INFO"
	LogLevelDebug     LogLevel = "DEBUG"
)

// LogAnalyzeParams 日志分析参数
type LogAnalyzeParams struct {
	// 日志来源
	Source LogSource `json:"source"`

	// 搜索条件
	Pattern  string   `json:"pattern,omitempty"`   // 正则表达式
	Keyword  string   `json:"keyword,omitempty"`   // 关键词搜索
	Level    LogLevel `json:"level,omitempty"`     // 日志级别
	MinLevel LogLevel `json:"min_level,omitempty"` // 最小日志级别

	// 时间范围
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Duration  string    `json:"duration,omitempty"` // e.g., "1h", "24h"

	// 聚合选项
	AggregateBy string `json:"aggregate_by,omitempty"` // e.g., "host", "process", "user"
	GroupSize   int    `json:"group_size,omitempty"`   // 聚合大小

	// 其他选项
	Limit          int  `json:"limit,omitempty"`           // 返回最大条数
	Offset         int  `json:"offset,omitempty"`          // 偏移
	IncludeContext int  `json:"include_context,omitempty"` // 包含上下文行数
	CaseSensitive  bool `json:"case_sensitive,omitempty"`
}

// LogEntry 日志条目
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Host      string                 `json:"host,omitempty"`
	Process   string                 `json:"process,omitempty"`
	PID       int                    `json:"pid,omitempty"`
	User      string                 `json:"user,omitempty"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Source    LogSource              `json:"source"`
}

// LogAnalyzeResult 日志分析结果
type LogAnalyzeResult struct {
	TotalCount    int             `json:"total_count"`
	FilteredCount int             `json:"filtered_count"`
	Entries       []*LogEntry     `json:"entries"`
	Aggregated    *AggregatedData `json:"aggregated,omitempty"`
	TopPatterns   []*Pattern      `json:"top_patterns,omitempty"`
	Anomalies     []*Anomaly      `json:"anomalies,omitempty"`
}

// AggregatedData 聚合数据
type AggregatedData struct {
	By     string                 `json:"by"`
	Groups map[string]*GroupStats `json:"groups"`
}

// GroupStats 组统计
type GroupStats struct {
	Count     int            `json:"count"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Levels    map[string]int `json:"levels"`
}

// Pattern 日志模式
type Pattern struct {
	Pattern string  `json:"pattern"`
	Count   int     `json:"count"`
	Percent float64 `json:"percent"`
}

// Anomaly 异常
type Anomaly struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Score       float64   `json:"score"` // 0-1
	Timestamp   time.Time `json:"timestamp"`
	Entry       *LogEntry `json:"entry,omitempty"`
}

// LogAnalyzeTool 日志分析工具
type LogAnalyzeTool struct {
	registry *SecOpsToolRegistry
	readFile func(string) ([]byte, error)
	glob     func(string) ([]string, error)
	now      func() time.Time
}

// NewLogAnalyzeTool 创建日志分析工具
func NewLogAnalyzeTool(registry *SecOpsToolRegistry) *LogAnalyzeTool {
	return &LogAnalyzeTool{
		registry: registry,
		readFile: os.ReadFile,
		glob:     filepath.Glob,
		now:      time.Now,
	}
}

// Type 实现 Tool.Type
func (lat *LogAnalyzeTool) Type() ToolType {
	return ToolTypeLogAnalyze
}

// Name 实现 Tool.Name
func (lat *LogAnalyzeTool) Name() string {
	return "Log Analyzer"
}

// Description 实现 Tool.Description
func (lat *LogAnalyzeTool) Description() string {
	return "Analyze system and application logs with pattern matching, filtering, and aggregation"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (lat *LogAnalyzeTool) RequiredCapabilities() []string {
	return []string{
		"log:read",
		"log:analyze",
	}
}

// ValidateParams 实现 Tool.ValidateParams
func (lat *LogAnalyzeTool) ValidateParams(params interface{}) error {
	p, ok := params.(*LogAnalyzeParams)
	if !ok {
		return ErrInvalidParams
	}

	// 验证日志来源
	if p.Source == "" {
		return fmt.Errorf("source is required")
	}

	// 验证时间范围
	if !p.StartTime.IsZero() && !p.EndTime.IsZero() {
		if p.StartTime.After(p.EndTime) {
			return ErrInvalidDateRange
		}
	}

	// 验证正则表达式
	if p.Pattern != "" {
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	return nil
}

// Execute 实现 Tool.Execute
func (lat *LogAnalyzeTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*LogAnalyzeParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := lat.ValidateParams(p); err != nil {
		return nil, err
	}

	// 执行日志分析
	result, err := lat.analyzeLogs(p)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// 私有方法

// analyzeLogs 分析日志
func (lat *LogAnalyzeTool) analyzeLogs(params *LogAnalyzeParams) (*LogAnalyzeResult, error) {
	result := &LogAnalyzeResult{
		Entries:     make([]*LogEntry, 0),
		TopPatterns: make([]*Pattern, 0),
		Anomalies:   make([]*Anomaly, 0),
	}

	allEntries, err := lat.readLogs(params)
	if err != nil {
		return nil, err
	}

	// 过滤日志
	filtered := lat.filterLogs(allEntries, params)

	// 聚合
	if params.AggregateBy != "" {
		result.Aggregated = lat.aggregateLogs(filtered, params.AggregateBy)
	}

	// 检测异常
	result.Anomalies = lat.detectAnomalies(filtered)

	// 提取模式
	result.TopPatterns = lat.extractPatterns(filtered)

	result.TotalCount = len(allEntries)
	result.FilteredCount = len(filtered)
	result.Entries = filtered

	return result, nil
}

func (lat *LogAnalyzeTool) readLogs(params *LogAnalyzeParams) ([]*LogEntry, error) {
	patterns := sourcePatterns(params.Source)
	if override := strings.TrimSpace(sourcePatternsOverride(params.Source)); override != "" {
		patterns = splitCSV(override)
	}

	fileSet := make(map[string]struct{})
	for _, pattern := range patterns {
		matches, err := lat.glob(pattern)
		if err != nil {
			continue
		}
		for _, m := range matches {
			fileSet[m] = struct{}{}
		}
	}

	files := make([]string, 0, len(fileSet))
	for file := range fileSet {
		files = append(files, file)
	}
	sort.Strings(files)

	entries := make([]*LogEntry, 0)
	const maxEntries = 5000
	for _, file := range files {
		content, err := lat.readFile(file)
		if err != nil {
			continue
		}
		parsed := lat.parseLogLines(content, params.Source)
		entries = append(entries, parsed...)
		if len(entries) >= maxEntries {
			entries = entries[:maxEntries]
			break
		}
	}

	return entries, nil
}

func sourcePatterns(source LogSource) []string {
	switch source {
	case LogSourceSyslog:
		return []string{"/var/log/syslog*", "/var/log/messages*"}
	case LogSourceSystemLog:
		return []string{"/var/log/system.log*", "/var/log/system/*.log", "/var/log/*.log"}
	case LogSourceApplication:
		return []string{"/var/log/*/*.log", "/var/log/*.log"}
	case LogSourceAudit:
		return []string{"/var/log/audit/audit.log*", "/var/log/*audit*.log"}
	default:
		return []string{"/var/log/*.log"}
	}
}

func sourcePatternsOverride(source LogSource) string {
	switch source {
	case LogSourceSyslog:
		return os.Getenv("SECOPS_LOG_SYSLOG_PATHS")
	case LogSourceSystemLog:
		return os.Getenv("SECOPS_LOG_SYSTEM_PATHS")
	case LogSourceApplication:
		return os.Getenv("SECOPS_LOG_APPLICATION_PATHS")
	case LogSourceAudit:
		return os.Getenv("SECOPS_LOG_AUDIT_PATHS")
	default:
		return ""
	}
}

func splitCSV(in string) []string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (lat *LogAnalyzeTool) parseLogLines(content []byte, source LogSource) []*LogEntry {
	lines := bytes.Split(content, []byte("\n"))
	entries := make([]*LogEntry, 0, len(lines))
	re := regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^\[:]+)(?:\[(\d+)\])?:\s*(.*)$`)
	for _, line := range lines {
		raw := strings.TrimSpace(string(line))
		if raw == "" {
			continue
		}

		entry := &LogEntry{
			Timestamp: lat.now(),
			Level:     inferLevel(raw),
			Message:   raw,
			Source:    source,
		}

		match := re.FindStringSubmatch(raw)
		if len(match) == 6 {
			entry.Host = match[2]
			entry.Process = strings.TrimSpace(match[3])
			if match[5] != "" {
				entry.Message = match[5]
			}
			// best-effort parse without year; fallback to now.
			if ts, err := time.Parse("Jan 2 15:04:05", strings.Join(strings.Fields(match[1]), " ")); err == nil {
				now := lat.now()
				entry.Timestamp = time.Date(now.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, now.Location())
			}
		}

		entries = append(entries, entry)
	}
	return entries
}

func inferLevel(msg string) LogLevel {
	upper := strings.ToUpper(msg)
	switch {
	case strings.Contains(upper, "EMERGENCY"):
		return LogLevelEmergency
	case strings.Contains(upper, "ALERT"):
		return LogLevelAlert
	case strings.Contains(upper, "CRITICAL"):
		return LogLevelCritical
	case strings.Contains(upper, "ERROR"), strings.Contains(upper, "ERR "):
		return LogLevelError
	case strings.Contains(upper, "WARNING"), strings.Contains(upper, "WARN"):
		return LogLevelWarning
	case strings.Contains(upper, "NOTICE"):
		return LogLevelNotice
	case strings.Contains(upper, "DEBUG"):
		return LogLevelDebug
	default:
		return LogLevelInfo
	}
}

// filterLogs 过滤日志
func (lat *LogAnalyzeTool) filterLogs(entries []*LogEntry, params *LogAnalyzeParams) []*LogEntry {
	filtered := make([]*LogEntry, 0)

	// 预编译正则表达式（在循环外编译一次）
	var patternRe *regexp.Regexp
	if params.Pattern != "" {
		var err error
		patternRe, err = regexp.Compile(params.Pattern)
		if err != nil {
			return filtered
		}
	}

	startTime := params.StartTime
	endTime := params.EndTime
	if params.Duration != "" && startTime.IsZero() && endTime.IsZero() {
		if d, err := time.ParseDuration(params.Duration); err == nil {
			endTime = lat.now()
			startTime = endTime.Add(-d)
		}
	}

	minLevelRank := -1
	if params.MinLevel != "" {
		minLevelRank = logLevelRank(params.MinLevel)
	}

	for _, entry := range entries {
		// 时间范围过滤
		if !startTime.IsZero() && entry.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && entry.Timestamp.After(endTime) {
			continue
		}

		// 模式过滤（使用预编译的正则）
		if patternRe != nil {
			if !patternRe.MatchString(entry.Message) {
				continue
			}
		}

		// 关键词过滤
		if params.Keyword != "" {
			search := params.Keyword
			if !params.CaseSensitive {
				search = strings.ToLower(params.Keyword)
			}

			msg := entry.Message
			if !params.CaseSensitive {
				msg = strings.ToLower(msg)
			}

			if !strings.Contains(msg, search) {
				continue
			}
		}

		// 日志级别过滤
		if params.Level != "" && entry.Level != params.Level {
			continue
		}
		if minLevelRank >= 0 && logLevelRank(entry.Level) > minLevelRank {
			continue
		}

		filtered = append(filtered, entry)
	}

	if params.Offset > 0 {
		if params.Offset >= len(filtered) {
			return []*LogEntry{}
		}
		filtered = filtered[params.Offset:]
	}
	if params.Limit > 0 && params.Limit < len(filtered) {
		filtered = filtered[:params.Limit]
	}

	return filtered
}

func logLevelRank(level LogLevel) int {
	switch level {
	case LogLevelEmergency:
		return 0
	case LogLevelAlert:
		return 1
	case LogLevelCritical:
		return 2
	case LogLevelError:
		return 3
	case LogLevelWarning:
		return 4
	case LogLevelNotice:
		return 5
	case LogLevelInfo:
		return 6
	case LogLevelDebug:
		return 7
	default:
		return 7
	}
}

// aggregateLogs 聚合日志
func (lat *LogAnalyzeTool) aggregateLogs(entries []*LogEntry, by string) *AggregatedData {
	aggregated := &AggregatedData{
		By:     by,
		Groups: make(map[string]*GroupStats),
	}

	for _, entry := range entries {
		key := lat.getGroupKey(entry, by)
		if key == "" {
			continue
		}

		stats, exists := aggregated.Groups[key]
		if !exists {
			stats = &GroupStats{
				FirstSeen: entry.Timestamp,
				Levels:    make(map[string]int),
			}
			aggregated.Groups[key] = stats
		}

		stats.Count++
		stats.LastSeen = entry.Timestamp
		stats.Levels[string(entry.Level)]++
	}

	return aggregated
}

// getGroupKey 获取分组键
func (lat *LogAnalyzeTool) getGroupKey(entry *LogEntry, by string) string {
	switch by {
	case "host":
		return entry.Host
	case "process":
		return entry.Process
	case "level":
		return string(entry.Level)
	case "user":
		return entry.User
	default:
		return ""
	}
}

// detectAnomalies 检测异常
func (lat *LogAnalyzeTool) detectAnomalies(entries []*LogEntry) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	// 简单的异常检测：错误和紧急日志
	for _, entry := range entries {
		if entry.Level == LogLevelError || entry.Level == LogLevelCritical {
			anomalies = append(anomalies, &Anomaly{
				Type:        "error_detected",
				Description: fmt.Sprintf("Error: %s on %s", entry.Message, entry.Host),
				Score:       0.8,
				Timestamp:   entry.Timestamp,
				Entry:       entry,
			})
		}
	}

	return anomalies
}

// extractPatterns 提取模式
func (lat *LogAnalyzeTool) extractPatterns(entries []*LogEntry) []*Pattern {
	patterns := make([]*Pattern, 0)
	if len(entries) == 0 {
		return patterns
	}

	// 统计消息模式
	patternMap := make(map[string]int)
	for _, entry := range entries {
		patternMap[entry.Message]++
	}

	// 转换为排序列表
	for pattern, count := range patternMap {
		patterns = append(patterns, &Pattern{
			Pattern: pattern,
			Count:   count,
			Percent: float64(count) / float64(len(entries)) * 100,
		})
	}

	return patterns
}
