package tools

import (
	"fmt"
	"regexp"
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
	Pattern    string    `json:"pattern,omitempty"`     // 正则表达式
	Keyword    string    `json:"keyword,omitempty"`     // 关键词搜索
	Level      LogLevel  `json:"level,omitempty"`       // 日志级别
	MinLevel   LogLevel  `json:"min_level,omitempty"`   // 最小日志级别

	// 时间范围
	StartTime  time.Time `json:"start_time,omitempty"`
	EndTime    time.Time `json:"end_time,omitempty"`
	Duration   string    `json:"duration,omitempty"`    // e.g., "1h", "24h"

	// 聚合选项
	AggregateBy string   `json:"aggregate_by,omitempty"` // e.g., "host", "process", "user"
	GroupSize   int      `json:"group_size,omitempty"`   // 聚合大小

	// 其他选项
	Limit         int    `json:"limit,omitempty"`        // 返回最大条数
	Offset        int    `json:"offset,omitempty"`       // 偏移
	IncludeContext int   `json:"include_context,omitempty"` // 包含上下文行数
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
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
	TotalCount   int              `json:"total_count"`
	FilteredCount int             `json:"filtered_count"`
	Entries      []*LogEntry      `json:"entries"`
	Aggregated   *AggregatedData  `json:"aggregated,omitempty"`
	TopPatterns  []*Pattern       `json:"top_patterns,omitempty"`
	Anomalies    []*Anomaly       `json:"anomalies,omitempty"`
}

// AggregatedData 聚合数据
type AggregatedData struct {
	By    string                 `json:"by"`
	Groups map[string]*GroupStats `json:"groups"`
}

// GroupStats 组统计
type GroupStats struct {
	Count       int       `json:"count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Levels      map[string]int `json:"levels"`
}

// Pattern 日志模式
type Pattern struct {
	Pattern string `json:"pattern"`
	Count   int    `json:"count"`
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
	registry *ToolRegistry
}

// NewLogAnalyzeTool 创建日志分析工具
func NewLogAnalyzeTool(registry *ToolRegistry) *LogAnalyzeTool {
	return &LogAnalyzeTool{
		registry: registry,
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
	result := lat.analyzeLogs(p)
	return result, nil
}

// 私有方法

// analyzeLogs 分析日志
func (lat *LogAnalyzeTool) analyzeLogs(params *LogAnalyzeParams) *LogAnalyzeResult {
	result := &LogAnalyzeResult{
		Entries: make([]*LogEntry, 0),
		TopPatterns: make([]*Pattern, 0),
		Anomalies: make([]*Anomaly, 0),
	}

	// TODO: 从日志源读取日志
	// 这是一个占位符实现

	// 模拟日志条目
	mockEntries := []*LogEntry{
		{
			Timestamp: time.Now().Add(-1 * time.Hour),
			Level:     LogLevelError,
			Host:      "server1",
			Process:   "nginx",
			PID:       12345,
			Message:   "Connection refused",
			Source:    LogSourceSystemLog,
		},
		{
			Timestamp: time.Now().Add(-2 * time.Hour),
			Level:     LogLevelWarning,
			Host:      "server2",
			Process:   "systemd",
			PID:       1,
			Message:   "Service restart detected",
			Source:    LogSourceSystemLog,
		},
	}

	// 过滤日志
	filtered := lat.filterLogs(mockEntries, params)

	// 聚合
	if params.AggregateBy != "" {
		result.Aggregated = lat.aggregateLogs(filtered, params.AggregateBy)
	}

	// 检测异常
	result.Anomalies = lat.detectAnomalies(filtered)

	// 提取模式
	result.TopPatterns = lat.extractPatterns(filtered)

	result.TotalCount = len(mockEntries)
	result.FilteredCount = len(filtered)
	result.Entries = filtered

	return result
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

	for _, entry := range entries {
		// 时间范围过滤
		if !params.StartTime.IsZero() && entry.Timestamp.Before(params.StartTime) {
			continue
		}
		if !params.EndTime.IsZero() && entry.Timestamp.After(params.EndTime) {
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

		filtered = append(filtered, entry)
	}

	return filtered
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
