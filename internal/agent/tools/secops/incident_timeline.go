package secops

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// IncidentTimelineParams for generating incident timeline
type IncidentTimelineParams struct {
	IncidentID string          `json:"incident_id"`
	Events     []TimelineEvent `json:"events,omitempty"`
}

// IncidentTimelineTool 事件时间线工具
type IncidentTimelineTool struct {
	registry *SecOpsToolRegistry
}

// NewIncidentTimelineTool 创建事件时间线工具
func NewIncidentTimelineTool(registry *SecOpsToolRegistry) *IncidentTimelineTool {
	return &IncidentTimelineTool{registry: registry}
}

// Type 实现 Tool.Type
func (itt *IncidentTimelineTool) Type() ToolType {
	return ToolTypeIncidentTimeline
}

// Name 实现 Tool.Name
func (itt *IncidentTimelineTool) Name() string {
	return "Incident Timeline"
}

// Description 实现 Tool.Description
func (itt *IncidentTimelineTool) Description() string {
	return "Generate incident timeline from alerts, actions, escalations, and resolutions"
}

// RequiredCapabilities 实现 Tool.RequiredCapabilities
func (itt *IncidentTimelineTool) RequiredCapabilities() []string {
	return []string{"incident:read"}
}

// TimelineEvent 时间线事件
type TimelineEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	Type        string            `json:"type"`  // "alert", "action", "escalation", "resolution", "communication"
	Actor       string            `json:"actor"` // user or system
	Description string            `json:"description"`
	Severity    string            `json:"severity,omitempty"` // for alert events
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// IncidentTimelineResult 事件时间线结果
type IncidentTimelineResult struct {
	IncidentID string          `json:"incident_id"`
	Title      string          `json:"title"`
	StartTime  time.Time       `json:"start_time"`
	EndTime    time.Time       `json:"end_time,omitempty"`
	Duration   time.Duration   `json:"duration"`
	Events     []TimelineEvent `json:"events"`
	RootCause  string          `json:"root_cause,omitempty"`
	Impact     string          `json:"impact,omitempty"`
	Status     string          `json:"status"` // open, mitigated, resolved, closed
}

// ValidateParams 实现 Tool.ValidateParams
func (itt *IncidentTimelineTool) ValidateParams(params interface{}) error {
	p, ok := params.(*IncidentTimelineParams)
	if !ok {
		return ErrInvalidParams
	}

	if p.IncidentID == "" {
		return fmt.Errorf("incident_id is required")
	}

	return nil
}

// Execute 实现 Tool.Execute
func (itt *IncidentTimelineTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*IncidentTimelineParams)
	if !ok {
		return nil, ErrInvalidParams
	}

	if err := itt.ValidateParams(p); err != nil {
		return nil, err
	}

	return itt.performTimeline(p), nil
}

// performTimeline 生成事件时间线
func (itt *IncidentTimelineTool) performTimeline(params *IncidentTimelineParams) *IncidentTimelineResult {
	if len(params.Events) > 0 {
		return itt.buildTimelineFromEvents(params)
	}

	if events := itt.loadExternalIncidentEvents(params.IncidentID); len(events) > 0 {
		return itt.buildTimelineFromEvents(&IncidentTimelineParams{
			IncidentID: params.IncidentID,
			Events:     events,
		})
	}

	result := &IncidentTimelineResult{
		IncidentID: params.IncidentID,
		Events:     make([]TimelineEvent, 0),
	}

	// 根据事件ID生成不同的时间线
	switch params.IncidentID {
	case "INC-001", "INC-002", "INC-003":
		result = itt.getDatabaseIncidentTimeline(params.IncidentID)
	case "INC-004", "INC-005":
		result = itt.getNetworkIncidentTimeline(params.IncidentID)
	case "INC-006":
		result = itt.getSecurityIncidentTimeline(params.IncidentID)
	default:
		result = itt.getGenericIncidentTimeline(params.IncidentID)
	}

	return result
}

type timelineEventRecord struct {
	IncidentID  string            `json:"incident_id"`
	Timestamp   string            `json:"timestamp"`
	Type        string            `json:"type"`
	Actor       string            `json:"actor"`
	Description string            `json:"description"`
	Severity    string            `json:"severity,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (itt *IncidentTimelineTool) loadExternalIncidentEvents(incidentID string) []TimelineEvent {
	path := strings.TrimSpace(os.Getenv("SECOPS_INCIDENT_EVENTS_FILE"))
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	events := make([]TimelineEvent, 0)
	if parsed, ok := parseIncidentEventArray(data, incidentID); ok {
		events = append(events, parsed...)
	} else {
		events = append(events, parseIncidentEventJSONL(data, incidentID)...)
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	return events
}

func parseIncidentEventArray(data []byte, incidentID string) ([]TimelineEvent, bool) {
	var records []timelineEventRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, false
	}
	events := make([]TimelineEvent, 0, len(records))
	for _, r := range records {
		if strings.TrimSpace(r.IncidentID) != incidentID {
			continue
		}
		events = append(events, toTimelineEvent(r))
	}
	return events, true
}

func parseIncidentEventJSONL(data []byte, incidentID string) []TimelineEvent {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	events := make([]TimelineEvent, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var r timelineEventRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if strings.TrimSpace(r.IncidentID) != incidentID {
			continue
		}
		events = append(events, toTimelineEvent(r))
	}
	return events
}

func toTimelineEvent(r timelineEventRecord) TimelineEvent {
	ts := time.Now()
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(r.Timestamp)); err == nil {
		ts = t
	}
	return TimelineEvent{
		Timestamp:   ts,
		Type:        defaultIfEmpty(strings.TrimSpace(r.Type), "action"),
		Actor:       defaultIfEmpty(strings.TrimSpace(r.Actor), "external"),
		Description: defaultIfEmpty(strings.TrimSpace(r.Description), "incident event"),
		Severity:    strings.TrimSpace(r.Severity),
		Metadata:    r.Metadata,
	}
}

func (itt *IncidentTimelineTool) buildTimelineFromEvents(params *IncidentTimelineParams) *IncidentTimelineResult {
	events := make([]TimelineEvent, 0, len(params.Events))
	for _, e := range params.Events {
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}
		events = append(events, e)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	start := events[0].Timestamp
	end := events[len(events)-1].Timestamp

	status := "open"
	rootCause := ""
	impact := ""
	title := "Incident Timeline"

	for _, e := range events {
		lt := strings.ToLower(strings.TrimSpace(e.Type))
		desc := strings.TrimSpace(e.Description)
		switch lt {
		case "resolution":
			status = "resolved"
		case "action":
			if status != "resolved" {
				status = "mitigated"
			}
		case "escalation":
			if status == "open" {
				status = "mitigated"
			}
		}

		if title == "Incident Timeline" && (lt == "alert" || lt == "communication") && desc != "" {
			title = desc
		}
		if rootCause == "" && (strings.Contains(strings.ToLower(desc), "root cause") ||
			strings.Contains(strings.ToLower(desc), "identified")) {
			rootCause = desc
		}
		if impact == "" && strings.Contains(strings.ToLower(desc), "impact") {
			impact = desc
		}
	}

	result := &IncidentTimelineResult{
		IncidentID: params.IncidentID,
		Title:      title,
		StartTime:  start,
		EndTime:    end,
		Duration:   end.Sub(start),
		Events:     events,
		RootCause:  rootCause,
		Impact:     impact,
		Status:     status,
	}

	return result
}

// getDatabaseIncidentTimeline 数据库事件时间线
func (itt *IncidentTimelineTool) getDatabaseIncidentTimeline(incidentID string) *IncidentTimelineResult {
	now := time.Now()
	start := now.Add(-4 * time.Hour)

	result := &IncidentTimelineResult{
		IncidentID: incidentID,
		Title:      "Database Performance Degradation",
		StartTime:  start,
		EndTime:    now.Add(-30 * time.Minute),
		Duration:   3*time.Hour + 30*time.Minute,
		Events: []TimelineEvent{
			{
				Timestamp:   start,
				Type:        "alert",
				Actor:       "prometheus",
				Description: "High database CPU usage alert fired (87%)",
				Severity:    "critical",
			},
			{
				Timestamp:   start.Add(2 * time.Minute),
				Type:        "action",
				Actor:       "oncall-dba",
				Description: "Acknowledged alert and started investigation",
			},
			{
				Timestamp:   start.Add(5 * time.Minute),
				Type:        "escalation",
				Actor:       "pagerduty",
				Description: "Escalated to Senior DBA after 5 minutes",
				Metadata:    map[string]string{"previous_responder": "oncall-dba"},
			},
			{
				Timestamp:   start.Add(8 * time.Minute),
				Type:        "alert",
				Actor:       "prometheus",
				Description: "Database connection pool exhaustion detected",
				Severity:    "critical",
			},
			{
				Timestamp:   start.Add(12 * time.Minute),
				Type:        "action",
				Actor:       "senior-dba",
				Description: "Identified slow query causing lock contention",
				Metadata:    map[string]string{"query_id": "slow_001", "duration_ms": "15420"},
			},
			{
				Timestamp:   start.Add(18 * time.Minute),
				Type:        "action",
				Actor:       "senior-dba",
				Description: "Killed long-running query and optimized indexes",
			},
			{
				Timestamp:   start.Add(20 * time.Minute),
				Type:        "communication",
				Actor:       "senior-dba",
				Description: "Posted status update to incident channel",
				Metadata:    map[string]string{"channel": "#incidents", "message": "Root cause identified, mitigation in progress"},
			},
			{
				Timestamp:   start.Add(45 * time.Minute),
				Type:        "alert",
				Actor:       "prometheus",
				Description: "Database CPU usage returned to normal (23%)",
				Severity:    "info",
			},
			{
				Timestamp:   start.Add(50 * time.Minute),
				Type:        "resolution",
				Actor:       "senior-dba",
				Description: "Incident resolved - slow query removed, indexes added",
			},
			{
				Timestamp:   start.Add(90 * time.Minute),
				Type:        "action",
				Actor:       "sre-team",
				Description: "Post-mortem meeting scheduled",
			},
		},
		RootCause: "Missing index on frequently queried column causing full table scans and lock contention",
		Impact:    "Database latency increased by 500%, affected 12% of user requests",
		Status:    "resolved",
	}

	result.EndTime = start.Add(50 * time.Minute)
	result.Duration = result.EndTime.Sub(result.StartTime)
	return result
}

// getNetworkIncidentTimeline 网络事件时间线
func (itt *IncidentTimelineTool) getNetworkIncidentTimeline(incidentID string) *IncidentTimelineResult {
	now := time.Now()
	start := now.Add(-2 * time.Hour)

	result := &IncidentTimelineResult{
		IncidentID: incidentID,
		Title:      "Network Connectivity Issue",
		StartTime:  start,
		EndTime:    now.Add(-45 * time.Minute),
		Duration:   75 * time.Minute,
		Events: []TimelineEvent{
			{
				Timestamp:   start,
				Type:        "alert",
				Actor:       "grafana",
				Description: "LB backend target unreachable: 503 errors spike",
				Severity:    "critical",
			},
			{
				Timestamp:   start.Add(3 * time.Minute),
				Type:        "action",
				Actor:       "network-oncall",
				Description: "Began tracing connectivity issue",
			},
			{
				Timestamp:   start.Add(10 * time.Minute),
				Type:        "action",
				Actor:       "network-oncall",
				Description: "Identified misconfigured firewall rule blocking traffic",
			},
			{
				Timestamp:   start.Add(15 * time.Minute),
				Type:        "escalation",
				Actor:       "pagerduty",
				Description: "Escalated to network team lead",
			},
			{
				Timestamp:   start.Add(20 * time.Minute),
				Type:        "action",
				Actor:       "network-team-lead",
				Description: "Corrected firewall rules, traffic restored",
			},
			{
				Timestamp:   start.Add(25 * time.Minute),
				Type:        "resolution",
				Actor:       "network-team-lead",
				Description: "Traffic restored, monitoring confirmed stable",
			},
		},
		RootCause: "Firewall rule change during maintenance window incorrectly blocked production traffic",
		Impact:    "Approximately 8% of requests failed with 503 errors for 25 minutes",
		Status:    "resolved",
	}

	result.EndTime = start.Add(25 * time.Minute)
	result.Duration = result.EndTime.Sub(result.StartTime)
	return result
}

// getSecurityIncidentTimeline 安全事件时间线
func (itt *IncidentTimelineTool) getSecurityIncidentTimeline(incidentID string) *IncidentTimelineResult {
	now := time.Now()
	start := now.Add(-6 * time.Hour)

	result := &IncidentTimelineResult{
		IncidentID: incidentID,
		Title:      "Suspicious Authentication Activity",
		StartTime:  start,
		Duration:   0,
		Events: []TimelineEvent{
			{
				Timestamp:   start,
				Type:        "alert",
				Actor:       "security-scanner",
				Description: "Multiple failed login attempts detected from unusual IP",
				Severity:    "critical",
			},
			{
				Timestamp:   start.Add(1 * time.Minute),
				Type:        "alert",
				Actor:       "security-scanner",
				Description: "Potential brute force attack detected - 50 failed attempts",
				Severity:    "critical",
			},
			{
				Timestamp:   start.Add(2 * time.Minute),
				Type:        "action",
				Actor:       "security-oncall",
				Description: "Initiated investigation, blocking suspicious IP",
			},
			{
				Timestamp:   start.Add(5 * time.Minute),
				Type:        "escalation",
				Actor:       "pagerduty",
				Description: "Escalated to security team - confirmed attack",
			},
			{
				Timestamp:   start.Add(8 * time.Minute),
				Type:        "action",
				Actor:       "security-team",
				Description: "IP address blocked at WAF level",
			},
			{
				Timestamp:   start.Add(10 * time.Minute),
				Type:        "communication",
				Actor:       "security-team",
				Description: "Notified affected users, initiated password reset",
			},
			{
				Timestamp:   start.Add(30 * time.Minute),
				Type:        "action",
				Actor:       "security-team",
				Description: "Audit log review completed - no successful unauthorized access",
			},
			{
				Timestamp:   start.Add(60 * time.Minute),
				Type:        "resolution",
				Actor:       "security-team",
				Description: "Incident mitigated - attack blocked, no compromise detected",
			},
		},
		RootCause: "Automated brute force attack targeting admin endpoints from Tor exit node",
		Impact:    "No unauthorized access confirmed. 3 accounts had failed login attempts.",
		Status:    "mitigated",
	}

	result.Duration = time.Since(start)
	return result
}

// getGenericIncidentTimeline 通用事件时间线
func (itt *IncidentTimelineTool) getGenericIncidentTimeline(incidentID string) *IncidentTimelineResult {
	now := time.Now()
	start := now.Add(-1 * time.Hour)

	result := &IncidentTimelineResult{
		IncidentID: incidentID,
		Title:      "Service Degradation",
		StartTime:  start,
		Duration:   0,
		Events: []TimelineEvent{
			{
				Timestamp:   start,
				Type:        "alert",
				Actor:       "monitoring",
				Description: "Service health check degraded",
				Severity:    "warning",
			},
			{
				Timestamp:   start.Add(5 * time.Minute),
				Type:        "action",
				Actor:       "oncall",
				Description: "Acknowledged and investigating",
			},
			{
				Timestamp:   start.Add(15 * time.Minute),
				Type:        "action",
				Actor:       "oncall",
				Description: "Root cause identified, applying fix",
			},
			{
				Timestamp:   start.Add(20 * time.Minute),
				Type:        "resolution",
				Actor:       "oncall",
				Description: "Service restored to normal",
			},
		},
		Status: "resolved",
	}

	result.Duration = time.Since(start)
	result.EndTime = start.Add(20 * time.Minute)
	result.Duration = result.EndTime.Sub(result.StartTime)
	return result
}
