package secops

import (
	"fmt"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/security/attack"
)

// AttackReasonEvidence is the tool input form for normalized evidence.
type AttackReasonEvidence struct {
	ID         string            `json:"id,omitempty"`
	Source     string            `json:"source,omitempty"`
	EventType  string            `json:"event_type,omitempty"`
	Timestamp  time.Time         `json:"timestamp,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	Target     string            `json:"target,omitempty"`
	Action     string            `json:"action,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Confidence float64           `json:"confidence,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Raw        string            `json:"raw,omitempty"`
}

// AttackReasonParams are the inputs for ATT&CK reasoning.
type AttackReasonParams struct {
	IncidentID         string                  `json:"incident_id,omitempty" description:"Incident identifier to correlate evidence"`
	Platform           string                  `json:"platform,omitempty" description:"Platform context, e.g. kubernetes, aws, gcp"`
	Events             []AttackReasonEvidence  `json:"events,omitempty" description:"Normalized evidence events for ATT&CK mapping"`
	AlertResult        *AlertCheckResult       `json:"alert_result,omitempty" description:"Output from the alert_check tool"`
	LogAnalyzeResult   *LogAnalyzeResult       `json:"log_analyze_result,omitempty" description:"Output from the log_analyze tool"`
	TimelineResult     *IncidentTimelineResult `json:"timeline_result,omitempty" description:"Output from the incident_timeline tool"`
	AccessReviewResult *AccessReviewResult     `json:"access_review_result,omitempty" description:"Output from the access_review tool"`
}

// AttackReasonResult wraps the ATT&CK assessment for SecOps tool callers.
type AttackReasonResult struct {
	IncidentID string            `json:"incident_id,omitempty"`
	Platform   string            `json:"platform,omitempty"`
	Assessment attack.Assessment `json:"assessment"`
}

// AttackReasonTool maps normalized evidence to MITRE ATT&CK techniques.
type AttackReasonTool struct {
	registry *SecOpsToolRegistry
	reasoner *attack.Reasoner
}

// NewAttackReasonTool creates an ATT&CK reasoning tool.
func NewAttackReasonTool(registry *SecOpsToolRegistry) *AttackReasonTool {
	return &AttackReasonTool{
		registry: registry,
		reasoner: attack.NewReasoner(),
	}
}

// Type implements Tool.Type.
func (art *AttackReasonTool) Type() ToolType {
	return ToolTypeAttackReason
}

// Name implements Tool.Name.
func (art *AttackReasonTool) Name() string {
	return "ATT&CK Reasoner"
}

// Description implements Tool.Description.
func (art *AttackReasonTool) Description() string {
	return "Rank MITRE ATT&CK techniques from normalized incident evidence and recommend next investigation steps"
}

// RequiredCapabilities implements Tool.RequiredCapabilities.
func (art *AttackReasonTool) RequiredCapabilities() []string {
	return []string{"incident:read", "security:analyze"}
}

// ValidateParams implements Tool.ValidateParams.
func (art *AttackReasonTool) ValidateParams(params interface{}) error {
	p, ok := params.(*AttackReasonParams)
	if !ok {
		return ErrInvalidParams
	}
	if p.IncidentID == "" &&
		len(p.Events) == 0 &&
		p.AlertResult == nil &&
		p.LogAnalyzeResult == nil &&
		p.TimelineResult == nil &&
		p.AccessReviewResult == nil {
		return fmt.Errorf("incident_id, events, or normalized secops results are required")
	}
	return nil
}

// Execute implements Tool.Execute.
func (art *AttackReasonTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*AttackReasonParams)
	if !ok {
		return nil, ErrInvalidParams
	}
	if err := art.ValidateParams(p); err != nil {
		return nil, err
	}

	events := make([]attack.EvidenceEvent, 0, len(p.Events)+16)
	for i, event := range p.Events {
		id := event.ID
		if id == "" {
			id = fmt.Sprintf("event-%d", i+1)
		}
		events = append(events, attack.EvidenceEvent{
			ID:         id,
			Source:     event.Source,
			EventType:  event.EventType,
			Timestamp:  event.Timestamp,
			Actor:      event.Actor,
			Target:     event.Target,
			Action:     event.Action,
			Severity:   event.Severity,
			Confidence: event.Confidence,
			Fields:     event.Fields,
			Raw:        event.Raw,
		})
	}
	events = append(events, evidenceFromAlertResult(p.AlertResult)...)
	events = append(events, evidenceFromLogAnalyzeResult(p.LogAnalyzeResult)...)
	events = append(events, evidenceFromTimelineResult(p.TimelineResult)...)
	events = append(events, evidenceFromAccessReviewResult(p.AccessReviewResult)...)

	return &AttackReasonResult{
		IncidentID: p.IncidentID,
		Platform:   p.Platform,
		Assessment: art.reasoner.Assess(events),
	}, nil
}

func evidenceFromAlertResult(result *AlertCheckResult) []attack.EvidenceEvent {
	if result == nil {
		return nil
	}
	events := make([]attack.EvidenceEvent, 0, len(result.Alerts))
	for i, alert := range result.Alerts {
		events = append(events, attack.EvidenceEvent{
			ID:         fallbackID(alert.ID, "alert", i),
			Source:     "alert_check",
			EventType:  normalizeAlertEventType(alert),
			Timestamp:  alert.FiredAt,
			Target:     alert.Name,
			Action:     alert.Status,
			Severity:   strings.ToUpper(alert.Severity),
			Confidence: 0.7,
			Fields: mergeFields(
				alert.Labels,
				alert.Annotations,
				map[string]string{"system": result.System, "status": alert.Status},
			),
			Raw: strings.TrimSpace(alert.Message),
		})
	}
	return events
}

func evidenceFromLogAnalyzeResult(result *LogAnalyzeResult) []attack.EvidenceEvent {
	if result == nil {
		return nil
	}
	events := make([]attack.EvidenceEvent, 0, len(result.Entries))
	for i, entry := range result.Entries {
		if entry == nil {
			continue
		}
		events = append(events, attack.EvidenceEvent{
			ID:         fallbackID("", "log", i),
			Source:     "log_analyze",
			EventType:  normalizeLogEventType(entry),
			Timestamp:  entry.Timestamp,
			Actor:      entry.User,
			Target:     entry.Host,
			Action:     entry.Process,
			Severity:   string(entry.Level),
			Confidence: 0.55,
			Fields: map[string]string{
				"host":    entry.Host,
				"process": entry.Process,
				"source":  string(entry.Source),
			},
			Raw: entry.Message,
		})
	}
	return events
}

func evidenceFromTimelineResult(result *IncidentTimelineResult) []attack.EvidenceEvent {
	if result == nil {
		return nil
	}
	events := make([]attack.EvidenceEvent, 0, len(result.Events))
	for i, event := range result.Events {
		events = append(events, attack.EvidenceEvent{
			ID:         fallbackID("", "timeline", i),
			Source:     "incident_timeline",
			EventType:  normalizeTimelineEventType(event),
			Timestamp:  event.Timestamp,
			Actor:      event.Actor,
			Action:     event.Type,
			Severity:   strings.ToUpper(event.Severity),
			Confidence: 0.65,
			Fields:     event.Metadata,
			Raw:        event.Description,
		})
	}
	return events
}

func evidenceFromAccessReviewResult(result *AccessReviewResult) []attack.EvidenceEvent {
	if result == nil {
		return nil
	}
	events := make([]attack.EvidenceEvent, 0, len(result.Entries))
	for i, entry := range result.Entries {
		events = append(events, attack.EvidenceEvent{
			ID:         fallbackID("", "access", i),
			Source:     "access_review",
			EventType:  normalizeAccessEventType(entry),
			Actor:      entry.Principal,
			Target:     entry.Resource,
			Action:     entry.Permission,
			Severity:   strings.ToUpper(entry.Risk),
			Confidence: 0.6,
			Fields: map[string]string{
				"principal":  entry.Principal,
				"permission": entry.Permission,
				"resource":   entry.Resource,
				"last_used":  entry.LastUsed,
			},
			Raw: fmt.Sprintf("%s has %s on %s", entry.Principal, entry.Permission, entry.Resource),
		})
	}
	return events
}

func normalizeAlertEventType(alert AlertInfo) string {
	text := strings.ToLower(strings.Join([]string{alert.Name, alert.Message}, " "))
	switch {
	case strings.Contains(text, "failed") && strings.Contains(text, "login"):
		return "failed_login_burst"
	case strings.Contains(text, "brute force"):
		return "failed_login_burst"
	case strings.Contains(text, "credential"):
		return "credential_exposure"
	case strings.Contains(text, "remote") || strings.Contains(text, "ssh"):
		return "unexpected_remote_execution"
	default:
		return "security_alert"
	}
}

func normalizeLogEventType(entry *LogEntry) string {
	text := strings.ToLower(strings.Join([]string{entry.Message, entry.Process, entry.User}, " "))
	switch {
	case strings.Contains(text, "failed password") || strings.Contains(text, "authentication failure"):
		return "failed_login_burst"
	case strings.Contains(text, "accepted password") || strings.Contains(text, "successful login after failures"):
		return "successful_login_after_failures"
	case strings.Contains(text, "sudo") || strings.Contains(text, "privilege"):
		return "suspicious_admin_privilege_use"
	case strings.Contains(text, "ssh") || strings.Contains(text, "remote command"):
		return "unexpected_remote_execution"
	case strings.Contains(text, "secret") || strings.Contains(text, "token") || strings.Contains(text, "api key"):
		return "credential_exposure"
	case strings.Contains(text, "truncate") || strings.Contains(text, "history deleted") || strings.Contains(text, "log cleared"):
		return "log_tamper"
	default:
		return "log_observation"
	}
}

func normalizeTimelineEventType(event TimelineEvent) string {
	text := strings.ToLower(strings.Join([]string{event.Type, event.Description, event.Actor}, " "))
	switch {
	case strings.Contains(text, "failed attempts") || strings.Contains(text, "brute force"):
		return "failed_login_burst"
	case strings.Contains(text, "confirmed attack") || strings.Contains(text, "successful login"):
		return "successful_login_after_failures"
	case strings.Contains(text, "escalated") || strings.Contains(text, "privilege"):
		return "suspicious_admin_privilege_use"
	default:
		return "incident_activity"
	}
}

func normalizeAccessEventType(entry AccessEntry) string {
	text := strings.ToLower(strings.Join([]string{entry.Principal, entry.Permission, entry.Resource, entry.Risk}, " "))
	switch {
	case strings.Contains(text, "owner") || strings.Contains(text, "iam:*") || strings.Contains(text, "admin"):
		return "suspicious_admin_privilege_use"
	case strings.Contains(text, "former-employee") || strings.Contains(text, "stale"):
		return "valid_account_risk"
	default:
		return "account_discovery_signal"
	}
}

func fallbackID(id, prefix string, index int) string {
	if strings.TrimSpace(id) != "" {
		return id
	}
	return fmt.Sprintf("%s-%d", prefix, index+1)
}

func mergeFields(groups ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, group := range groups {
		for k, v := range group {
			if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
				continue
			}
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
