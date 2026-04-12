package secops

import (
	"fmt"
	"strings"
)

// IncidentAssessParams combines common SecOps evidence sources into a single
// investigation workflow input.
type IncidentAssessParams struct {
	IncidentID         string                  `json:"incident_id,omitempty" description:"Incident identifier for the assessment"`
	Platform           string                  `json:"platform,omitempty" description:"Platform context, e.g. kubernetes, aws, gcp"`
	AlertResult        *AlertCheckResult       `json:"alert_result,omitempty" description:"Output from the alert_check tool"`
	LogAnalyzeResult   *LogAnalyzeResult       `json:"log_analyze_result,omitempty" description:"Output from the log_analyze tool"`
	TimelineResult     *IncidentTimelineResult `json:"timeline_result,omitempty" description:"Output from the incident_timeline tool"`
	AccessReviewResult *AccessReviewResult     `json:"access_review_result,omitempty" description:"Output from the access_review tool"`
	Events             []AttackReasonEvidence  `json:"events,omitempty" description:"Normalized evidence events for analysis"`
}

// IncidentAssessResult is a higher-level security investigation output.
type IncidentAssessResult struct {
	IncidentID        string             `json:"incident_id,omitempty"`
	Platform          string             `json:"platform,omitempty"`
	ExecutiveSummary  string             `json:"executive_summary"`
	EvidenceSummary   []string           `json:"evidence_summary,omitempty"`
	AttackAssessment  AttackReasonResult `json:"attack_assessment"`
	ContainmentAdvice []string           `json:"containment_advice,omitempty"`
}

// IncidentAssessTool creates a closed-loop investigation summary from SecOps evidence.
type IncidentAssessTool struct {
	registry     *SecOpsToolRegistry
	attackReason *AttackReasonTool
}

// NewIncidentAssessTool creates a new incident assessment tool.
func NewIncidentAssessTool(registry *SecOpsToolRegistry) *IncidentAssessTool {
	return &IncidentAssessTool{
		registry:     registry,
		attackReason: NewAttackReasonTool(registry),
	}
}

// Type implements Tool.Type.
func (iat *IncidentAssessTool) Type() ToolType {
	return ToolTypeIncidentAssess
}

// Name implements Tool.Name.
func (iat *IncidentAssessTool) Name() string {
	return "Incident Assess"
}

// Description implements Tool.Description.
func (iat *IncidentAssessTool) Description() string {
	return "Combine alerts, logs, timelines, and access review into an ATT&CK-guided incident assessment with containment advice"
}

// RequiredCapabilities implements Tool.RequiredCapabilities.
func (iat *IncidentAssessTool) RequiredCapabilities() []string {
	return []string{"incident:read", "security:analyze", "monitoring:read"}
}

// ValidateParams implements Tool.ValidateParams.
func (iat *IncidentAssessTool) ValidateParams(params interface{}) error {
	p, ok := params.(*IncidentAssessParams)
	if !ok {
		return ErrInvalidParams
	}
	return iat.attackReason.ValidateParams(&AttackReasonParams{
		IncidentID:         p.IncidentID,
		Platform:           p.Platform,
		Events:             p.Events,
		AlertResult:        p.AlertResult,
		LogAnalyzeResult:   p.LogAnalyzeResult,
		TimelineResult:     p.TimelineResult,
		AccessReviewResult: p.AccessReviewResult,
	})
}

// Execute implements Tool.Execute.
func (iat *IncidentAssessTool) Execute(params interface{}) (interface{}, error) {
	p, ok := params.(*IncidentAssessParams)
	if !ok {
		return nil, ErrInvalidParams
	}
	if err := iat.ValidateParams(p); err != nil {
		return nil, err
	}

	raw, err := iat.attackReason.Execute(&AttackReasonParams{
		IncidentID:         p.IncidentID,
		Platform:           p.Platform,
		Events:             p.Events,
		AlertResult:        p.AlertResult,
		LogAnalyzeResult:   p.LogAnalyzeResult,
		TimelineResult:     p.TimelineResult,
		AccessReviewResult: p.AccessReviewResult,
	})
	if err != nil {
		return nil, err
	}
	attackResult, ok := raw.(*AttackReasonResult)
	if !ok {
		return nil, fmt.Errorf("unexpected attack assessment type %T", raw)
	}

	return &IncidentAssessResult{
		IncidentID:        p.IncidentID,
		Platform:          p.Platform,
		ExecutiveSummary:  buildIncidentExecutiveSummary(attackResult),
		EvidenceSummary:   summarizeEvidence(p),
		AttackAssessment:  *attackResult,
		ContainmentAdvice: buildContainmentAdvice(attackResult),
	}, nil
}

func summarizeEvidence(params *IncidentAssessParams) []string {
	var summary []string
	if params.AlertResult != nil {
		summary = append(summary, fmt.Sprintf("Alerts: %d total from %s.", params.AlertResult.Total, params.AlertResult.System))
	}
	if params.LogAnalyzeResult != nil {
		summary = append(summary, fmt.Sprintf("Logs: %d filtered entries from %d total.", params.LogAnalyzeResult.FilteredCount, params.LogAnalyzeResult.TotalCount))
	}
	if params.TimelineResult != nil {
		summary = append(summary, fmt.Sprintf("Timeline: %d correlated incident events.", len(params.TimelineResult.Events)))
	}
	if params.AccessReviewResult != nil {
		summary = append(summary, fmt.Sprintf("Access review: %d high-risk entries out of %d.", params.AccessReviewResult.HighRiskCount, params.AccessReviewResult.TotalCount))
	}
	if len(params.Events) > 0 {
		summary = append(summary, fmt.Sprintf("Manual evidence events: %d.", len(params.Events)))
	}
	if len(summary) == 0 {
		summary = append(summary, "No structured evidence summary was available.")
	}
	return summary
}

func buildIncidentExecutiveSummary(result *AttackReasonResult) string {
	if len(result.Assessment.Techniques) == 0 {
		return "Incident assessment did not find a high-confidence ATT&CK path; gather more alerts, logs, and access evidence."
	}
	top := result.Assessment.Techniques[0]
	tactics := strings.Join(result.Assessment.Tactics, ", ")
	if tactics == "" {
		tactics = "unknown tactics"
	}
	return fmt.Sprintf("Top ATT&CK assessment is %s (%s) with confidence %.2f across tactics: %s.", top.TechniqueID, top.Name, top.Confidence, tactics)
}

func buildContainmentAdvice(result *AttackReasonResult) []string {
	advice := append([]string{}, result.Assessment.NextActions...)
	if len(result.Assessment.Techniques) == 0 {
		advice = append(advice, "Pause disruptive actions until stronger evidence is collected.")
		return uniqueStrings(advice)
	}

	switch result.Assessment.Techniques[0].TechniqueID {
	case "T1110", "T1078":
		advice = append(advice,
			"Enforce MFA or step-up authentication for the affected accounts immediately.",
			"Temporarily restrict suspicious source IPs or geographies while validation continues.",
		)
	case "T1552":
		advice = append(advice,
			"Rotate exposed credentials and invalidate dependent sessions.",
			"Audit downstream systems for use of the compromised secrets.",
		)
	case "T1021":
		advice = append(advice,
			"Constrain remote access paths and isolate suspected lateral movement pivots.",
		)
	case "T1070":
		advice = append(advice,
			"Preserve centralized logs and prevent local cleanup actions on the affected hosts.",
		)
	}

	return uniqueStrings(advice)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
