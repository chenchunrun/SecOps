package chat

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
)

type SecOpsToolMessageItem struct {
	*baseToolMessageItem
}

var _ ToolMessageItem = (*SecOpsToolMessageItem)(nil)

func NewSecOpsToolMessageItem(
	sty *styles.Styles,
	toolCall message.ToolCall,
	result *message.ToolResult,
	canceled bool,
) ToolMessageItem {
	return newBaseToolMessageItem(sty, toolCall, result, &SecOpsToolRenderContext{}, canceled)
}

type SecOpsToolRenderContext struct{}

func (s *SecOpsToolRenderContext) RenderTool(sty *styles.Styles, width int, opts *ToolRenderOpts) string {
	cappedWidth := cappedMessageWidth(width)
	name := secOpsPrettyName(opts.ToolCall.Name)

	if opts.IsPending() {
		return pendingTool(sty, name, opts.Anim, opts.Compact)
	}

	header := toolHeader(sty, opts.Status, name, cappedWidth, opts.Compact)
	if opts.Compact {
		return header
	}
	if earlyState, ok := toolEarlyStateContent(sty, opts, cappedWidth); ok {
		return joinToolParts(header, earlyState)
	}
	if !opts.HasResult() || opts.Result.Content == "" {
		return header
	}

	bodyWidth := cappedWidth - toolBodyLeftPaddingTotal
	summary, prettyJSON, err := summarizeSecOpsToolResult(opts.ToolCall.Name, opts.Result.Content)
	if err != nil {
		body := sty.Tool.Body.Render(toolOutputPlainContent(sty, opts.Result.Content, bodyWidth, opts.ExpandedContent))
		return joinToolParts(header, body)
	}

	bodyParts := make([]string, 0, 2)
	if summary != "" {
		bodyParts = append(bodyParts, toolOutputPlainContent(sty, summary, bodyWidth, opts.ExpandedContent))
	}
	if prettyJSON != "" && opts.ExpandedContent {
		bodyParts = append(bodyParts, toolOutputCodeContent(sty, "result.json", prettyJSON, 0, bodyWidth, opts.ExpandedContent))
	}

	body := sty.Tool.Body.Render(strings.Join(bodyParts, "\n\n"))
	return joinToolParts(header, body)
}

func secOpsPrettyName(name string) string {
	switch name {
	case "incident_assess":
		return "Incident Assess"
	case "attack_reason":
		return "ATT&CK Reason"
	default:
		return genericPrettyName(name)
	}
}

func summarizeSecOpsToolResult(toolName, content string) (string, string, error) {
	switch toolName {
	case "incident_assess":
		return summarizeIncidentAssessResult(content)
	case "attack_reason":
		return summarizeAttackReasonResult(content)
	default:
		return "", "", fmt.Errorf("unsupported secops tool %q", toolName)
	}
}

type incidentAssessUIResult struct {
	IncidentID        string   `json:"incident_id"`
	Platform          string   `json:"platform"`
	ExecutiveSummary  string   `json:"executive_summary"`
	EvidenceSummary   []string `json:"evidence_summary"`
	ContainmentAdvice []string `json:"containment_advice"`
	AttackAssessment  struct {
		Assessment struct {
			Tactics    []string `json:"tactics"`
			Techniques []struct {
				TechniqueID string  `json:"technique_id"`
				Name        string  `json:"name"`
				Confidence  float64 `json:"confidence"`
			} `json:"techniques"`
			NextActions []string `json:"next_actions"`
		} `json:"assessment"`
	} `json:"attack_assessment"`
}

func summarizeIncidentAssessResult(content string) (string, string, error) {
	var result incidentAssessUIResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return "", "", err
	}

	lines := make([]string, 0, 8)
	if result.ExecutiveSummary != "" {
		lines = append(lines, "Executive Summary: "+result.ExecutiveSummary)
	}
	if len(result.AttackAssessment.Assessment.Techniques) > 0 {
		top := result.AttackAssessment.Assessment.Techniques[0]
		lines = append(lines, fmt.Sprintf("Top Technique: %s (%s) confidence %.2f", top.TechniqueID, top.Name, top.Confidence))
	}
	if len(result.AttackAssessment.Assessment.Tactics) > 0 {
		lines = append(lines, "Tactics: "+strings.Join(result.AttackAssessment.Assessment.Tactics, ", "))
	}
	if len(result.EvidenceSummary) > 0 {
		lines = append(lines, "Evidence: "+strings.Join(result.EvidenceSummary, " | "))
	}
	if len(result.ContainmentAdvice) > 0 {
		lines = append(lines, "Containment: "+strings.Join(result.ContainmentAdvice, " | "))
	}

	pretty, err := indentJSON(content)
	return strings.Join(lines, "\n"), pretty, err
}

type attackReasonUIResult struct {
	IncidentID string `json:"incident_id"`
	Platform   string `json:"platform"`
	Assessment struct {
		Summary    string   `json:"summary"`
		Tactics    []string `json:"tactics"`
		Techniques []struct {
			TechniqueID string   `json:"technique_id"`
			Name        string   `json:"name"`
			Confidence  float64  `json:"confidence"`
			Reasons     []string `json:"reasons"`
		} `json:"techniques"`
		NextActions []string `json:"next_actions"`
	} `json:"assessment"`
}

func summarizeAttackReasonResult(content string) (string, string, error) {
	var result attackReasonUIResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return "", "", err
	}

	lines := make([]string, 0, 6)
	if result.Assessment.Summary != "" {
		lines = append(lines, "Assessment: "+result.Assessment.Summary)
	}
	if len(result.Assessment.Techniques) > 0 {
		top := result.Assessment.Techniques[0]
		lines = append(lines, fmt.Sprintf("Top Technique: %s (%s) confidence %.2f", top.TechniqueID, top.Name, top.Confidence))
		if len(top.Reasons) > 0 {
			lines = append(lines, "Why: "+strings.Join(top.Reasons, " | "))
		}
	}
	if len(result.Assessment.Tactics) > 0 {
		lines = append(lines, "Tactics: "+strings.Join(result.Assessment.Tactics, ", "))
	}
	if len(result.Assessment.NextActions) > 0 {
		lines = append(lines, "Next Actions: "+strings.Join(result.Assessment.NextActions, " | "))
	}

	pretty, err := indentJSON(content)
	return strings.Join(lines, "\n"), pretty, err
}

func indentJSON(content string) (string, error) {
	var raw json.RawMessage
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}
