package attack

import (
	"math"
	"testing"
)

func approxEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestReasoner_Assess_NoEvents(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	assessment := r.Assess(nil)

	if len(assessment.Techniques) != 0 {
		t.Errorf("expected no techniques for empty evidence, got %d", len(assessment.Techniques))
	}
	if assessment.Summary == "" {
		t.Error("expected non-empty summary for empty evidence")
	}
	if len(assessment.Gaps) == 0 || len(assessment.NextActions) == 0 {
		t.Error("expected guidance gaps and next actions for empty evidence")
	}
}

func TestReasoner_Assess_SingleTechnique(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	assessment := r.Assess([]EvidenceEvent{
		{ID: "ev-1", Source: "auditd", Action: "log cleared", Severity: "HIGH", Confidence: 0.5},
	})

	if len(assessment.Techniques) != 1 {
		t.Fatalf("expected 1 technique, got %d", len(assessment.Techniques))
	}
	top := assessment.Techniques[0]
	if top.TechniqueID != "T1070" {
		t.Errorf("expected top technique T1070, got %s", top.TechniqueID)
	}
	if top.Score <= 0 || top.Score > 5.0 {
		t.Errorf("score %.2f out of expected range (0, 5]", top.Score)
	}
	if top.Confidence <= 0 || top.Confidence > 0.95 {
		t.Errorf("confidence %.2f out of expected range (0, 0.95]", top.Confidence)
	}
	if len(top.EvidenceIDs) != 1 || top.EvidenceIDs[0] != "ev-1" {
		t.Errorf("expected evidence [ev-1], got %v", top.EvidenceIDs)
	}
	foundTactic := false
	for _, tactic := range assessment.Tactics {
		if tactic == "Defense Evasion" {
			foundTactic = true
		}
	}
	if !foundTactic {
		t.Errorf("expected Defense Evasion tactic, got %v", assessment.Tactics)
	}
	if assessment.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestReasoner_Assess_AccumulatesSameTechnique(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	// 三条证据均映射到 T1070；其中两条共享 ID，应去重。
	assessment := r.Assess([]EvidenceEvent{
		{ID: "e1", Action: "log cleared"},
		{ID: "e1", Action: "truncate log"}, // 与上一条同 ID，触发 EvidenceIDs 去重
		{ID: "e2", Action: "history deleted"},
	})

	if len(assessment.Techniques) != 1 {
		t.Fatalf("expected 1 accumulated technique, got %d", len(assessment.Techniques))
	}
	top := assessment.Techniques[0]
	if top.TechniqueID != "T1070" {
		t.Fatalf("expected T1070, got %s", top.TechniqueID)
	}
	if len(top.EvidenceIDs) != 2 {
		t.Errorf("expected 2 deduped evidence IDs, got %v", top.EvidenceIDs)
	}
	seen := map[string]bool{}
	for _, id := range top.EvidenceIDs {
		seen[id] = true
	}
	if !seen["e1"] || !seen["e2"] {
		t.Errorf("expected evidence e1 and e2, got %v", top.EvidenceIDs)
	}
	if len(top.Reasons) != 1 {
		t.Errorf("expected deduped single reason, got %v", top.Reasons)
	}
}

func TestReasoner_Assess_ScoreAndConfidenceCaps(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	// 5 条高严重度 T1070 证据使累计分数超过上限，触发分数(5.0)与置信度(0.95)双重封顶。
	events := make([]EvidenceEvent, 0, 5)
	for i := 0; i < 5; i++ {
		events = append(events, EvidenceEvent{
			ID:         "ev",
			Action:     "log cleared",
			Severity:   "CRITICAL",
			Confidence: 1.0,
		})
	}

	assessment := r.Assess(events)
	if len(assessment.Techniques) != 1 {
		t.Fatalf("expected 1 technique, got %d", len(assessment.Techniques))
	}
	top := assessment.Techniques[0]
	if !approxEqual(top.Score, 5.0) {
		t.Errorf("expected score capped at 5.0, got %.2f", top.Score)
	}
	if !approxEqual(top.Confidence, 0.95) {
		t.Errorf("expected confidence capped at 0.95, got %.2f", top.Confidence)
	}
}

func TestReasoner_Assess_TieBreakByID(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	// T1110 (0.55) + LOW (0.05) = 0.60；T1021 (0.60) = 0.60。同分按 ID 升序，T1021 在前。
	assessment := r.Assess([]EvidenceEvent{
		{ID: "a", Action: "brute force", Severity: "LOW"},
		{ID: "b", Action: "ssh"},
	})

	if len(assessment.Techniques) != 2 {
		t.Fatalf("expected 2 techniques, got %d", len(assessment.Techniques))
	}
	if assessment.Techniques[0].TechniqueID != "T1021" {
		t.Errorf("expected T1021 first on tie, got %s", assessment.Techniques[0].TechniqueID)
	}
	if assessment.Techniques[1].TechniqueID != "T1110" {
		t.Errorf("expected T1110 second on tie, got %s", assessment.Techniques[1].TechniqueID)
	}
}

func TestReasoner_Assess_TopFiveTruncation(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	// 单条证据文本同时命中全部 6 个技术分类，结果应截断为前 5。
	assessment := r.Assess([]EvidenceEvent{
		{ID: "x", Action: "brute force valid account api key ssh log cleared list users"},
	})

	if len(assessment.Techniques) != 5 {
		t.Fatalf("expected top-5 truncation, got %d techniques", len(assessment.Techniques))
	}
}

func TestReasoner_Assess_FallbackLowConfidence(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	// EventType 存在但无触发词 → 兜底 T1078 低置信，触发 gap 提示。
	assessment := r.Assess([]EvidenceEvent{
		{ID: "f", EventType: "anomaly", Source: "edr"},
	})

	if len(assessment.Techniques) != 1 || assessment.Techniques[0].TechniqueID != "T1078" {
		t.Fatalf("expected fallback T1078, got %+v", assessment.Techniques)
	}
	if assessment.Techniques[0].Confidence >= 0.5 {
		t.Errorf("expected low confidence < 0.5, got %.2f", assessment.Techniques[0].Confidence)
	}
	// 低置信应触发 gap 与认证日志类建议。
	if len(assessment.Gaps) < 2 {
		t.Errorf("expected >= 2 gaps for low confidence, got %v", assessment.Gaps)
	}
	foundAuth := false
	for _, action := range assessment.NextActions {
		if containsAny(action, "authentication") {
			foundAuth = true
		}
	}
	if !foundAuth {
		t.Errorf("expected auth-log next action for T1078, got %v", assessment.NextActions)
	}
}

func TestReasoner_Assess_NoMatch(t *testing.T) {
	t.Parallel()

	r := NewReasoner()
	// 无 EventType 且无触发词 → 零匹配，走 empty 分支。
	assessment := r.Assess([]EvidenceEvent{
		{ID: "n", Source: "noise"},
	})

	if len(assessment.Techniques) != 0 {
		t.Fatalf("expected zero techniques, got %d", len(assessment.Techniques))
	}
	if !containsAny(assessment.Summary, "no ATT&CK techniques ranked") {
		t.Errorf("expected no-match summary, got %q", assessment.Summary)
	}
	foundCollect := false
	for _, action := range assessment.NextActions {
		if containsAny(action, "log_analyze") {
			foundCollect = true
		}
	}
	if !foundCollect {
		t.Errorf("expected evidence-collection next action, got %v", assessment.NextActions)
	}
}

func TestReasoner_Assess_NextActionsBranches(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		action         string
		wantTechnique  string
		wantContainSub string
	}{
		{name: "T1552 凭证分支", action: "private key leaked", wantTechnique: "T1552", wantContainSub: "secret_audit"},
		{name: "T1021 远程分支", action: "remote execution over ssh", wantTechnique: "T1021", wantContainSub: "remote"},
		{name: "T1070 指标移除分支", action: "log cleared", wantTechnique: "T1070", wantContainSub: "SIEM"},
		{name: "T1110 认证分支", action: "brute force", wantTechnique: "T1110", wantContainSub: "authentication"},
		{name: "T1087 默认分支", action: "list users", wantTechnique: "T1087", wantContainSub: "incident_timeline"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := NewReasoner()
			assessment := r.Assess([]EvidenceEvent{{ID: "e", Action: tc.action}})

			if len(assessment.Techniques) == 0 {
				t.Fatalf("expected at least one technique for %q", tc.action)
			}
			if assessment.Techniques[0].TechniqueID != tc.wantTechnique {
				t.Fatalf("expected top %s, got %s", tc.wantTechnique, assessment.Techniques[0].TechniqueID)
			}
			found := false
			for _, action := range assessment.NextActions {
				if containsAny(action, tc.wantContainSub) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected NextActions to mention %q, got %v", tc.wantContainSub, assessment.NextActions)
			}
		})
	}
}

func TestSeverityWeight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity string
		want     float64
	}{
		{name: "CRITICAL", severity: "CRITICAL", want: 0.25},
		{name: "HIGH", severity: "HIGH", want: 0.2},
		{name: "MEDIUM", severity: "MEDIUM", want: 0.12},
		{name: "LOW", severity: "LOW", want: 0.05},
		{name: "未知", severity: "BOGUS", want: 0},
		{name: "空", severity: "", want: 0},
		{name: "小写归一", severity: "critical", want: 0.25},
		{name: "空白归一", severity: "  High  ", want: 0.2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := severityWeight(tc.severity); !approxEqual(got, tc.want) {
				t.Errorf("severityWeight(%q) = %.2f, want %.2f", tc.severity, got, tc.want)
			}
		})
	}
}

func TestConfidenceWeight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		confidence float64
		want       float64
	}{
		{name: "零", confidence: 0, want: 0},
		{name: "负值归零", confidence: -1, want: 0},
		{name: "正常", confidence: 0.5, want: 0.125},
		{name: "封顶", confidence: 10, want: 0.25},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := confidenceWeight(tc.confidence); !approxEqual(got, tc.want) {
				t.Errorf("confidenceWeight(%.2f) = %.2f, want %.2f", tc.confidence, got, tc.want)
			}
		})
	}
}

func TestUnique(t *testing.T) {
	t.Parallel()

	got := unique([]string{"a", " a ", "", "a", "b", "  "})
	if len(got) != 2 {
		t.Fatalf("expected 2 unique values, got %v", got)
	}
	seen := map[string]bool{}
	for _, v := range got {
		seen[v] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Errorf("expected unique [a b], got %v", got)
	}
}

func TestRound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   float64
		want float64
	}{
		{in: 1.234, want: 1.23},
		{in: 2.0, want: 2.0},
		{in: 0.006, want: 0.01},
	}
	for _, tc := range tests {
		if got := round(tc.in); !approxEqual(got, tc.want) {
			t.Errorf("round(%.3f) = %.3f, want %.3f", tc.in, got, tc.want)
		}
	}
}

func TestMinFloat(t *testing.T) {
	t.Parallel()

	if !approxEqual(min(2, 3), 2) {
		t.Errorf("min(2,3) wrong")
	}
	if !approxEqual(min(3, 2), 2) {
		t.Errorf("min(3,2) wrong")
	}
	if !approxEqual(min(-1, 1), -1) {
		t.Errorf("min(-1,1) wrong")
	}
}
