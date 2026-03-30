package attack

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
)

// Reasoner evaluates normalized evidence against the reduced ATT&CK corpus.
type Reasoner struct {
	kb *KnowledgeBase
}

// NewReasoner returns a local ATT&CK reasoner backed by the built-in corpus.
func NewReasoner() *Reasoner {
	return &Reasoner{kb: NewKnowledgeBase()}
}

type accumulated struct {
	Technique Technique
	Score     float64
	Reasons   []string
	Evidence  []string
}

// Assess ranks ATT&CK techniques for the provided evidence.
func (r *Reasoner) Assess(events []EvidenceEvent) Assessment {
	if len(events) == 0 {
		return Assessment{
			Summary:     "No evidence events were provided, so ATT&CK reasoning could not rank any techniques.",
			Gaps:        []string{"Collect normalized alerts, logs, or incident timeline events before running ATT&CK reasoning."},
			NextActions: []string{"Run alert_check, log_analyze, or incident_timeline to collect investigation evidence."},
		}
	}

	acc := make(map[string]*accumulated)
	for _, event := range events {
		for _, mapping := range mapEvidenceEvent(event) {
			technique, ok := r.kb.Get(mapping.TechniqueID)
			if !ok {
				continue
			}
			entry, exists := acc[mapping.TechniqueID]
			if !exists {
				entry = &accumulated{Technique: technique}
				acc[mapping.TechniqueID] = entry
			}

			score := mapping.Score + severityWeight(event.Severity) + confidenceWeight(event.Confidence)
			entry.Score += score
			entry.Reasons = append(entry.Reasons, mapping.Reason)
			if event.ID != "" {
				entry.Evidence = append(entry.Evidence, event.ID)
			}
		}
	}

	matches := make([]TechniqueMatch, 0, len(acc))
	for _, entry := range acc {
		uniqueEvidence := unique(entry.Evidence)
		match := TechniqueMatch{
			TechniqueID: entry.Technique.ID,
			Name:        entry.Technique.Name,
			Score:       round(min(entry.Score, 5.0)),
			Confidence:  round(min(0.95, 0.2+entry.Score/5.0)),
			EvidenceIDs: uniqueEvidence,
			Reasons:     unique(entry.Reasons),
			TacticIDs:   slices.Clone(entry.Technique.TacticIDs),
		}
		matches = append(matches, match)
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Score == matches[j].Score {
			return matches[i].TechniqueID < matches[j].TechniqueID
		}
		return matches[i].Score > matches[j].Score
	})

	if len(matches) > 5 {
		matches = matches[:5]
	}

	techniqueIDs := make([]string, 0, len(matches))
	for _, match := range matches {
		techniqueIDs = append(techniqueIDs, match.TechniqueID)
	}
	tactics := r.kb.TacticsFor(techniqueIDs)

	return Assessment{
		Summary:     buildSummary(matches),
		Tactics:     tactics,
		Techniques:  matches,
		Gaps:        buildGaps(matches, events),
		NextActions: buildNextActions(matches),
	}
}

func severityWeight(severity string) float64 {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0.25
	case "HIGH":
		return 0.2
	case "MEDIUM":
		return 0.12
	case "LOW":
		return 0.05
	default:
		return 0
	}
}

func confidenceWeight(confidence float64) float64 {
	if confidence <= 0 {
		return 0
	}
	return min(0.25, confidence*0.25)
}

func buildSummary(matches []TechniqueMatch) string {
	if len(matches) == 0 {
		return "Evidence was collected, but no ATT&CK techniques ranked above the minimum threshold."
	}
	top := matches[0]
	return fmt.Sprintf("Top ATT&CK candidate is %s (%s) with confidence %.2f based on correlated security evidence.", top.TechniqueID, top.Name, top.Confidence)
}

func buildGaps(matches []TechniqueMatch, events []EvidenceEvent) []string {
	gaps := []string{
		"Validate suspicious findings against host, identity, and network evidence before containment.",
	}
	if len(events) < 2 {
		gaps = append(gaps, "Only a small amount of evidence was provided; ranking confidence is limited.")
	}
	if len(matches) == 0 || matches[0].Confidence < 0.5 {
		gaps = append(gaps, "No high-confidence technique match was produced; collect more precise incident artifacts.")
	}
	return unique(gaps)
}

func buildNextActions(matches []TechniqueMatch) []string {
	actions := []string{
		"Preserve raw alerts and log evidence for auditability before making destructive changes.",
	}
	if len(matches) == 0 {
		actions = append(actions, "Run log_analyze, alert_check, and incident_timeline to expand the evidence set.")
		return actions
	}

	switch matches[0].TechniqueID {
	case "T1110", "T1078":
		actions = append(actions,
			"Review authentication logs for source IP clustering, MFA outcomes, and impossible-travel indicators.",
			"Check access_review output for newly privileged or suspicious principals.",
		)
	case "T1552":
		actions = append(actions,
			"Run secret_audit to scope the exposed credentials and rotate affected secrets.",
			"Search for downstream usage of the exposed credentials in logs and CI systems.",
		)
	case "T1021":
		actions = append(actions,
			"Inspect remote access logs and session metadata for lateral movement paths.",
			"Constrain or revoke remote access for the suspected accounts until validation completes.",
		)
	case "T1070":
		actions = append(actions,
			"Check centralized audit and SIEM exports for evidence that was removed locally.",
			"Preserve host state and review shell history, auditd, and log forwarding health.",
		)
	default:
		actions = append(actions, "Correlate the top-ranked techniques with incident_timeline and alert_check before response escalation.")
	}

	return unique(actions)
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
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

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func round(v float64) float64 {
	return math.Round(v*100) / 100
}
