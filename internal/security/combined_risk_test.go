package security

import "testing"

func TestCombineDescriptorAndParameterRisk(t *testing.T) {
	t.Parallel()

	parameter := &RiskAssessment{
		Score:   25,
		Factors: []RiskFactor{{Name: "parameter", Weight: 25}},
	}
	combined := CombineRisk(40, parameter)

	if combined.Score != 65 {
		t.Fatalf("expected 40 descriptor + 25 parameter risk, got %d", combined.Score)
	}
	if combined.Level != RiskLevelHigh || combined.Action != RiskActionAdminReview {
		t.Fatalf("unexpected combined decision: %#v", combined)
	}
	if len(combined.Factors) != 2 {
		t.Fatalf("expected descriptor and parameter factors, got %#v", combined.Factors)
	}
}

func TestCombineRiskCapsAtOneHundred(t *testing.T) {
	t.Parallel()

	combined := CombineRisk(80, &RiskAssessment{Score: 50})
	if combined.Score != 100 || combined.Level != RiskLevelCritical {
		t.Fatalf("expected capped critical risk, got %#v", combined)
	}
}
