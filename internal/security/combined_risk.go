package security

import "fmt"

// CombineRisk adds deterministic descriptor risk to parameter-derived risk.
func CombineRisk(descriptorBase int, parameter *RiskAssessment) *RiskAssessment {
	if descriptorBase < 0 {
		descriptorBase = 0
	}
	combined := &RiskAssessment{}
	if parameter != nil {
		*combined = *parameter
		combined.Factors = append([]RiskFactor(nil), parameter.Factors...)
	}
	if descriptorBase > 0 {
		combined.Factors = append([]RiskFactor{{
			Name:     "descriptor_base_risk",
			Weight:   descriptorBase,
			Evidence: fmt.Sprintf("tool descriptor contributes %d base risk points", descriptorBase),
		}}, combined.Factors...)
	}
	combined.Score += descriptorBase
	if combined.Score > 100 {
		combined.Score = 100
	}
	NewRiskAssessor().categorizeRisk(combined)
	return combined
}
