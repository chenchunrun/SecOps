package agent

import (
	"testing"

	capregistry "github.com/chenchunrun/SecOps/internal/capability/registry"
	"github.com/chenchunrun/SecOps/internal/security"
)

func TestAdapterRiskCombinesDescriptorAndParameters(t *testing.T) {
	t.Parallel()

	adapter := &Adapter{
		tool:     &testSecOpsTool{},
		assessor: security.NewRiskAssessor(),
		registry: capregistry.NewSecOpsRegistry(),
	}
	risk := adapter.assessRisk(`{"command":"cat /etc/shadow"}`)

	if risk.Score < 35 {
		t.Fatalf("expected descriptor base plus sensitive parameter risk, got %#v", risk)
	}
	if len(risk.Factors) < 2 || risk.Factors[0].Name != "descriptor_base_risk" {
		t.Fatalf("expected descriptor factor followed by parameter factors, got %#v", risk.Factors)
	}
}
