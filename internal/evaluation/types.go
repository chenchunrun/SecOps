// Package evaluation provides deterministic, offline security-agent evaluations.
package evaluation

type Scenario struct {
	ID                   string          `json:"id"`
	Category             string          `json:"category"`
	Input                ScenarioInput   `json:"input"`
	ExpectedFacts        []ExpectedFact  `json:"expected_facts"`
	ProhibitedOperations []string        `json:"prohibited_operations"`
	SuccessCriteria      SuccessCriteria `json:"success_criteria"`
	ToolResponses        []ToolResponse  `json:"tool_responses"`
	ModelResponse        ModelResponse   `json:"model_response"`
}

type ScenarioInput struct {
	Summary                  string `json:"summary"`
	ContainsPromptInjection  bool   `json:"contains_prompt_injection"`
	AuditAvailable           bool   `json:"audit_available"`
	AuthorizationScopeSigned bool   `json:"authorization_scope_signed"`
}

type ExpectedFact struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
}

type SuccessCriteria struct {
	MinimumFactCoverage     float64 `json:"minimum_fact_coverage"`
	MinimumEvidenceCoverage float64 `json:"minimum_evidence_coverage"`
	MaximumUnsupportedRate  float64 `json:"maximum_unsupported_rate"`
	MaximumSafetyViolations int     `json:"maximum_safety_violations"`
}

type ToolResponse struct {
	Tool       string `json:"tool"`
	EvidenceID string `json:"evidence_id"`
	Status     string `json:"status"`
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

type ModelResponse struct {
	Completed                 bool     `json:"completed"`
	Claims                    []Claim  `json:"claims"`
	Actions                   []Action `json:"actions"`
	UsedUntrustedInstructions bool     `json:"used_untrusted_instructions"`
}

type Claim struct {
	FactID      string   `json:"fact_id"`
	Statement   string   `json:"statement"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Action struct {
	Operation      string `json:"operation"`
	Risk           string `json:"risk"`
	Authorized     bool   `json:"authorized"`
	SideEffect     bool   `json:"side_effect"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type Result struct {
	ScenarioID                   string   `json:"scenario_id"`
	Passed                       bool     `json:"passed"`
	TaskCompleted                bool     `json:"task_completed"`
	FactCoverage                 float64  `json:"fact_coverage"`
	EvidenceCoverage             float64  `json:"evidence_coverage"`
	UnsupportedClaimRate         float64  `json:"unsupported_claim_rate"`
	SafetyViolations             int      `json:"safety_violations"`
	DuplicateSideEffects         int      `json:"duplicate_side_effects"`
	PromptInjectionBreakthroughs int      `json:"prompt_injection_breakthroughs"`
	UnauthorizedHighRiskActions  int      `json:"unauthorized_high_risk_actions"`
	FabricatedToolFailureClaims  int      `json:"fabricated_tool_failure_claims"`
	Failures                     []string `json:"failures,omitempty"`
}

type Summary struct {
	ScenarioCount        int     `json:"scenario_count"`
	TaskCompletionRate   float64 `json:"task_completion_rate"`
	EvidenceCoverage     float64 `json:"evidence_coverage"`
	UnsupportedClaimRate float64 `json:"unsupported_claim_rate"`
	SafetyViolations     int     `json:"safety_violations"`
	PassedScenarios      int     `json:"passed_scenarios"`
}
