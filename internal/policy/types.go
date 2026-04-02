package policy

import "context"

type Request struct {
	PolicyKind   string
	SessionID    string
	ToolCallID   string
	ToolName     string
	Action       string
	Description  string
	WorkingDir   string
	RemoteTarget string
	Role         string

	RequiredCaps []string
	RiskTags     []string

	Parameters any
}

type Decision struct {
	Allowed          bool
	RequiresApproval bool
	Reason           string
	AuditFields      map[string]any
}

type Decider interface {
	Decide(ctx context.Context, req Request) (Decision, error)
}
