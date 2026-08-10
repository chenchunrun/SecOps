// Package scheduler selects a trusted Computer for an authorized capability request.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/chenchunrun/SecOps/internal/computer"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/security"
)

var (
	ErrInvalidRequest        = errors.New("invalid scheduler request")
	ErrPermissionDenied      = errors.New("scheduler permission denied")
	ErrAuthorizationRequired = errors.New("scheduler authorization required")
	ErrRiskBlocked           = errors.New("scheduler risk blocked")
	ErrNoCandidate           = errors.New("scheduler has no eligible candidate")
	ErrAuditFailed           = errors.New("scheduler audit failed")
)

// Scope describes the execution environment required by a task. It is not a
// backend preference: policy maps the scope to eligible trusted Computers.
type Scope string

const (
	ScopeWorkspace Scope = "workspace"
	ScopeIsolated  Scope = "isolated"
	ScopeHost      Scope = "host"
	ScopeRemote    Scope = "remote"
)

// Outcome is the auditable terminal result of a scheduling attempt.
type Outcome string

const (
	OutcomeSelected    Outcome = "selected"
	OutcomeDenied      Outcome = "denied"
	OutcomePending     Outcome = "pending"
	OutcomeBlocked     Outcome = "blocked"
	OutcomeNoCandidate Outcome = "no_candidate"
)

// Authorization carries the permission engine's decision and records whether
// an external user or administrator approval has already been completed.
type Authorization struct {
	Decision permission.PermissionDecision
	Approved bool
}

// Request contains declarative execution requirements. It intentionally has no
// preferred backend or Computer field.
type Request struct {
	RequestID     string
	Capabilities  []string
	Scope         Scope
	Authorization Authorization
	Risk          *security.RiskAssessment
}

// Profile is trusted scheduler configuration for a registered Computer.
type Profile struct {
	ComputerID   computer.ID
	Capabilities []string
	Scopes       []Scope
}

// Decision explains why a scheduling request was or was not selected.
type Decision struct {
	RequestID    string           `json:"request_id"`
	Outcome      Outcome          `json:"outcome"`
	ComputerID   computer.ID      `json:"computer_id,omitempty"`
	Backend      computer.Backend `json:"backend,omitempty"`
	Capabilities []string         `json:"capabilities"`
	RiskScore    int              `json:"risk_score"`
	Reasons      []string         `json:"reasons"`
}

// Event is the immutable audit representation of a scheduling decision.
type Event struct {
	Decision           Decision
	PermissionDecision permission.PermissionDecision
}

// Observer persists scheduling decisions outside the selected runtime.
type Observer interface {
	Record(ctx context.Context, event Event) error
}

// Inventory supplies the currently registered Computers and their real state.
type Inventory interface {
	List() []computer.Computer
}

// Scheduler deterministically applies capability, permission, risk, lifecycle,
// and backend-isolation policy.
type Scheduler struct {
	inventory Inventory
	profiles  map[computer.ID]Profile
	observer  Observer
}

// New creates a Scheduler from trusted Computer profiles.
func New(inventory Inventory, profiles []Profile, observer Observer) (*Scheduler, error) {
	if inventory == nil {
		return nil, fmt.Errorf("%w: inventory is required", ErrInvalidRequest)
	}

	indexed := make(map[computer.ID]Profile, len(profiles))
	for _, profile := range profiles {
		if profile.ComputerID == "" || len(profile.Capabilities) == 0 || len(profile.Scopes) == 0 {
			return nil, fmt.Errorf("%w: incomplete profile", ErrInvalidRequest)
		}
		if _, exists := indexed[profile.ComputerID]; exists {
			return nil, fmt.Errorf("%w: duplicate profile %q", ErrInvalidRequest, profile.ComputerID)
		}
		profile.Capabilities = normalizeStrings(profile.Capabilities)
		profile.Scopes = normalizeScopes(profile.Scopes)
		indexed[profile.ComputerID] = profile
	}

	return &Scheduler{inventory: inventory, profiles: indexed, observer: observer}, nil
}

// Schedule returns an executable Computer only after all fail-closed checks and
// the decision audit have succeeded.
func (s *Scheduler) Schedule(ctx context.Context, request Request) (Decision, error) {
	decision := Decision{
		RequestID:    request.RequestID,
		Capabilities: normalizeStrings(request.Capabilities),
	}
	if request.Risk != nil {
		decision.RiskScore = request.Risk.Score
	}

	if request.RequestID == "" || len(decision.Capabilities) == 0 || !validScope(request.Scope) || request.Risk == nil {
		decision.Outcome = OutcomeDenied
		decision.Reasons = []string{"Request is missing required scheduler inputs."}
		return s.finish(ctx, decision, request.Authorization.Decision, ErrInvalidRequest)
	}
	if request.Authorization.Decision == permission.DecisionDeny {
		decision.Outcome = OutcomeDenied
		decision.Reasons = []string{"Permission engine denied the request."}
		return s.finish(ctx, decision, request.Authorization.Decision, ErrPermissionDenied)
	}
	if request.Risk.Action == security.RiskActionBlock || request.Risk.Level == security.RiskLevelCritical {
		decision.Outcome = OutcomeBlocked
		decision.Reasons = []string{"Risk engine blocked the request."}
		return s.finish(ctx, decision, request.Authorization.Decision, ErrRiskBlocked)
	}
	if !authorized(request.Authorization) || riskApprovalPending(request.Risk, request.Authorization) {
		decision.Outcome = OutcomePending
		decision.Reasons = []string{"Required user or administrator authorization has not completed."}
		return s.finish(ctx, decision, request.Authorization.Decision, ErrAuthorizationRequired)
	}

	candidates := s.eligibleCandidates(request, decision.Capabilities)
	if len(candidates) == 0 {
		decision.Outcome = OutcomeNoCandidate
		decision.Reasons = []string{"No active Computer satisfies every capability and scope requirement."}
		return s.finish(ctx, decision, request.Authorization.Decision, ErrNoCandidate)
	}

	sort.Slice(candidates, func(i, j int) bool {
		leftRank := backendRank(candidates[i].Backend(), request)
		rightRank := backendRank(candidates[j].Backend(), request)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return candidates[i].ID() < candidates[j].ID()
	})
	selected := candidates[0]
	decision.Outcome = OutcomeSelected
	decision.ComputerID = selected.ID()
	decision.Backend = selected.Backend()
	decision.Reasons = []string{
		"Candidate satisfies all trusted capability and scope constraints.",
		fmt.Sprintf("Backend %s has deterministic policy rank %d.", selected.Backend(), backendRank(selected.Backend(), request)),
	}
	return s.finish(ctx, decision, request.Authorization.Decision, nil)
}

func (s *Scheduler) eligibleCandidates(request Request, capabilities []string) []computer.Computer {
	var candidates []computer.Computer
	for _, candidate := range s.inventory.List() {
		if candidate == nil || !runnableState(candidate.State()) {
			continue
		}
		profile, exists := s.profiles[candidate.ID()]
		if !exists || !supportsScope(profile.Scopes, request.Scope) || !supportsCapabilities(profile.Capabilities, capabilities) {
			continue
		}
		if !backendSupportsScope(candidate.Backend(), request.Scope) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func (s *Scheduler) finish(
	ctx context.Context,
	decision Decision,
	permissionDecision permission.PermissionDecision,
	resultErr error,
) (Decision, error) {
	if s.observer == nil {
		return decision, resultErr
	}
	if err := s.observer.Record(ctx, Event{Decision: decision, PermissionDecision: permissionDecision}); err != nil {
		return Decision{
			RequestID:    decision.RequestID,
			Outcome:      OutcomeDenied,
			Capabilities: decision.Capabilities,
			RiskScore:    decision.RiskScore,
			Reasons:      []string{"Scheduler audit could not be persisted."},
		}, fmt.Errorf("%w: %v", ErrAuditFailed, err)
	}
	return decision, resultErr
}

func authorized(authorization Authorization) bool {
	return authorization.Approved || authorization.Decision == permission.DecisionAutoApprove
}

func riskApprovalPending(risk *security.RiskAssessment, authorization Authorization) bool {
	if authorization.Approved {
		return false
	}
	return risk.Action == security.RiskActionAdminReview || risk.Action == security.RiskActionUserConfirm
}

func runnableState(state computer.State) bool {
	return state == computer.StateActive || state == computer.StateCompleted
}

func validScope(scope Scope) bool {
	switch scope {
	case ScopeWorkspace, ScopeIsolated, ScopeHost, ScopeRemote:
		return true
	default:
		return false
	}
}

func backendSupportsScope(backend computer.Backend, scope Scope) bool {
	switch scope {
	case ScopeHost:
		return backend == computer.BackendLocal
	case ScopeIsolated:
		return backend == computer.BackendDocker
	case ScopeRemote:
		return backend == computer.BackendSSH
	case ScopeWorkspace:
		return backend == computer.BackendLocal || backend == computer.BackendDocker || backend == computer.BackendSSH
	default:
		return false
	}
}

func backendRank(backend computer.Backend, request Request) int {
	if request.Scope == ScopeHost && backend == computer.BackendLocal ||
		request.Scope == ScopeIsolated && backend == computer.BackendDocker ||
		request.Scope == ScopeRemote && backend == computer.BackendSSH {
		return 0
	}

	preferIsolation := request.Risk.Score >= 40 ||
		request.Risk.Action != security.RiskActionAutoApprove ||
		capabilitiesMutate(request.Capabilities)
	if preferIsolation {
		switch backend {
		case computer.BackendDocker:
			return 0
		case computer.BackendSSH:
			return 1
		case computer.BackendLocal:
			return 2
		}
	}
	switch backend {
	case computer.BackendLocal:
		return 0
	case computer.BackendDocker:
		return 1
	case computer.BackendSSH:
		return 2
	default:
		return 3
	}
}

func capabilitiesMutate(capabilities []string) bool {
	readOnly := map[string]struct{}{
		security.CapabilityFileRead:         {},
		security.CapabilityLogRead:          {},
		security.CapabilityLogAnalyze:       {},
		security.CapabilityMonitoringQuery:  {},
		security.CapabilityComplianceCheck:  {},
		security.CapabilityComplianceReport: {},
		security.CapabilitySecurityAudit:    {},
		security.CapabilitySecurityAnalyze:  {},
		security.CapabilityNetworkDiag:      {},
		security.CapabilityNetworkTrace:     {},
		security.CapabilityShellReadOnly:    {},
		security.CapabilityProcessQuery:     {},
		security.CapabilityDatabaseQuery:    {},
		security.CapabilityRedTeamRecon:     {},
	}
	for _, capability := range capabilities {
		if _, exists := readOnly[capability]; !exists {
			return true
		}
	}
	return false
}

func supportsCapabilities(supported, required []string) bool {
	allowed := make(map[string]struct{}, len(supported))
	for _, capability := range supported {
		allowed[capability] = struct{}{}
	}
	if _, wildcard := allowed["*"]; wildcard {
		return true
	}
	for _, capability := range required {
		if _, exists := allowed[capability]; !exists {
			return false
		}
	}
	return true
}

func supportsScope(scopes []Scope, required Scope) bool {
	for _, scope := range scopes {
		if scope == required {
			return true
		}
	}
	return false
}

func normalizeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

func normalizeScopes(values []Scope) []Scope {
	seen := make(map[Scope]struct{}, len(values))
	normalized := make([]Scope, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i] < normalized[j] })
	return normalized
}
