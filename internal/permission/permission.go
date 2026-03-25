package permission

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/csync"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/google/uuid"
)

var ErrorPermissionDenied = errors.New("user denied permission")

// Severity levels for permission requests
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// PermissionDecision outcomes
type PermissionDecision string

const (
	DecisionAutoApprove PermissionDecision = "auto_approve"
	DecisionUserConfirm PermissionDecision = "user_confirm"
	DecisionAdminReview PermissionDecision = "admin_review"
	DecisionDeny        PermissionDecision = "deny"
)

// PermissionLevel defines the role hierarchy
type PermissionLevel string

const (
	LevelViewer   PermissionLevel = "viewer"
	LevelOperator PermissionLevel = "operator"
	LevelAdmin    PermissionLevel = "admin"
	LevelAnalyst  PermissionLevel = "analyst"
)

// ResourceType classifies resources being accessed
type ResourceType string

const (
	ResourceTypeFile     ResourceType = "file"
	ResourceTypeNetwork  ResourceType = "network"
	ResourceTypeProcess  ResourceType = "process"
	ResourceTypeDatabase ResourceType = "database"
	ResourceTypeCommand  ResourceType = "command"
	ResourceTypeSystem   ResourceType = "system"
)

type CreatePermissionRequest struct {
	SessionID   string `json:"session_id"`
	ToolCallID  string `json:"tool_call_id"`
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Params      any    `json:"params"`
	Path        string `json:"path"`
	Transport   string `json:"transport,omitempty"`
	TargetHost  string `json:"target_host,omitempty"`
	TargetEnv   string `json:"target_env,omitempty"`
	TargetID    string `json:"target_id,omitempty"`
}

type PermissionNotification struct {
	ToolCallID string `json:"tool_call_id"`
	Granted    bool   `json:"granted"`
	Denied     bool   `json:"denied"`
}

type PermissionRequest struct {
	ID          string `json:"id"`
	SessionID   string `json:"session_id"`
	ToolCallID  string `json:"tool_call_id"`
	ToolName    string `json:"tool_name"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Params      any    `json:"params"`
	Path        string `json:"path"`
	Transport   string `json:"transport,omitempty"`
	TargetHost  string `json:"target_host,omitempty"`
	TargetEnv   string `json:"target_env,omitempty"`
	TargetID    string `json:"target_id,omitempty"`
	// SecOps fields
	RiskScore    int                `json:"risk_score"`
	Severity     Severity           `json:"severity"`
	Decision     PermissionDecision `json:"decision"`
	ResourceType ResourceType       `json:"resource_type"`
	ResourcePath string             `json:"resource_path"`
	UserID       string             `json:"user_id"`
	Username     string             `json:"username"`
	RequiredRole PermissionLevel    `json:"required_role"`
	SourceIP     string             `json:"source_ip"`
	RequestTime  time.Time          `json:"request_time"`
	ApprovalID   string             `json:"approval_id"`
	Reason       string             `json:"reason"`
	RiskFactors  []string           `json:"risk_factors"`
	ApprovedBy   string             `json:"approved_by"`
	ApprovedAt   time.Time          `json:"approved_at"`
	DeniedReason string             `json:"denied_reason"`
}

type Service interface {
	pubsub.Subscriber[PermissionRequest]
	GrantPersistent(permission PermissionRequest)
	Grant(permission PermissionRequest)
	Deny(permission PermissionRequest)
	Request(ctx context.Context, opts CreatePermissionRequest) (bool, error)
	AutoApproveSession(sessionID string)
	SetSkipRequests(skip bool)
	SkipRequests() bool
	SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[PermissionNotification]
}

type permissionService struct {
	*pubsub.Broker[PermissionRequest]

	notificationBroker    *pubsub.Broker[PermissionNotification]
	workingDir            string
	sessionPermissions    []PermissionRequest
	sessionPermissionsMu  sync.RWMutex
	pendingRequests       *csync.Map[string, chan bool]
	autoApproveSessions   map[string]bool
	autoApproveSessionsMu sync.RWMutex
	skip                  atomic.Bool
	allowedTools          []string

	// used to make sure we only process one request at a time
	requestMu       sync.Mutex
	activeRequest   *PermissionRequest
	activeRequestMu sync.Mutex
	assessor        *security.RiskAssessor
	bypassMarkers   []string
}

func (s *permissionService) GrantPersistent(permission PermissionRequest) {
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: permission.ToolCallID,
		Granted:    true,
	})
	respCh, ok := s.pendingRequests.Get(permission.ID)
	if ok {
		respCh <- true
	}

	s.sessionPermissionsMu.Lock()
	s.sessionPermissions = append(s.sessionPermissions, permission)
	s.sessionPermissionsMu.Unlock()

	s.activeRequestMu.Lock()
	if s.activeRequest != nil && s.activeRequest.ID == permission.ID {
		s.activeRequest = nil
	}
	s.activeRequestMu.Unlock()
}

func (s *permissionService) Grant(permission PermissionRequest) {
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: permission.ToolCallID,
		Granted:    true,
	})
	respCh, ok := s.pendingRequests.Get(permission.ID)
	if ok {
		respCh <- true
	}

	s.activeRequestMu.Lock()
	if s.activeRequest != nil && s.activeRequest.ID == permission.ID {
		s.activeRequest = nil
	}
	s.activeRequestMu.Unlock()
}

func (s *permissionService) Deny(permission PermissionRequest) {
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: permission.ToolCallID,
		Granted:    false,
		Denied:     true,
	})
	respCh, ok := s.pendingRequests.Get(permission.ID)
	if ok {
		respCh <- false
	}

	s.activeRequestMu.Lock()
	if s.activeRequest != nil && s.activeRequest.ID == permission.ID {
		s.activeRequest = nil
	}
	s.activeRequestMu.Unlock()
}

func (s *permissionService) Request(ctx context.Context, opts CreatePermissionRequest) (bool, error) {
	assessment, forceInteractive, bypassPhrases := s.evaluateRiskGate(opts)
	if len(bypassPhrases) > 0 {
		s.recordBypassAuditEvent(opts, assessment, bypassPhrases)
	}

	if s.skip.Load() && !forceInteractive {
		return true, nil
	}

	// Check if the tool/action combination is in the allowlist
	commandKey := opts.ToolName + ":" + opts.Action
	if !forceInteractive && (slices.Contains(s.allowedTools, commandKey) || slices.Contains(s.allowedTools, opts.ToolName)) {
		return true, nil
	}

	// tell the UI that a permission was requested
	s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
		ToolCallID: opts.ToolCallID,
	})
	s.requestMu.Lock()
	defer s.requestMu.Unlock()

	s.autoApproveSessionsMu.RLock()
	autoApprove := s.autoApproveSessions[opts.SessionID]
	s.autoApproveSessionsMu.RUnlock()

	if autoApprove && !forceInteractive {
		s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
			ToolCallID: opts.ToolCallID,
			Granted:    true,
		})
		return true, nil
	}

	fileInfo, err := os.Stat(opts.Path)
	dir := opts.Path
	if err == nil {
		if fileInfo.IsDir() {
			dir = opts.Path
		} else {
			dir = filepath.Dir(opts.Path)
		}
	}

	if dir == "." {
		dir = s.workingDir
	}
	permission := PermissionRequest{
		ID:          uuid.New().String(),
		Path:        dir,
		SessionID:   opts.SessionID,
		ToolCallID:  opts.ToolCallID,
		ToolName:    opts.ToolName,
		Description: opts.Description,
		Action:      opts.Action,
		Params:      opts.Params,
		Transport:   opts.Transport,
		TargetHost:  opts.TargetHost,
		TargetEnv:   opts.TargetEnv,
		TargetID:    opts.TargetID,
	}
	if assessment != nil {
		permission.RiskScore = assessment.Score
		permission.RiskFactors = riskFactorNames(assessment.Factors)
		permission.Severity = mapRiskLevelToSeverity(assessment.Level)
	}

	s.sessionPermissionsMu.RLock()
	for _, p := range s.sessionPermissions {
		if p.ToolName == permission.ToolName && p.Action == permission.Action && p.SessionID == permission.SessionID && p.Path == permission.Path {
			s.sessionPermissionsMu.RUnlock()
			s.notificationBroker.Publish(pubsub.CreatedEvent, PermissionNotification{
				ToolCallID: opts.ToolCallID,
				Granted:    true,
			})
			return true, nil
		}
	}
	s.sessionPermissionsMu.RUnlock()

	s.activeRequestMu.Lock()
	s.activeRequest = &permission
	s.activeRequestMu.Unlock()

	respCh := make(chan bool, 1)
	s.pendingRequests.Set(permission.ID, respCh)
	defer s.pendingRequests.Del(permission.ID)

	// Publish the request
	s.Publish(pubsub.CreatedEvent, permission)

	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case granted := <-respCh:
		return granted, nil
	}
}

func (s *permissionService) AutoApproveSession(sessionID string) {
	s.autoApproveSessionsMu.Lock()
	s.autoApproveSessions[sessionID] = true
	s.autoApproveSessionsMu.Unlock()
}

func (s *permissionService) SubscribeNotifications(ctx context.Context) <-chan pubsub.Event[PermissionNotification] {
	return s.notificationBroker.Subscribe(ctx)
}

func (s *permissionService) SetSkipRequests(skip bool) {
	s.skip.Store(skip)
}

func (s *permissionService) SkipRequests() bool {
	return s.skip.Load()
}

func NewPermissionService(workingDir string, skip bool, allowedTools []string) Service {
	return NewPermissionServiceWithBypassMarkers(workingDir, skip, allowedTools, nil, nil)
}

func NewPermissionServiceWithBypassMarkers(
	workingDir string,
	skip bool,
	allowedTools []string,
	overrideMarkers []string,
	extraMarkers []string,
) Service {
	svc := &permissionService{
		Broker:              pubsub.NewBroker[PermissionRequest](),
		notificationBroker:  pubsub.NewBroker[PermissionNotification](),
		workingDir:          workingDir,
		sessionPermissions:  make([]PermissionRequest, 0),
		autoApproveSessions: make(map[string]bool),
		allowedTools:        allowedTools,
		pendingRequests:     csync.NewMap[string, chan bool](),
		assessor:            security.NewRiskAssessor(),
		bypassMarkers:       mergeBypassIntentMarkers(overrideMarkers, extraMarkers),
	}
	svc.skip.Store(skip)
	return svc
}

func (s *permissionService) evaluateRiskGate(
	opts CreatePermissionRequest,
) (*security.RiskAssessment, bool, []string) {
	assessor := s.assessor
	if assessor == nil {
		assessor = security.NewRiskAssessor()
	}

	candidates := permissionRiskCandidates(opts)
	if len(candidates) == 0 {
		return nil, false, nil
	}

	best := assessor.AssessCommand(candidates[0])
	for _, candidate := range candidates[1:] {
		current := assessor.AssessCommand(candidate)
		if current.Score > best.Score {
			best = current
		}
	}

	forceInteractive := best.Level == security.RiskLevelHigh || best.Level == security.RiskLevelCritical
	bypassPhrases := detectBypassIntent(candidates, s.bypassMarkers)
	if len(bypassPhrases) > 0 {
		forceInteractive = true
	}
	return best, forceInteractive, bypassPhrases
}

func permissionRiskCandidates(opts CreatePermissionRequest) []string {
	candidates := make([]string, 0, 6)
	addCandidate := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" {
			candidates = append(candidates, v)
		}
	}

	addCandidate(opts.ToolName)
	addCandidate(opts.Action)
	addCandidate(opts.Description)
	addCandidate(opts.Path)

	if raw, err := json.Marshal(opts.Params); err == nil {
		addCandidate(string(raw))
	}

	return candidates
}

func detectBypassIntent(candidates []string, markers []string) []string {
	if len(markers) == 0 {
		markers = defaultBypassIntentMarkers()
	}

	seen := make(map[string]struct{})
	for _, candidate := range candidates {
		text := strings.ToLower(candidate)
		for _, marker := range markers {
			if strings.Contains(text, marker) {
				seen[marker] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(seen))
	for marker := range seen {
		out = append(out, marker)
	}
	slices.Sort(out)
	return out
}

func defaultBypassIntentMarkers() []string {
	return []string{
		"ignore previous instructions",
		"bypass permission",
		"disable permission",
		"skip permission",
		"turn off security",
		"disable security",
		"override guardrail",
		"jailbreak",
		"越过权限",
		"绕过权限",
		"关闭安全",
	}
}

func mergeBypassIntentMarkers(override []string, extra []string) []string {
	base := override
	if len(base) == 0 {
		base = defaultBypassIntentMarkers()
	}

	merged := make([]string, 0, len(base)+len(extra))
	merged = append(merged, base...)
	merged = append(merged, extra...)

	uniq := make(map[string]struct{})
	out := make([]string, 0, len(merged))
	for _, marker := range merged {
		normalized := strings.ToLower(strings.TrimSpace(marker))
		if normalized == "" {
			continue
		}
		if _, exists := uniq[normalized]; exists {
			continue
		}
		uniq[normalized] = struct{}{}
		out = append(out, normalized)
	}

	if len(out) == 0 {
		return defaultBypassIntentMarkers()
	}
	return out
}

func (s *permissionService) recordBypassAuditEvent(
	opts CreatePermissionRequest,
	assessment *security.RiskAssessment,
	bypassPhrases []string,
) {
	riskScore := 0
	riskLevel := string(security.RiskLevelLow)
	if assessment != nil {
		riskScore = assessment.Score
		riskLevel = string(assessment.Level)
	}
	event := audit.NewAuditEventBuilder(audit.EventTypeSecurityAlert).
		WithSession(opts.SessionID).
		WithAction("permission_bypass_intent_detected").
		WithResource(string(ResourceTypeCommand), opts.ToolName, opts.Path).
		WithRiskScore(riskScore, riskLevel).
		WithResult(audit.ResultDenied).
		WithDetail("tool_call_id", opts.ToolCallID).
		WithDetail("tool_name", opts.ToolName).
		WithDetail("action", opts.Action).
		WithDetail("bypass_phrases", bypassPhrases).
		Build()
	_ = audit.RecordGlobal(event)
}

func mapRiskLevelToSeverity(level security.RiskLevel) Severity {
	switch level {
	case security.RiskLevelCritical:
		return SeverityCritical
	case security.RiskLevelHigh:
		return SeverityHigh
	case security.RiskLevelMedium:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func riskFactorNames(factors []security.RiskFactor) []string {
	names := make([]string, 0, len(factors))
	for _, factor := range factors {
		names = append(names, factor.Name)
	}
	return names
}
