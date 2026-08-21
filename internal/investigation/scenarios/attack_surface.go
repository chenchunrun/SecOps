package scenarios

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/chenchunrun/SecOps/internal/evidence"
)

type AuthorizationScope struct {
	ID                    string    `json:"id"`
	Domains               []string  `json:"domains"`
	CIDRs                 []string  `json:"cidrs"`
	Ports                 []int     `json:"ports"`
	ValidFrom             time.Time `json:"valid_from"`
	ValidUntil            time.Time `json:"valid_until"`
	AllowActiveValidation bool      `json:"allow_active_validation"`
}

type SignedScope struct {
	Scope     AuthorizationScope `json:"scope"`
	Signature []byte             `json:"signature"`
}

func SignAuthorizationScope(scope AuthorizationScope, privateKey ed25519.PrivateKey) (SignedScope, error) {
	payload, err := json.Marshal(scope)
	if err != nil {
		return SignedScope{}, err
	}
	return SignedScope{Scope: scope, Signature: ed25519.Sign(privateKey, payload)}, nil
}

func (s SignedScope) Verify(publicKey ed25519.PublicKey, now time.Time) error {
	payload, err := json.Marshal(s.Scope)
	if err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payload, s.Signature) {
		return errors.New("authorization scope signature is invalid")
	}
	if now.Before(s.Scope.ValidFrom) || !now.Before(s.Scope.ValidUntil) {
		return errors.New("authorization scope is outside its time window")
	}
	return nil
}

type AttackTarget struct {
	Host string
	Port int
}

type ProbeRequest struct {
	Target      AttackTarget
	Ephemeral   bool
	Destructive bool
	Active      bool
}

type ProbeResult struct {
	AttackPath string `json:"attack_path"`
	Confirmed  bool   `json:"confirmed"`
	Raw        []byte `json:"-"`
}

type AttackSurfaceProbe interface {
	Probe(context.Context, ProbeRequest) (ProbeResult, error)
	Retest(context.Context, ProbeRequest) (ProbeResult, error)
}

type KillSwitch interface {
	Triggered() bool
}

type AttackSurfaceInput struct {
	TaskID    string
	Target    AttackTarget
	Scope     SignedScope
	PublicKey ed25519.PublicKey
	MakerID   string
	CheckerID string
	Active    bool
	Retest    bool
}

type AttackSurfaceReport struct {
	TaskID       string
	FindingID    string
	EvidenceIDs  []string
	Confirmed    bool
	Retested     bool
	Verification evidence.Verdict
}

type AttackSurfaceWorkflow struct {
	store      *evidence.FileStore
	probe      AttackSurfaceProbe
	killSwitch KillSwitch
	auditor    ScenarioAuditor
	now        func() time.Time
}

func NewAttackSurfaceWorkflow(store *evidence.FileStore, probe AttackSurfaceProbe, killSwitch KillSwitch, auditor ScenarioAuditor) (*AttackSurfaceWorkflow, error) {
	if store == nil || probe == nil || killSwitch == nil || auditor == nil {
		return nil, errors.New("initialize attack surface workflow: dependencies are required")
	}
	return &AttackSurfaceWorkflow{store: store, probe: probe, killSwitch: killSwitch, auditor: auditor, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (w *AttackSurfaceWorkflow) Run(ctx context.Context, input AttackSurfaceInput) (AttackSurfaceReport, error) {
	if input.TaskID == "" || input.Target.Host == "" || input.Target.Port < 1 || input.MakerID == "" || input.CheckerID == "" {
		return AttackSurfaceReport{}, errors.New("run attack surface workflow: invalid input")
	}
	if err := input.Scope.Verify(input.PublicKey, w.now()); err != nil {
		return AttackSurfaceReport{}, err
	}
	if !targetInScope(input.Target, input.Scope.Scope) {
		return AttackSurfaceReport{}, errors.New("target is outside signed authorization scope")
	}
	if input.Active && !input.Scope.Scope.AllowActiveValidation {
		return AttackSurfaceReport{}, errors.New("active validation is not authorized")
	}
	if w.killSwitch.Triggered() {
		return AttackSurfaceReport{}, errors.New("attack surface kill switch is active")
	}
	request := ProbeRequest{Target: input.Target, Ephemeral: true, Destructive: false, Active: input.Active}
	if err := w.auditor.Record(ctx, ScenarioAuditEvent{TaskID: input.TaskID, Action: "authorized_attack_surface_probe", Target: fmt.Sprintf("%s:%d", input.Target.Host, input.Target.Port), ApprovalID: input.Scope.Scope.ID}); err != nil {
		return AttackSurfaceReport{}, fmt.Errorf("audit attack surface probe: %w", err)
	}
	probeResult, err := w.probe.Probe(ctx, request)
	if err != nil {
		return AttackSurfaceReport{}, fmt.Errorf("probe authorized target: %w", err)
	}
	probeEvidence, err := w.persistProbe(ctx, input.TaskID+"-probe", input, "initial_probe", probeResult)
	if err != nil {
		return AttackSurfaceReport{}, err
	}
	report := AttackSurfaceReport{
		TaskID: input.TaskID, FindingID: input.TaskID + "-attack-finding",
		EvidenceIDs: []string{probeEvidence.ID}, Confirmed: probeResult.Confirmed,
	}
	if input.Retest {
		if w.killSwitch.Triggered() {
			return AttackSurfaceReport{}, errors.New("attack surface kill switch activated before retest")
		}
		retestResult, err := w.probe.Retest(ctx, request)
		if err != nil {
			return AttackSurfaceReport{}, fmt.Errorf("retest authorized target: %w", err)
		}
		retestEvidence, err := w.persistProbe(ctx, input.TaskID+"-retest", input, "remediation_retest", retestResult)
		if err != nil {
			return AttackSurfaceReport{}, err
		}
		report.EvidenceIDs = append(report.EvidenceIDs, retestEvidence.ID)
		report.Retested = true
	}
	factID := input.TaskID + "-attack-fact"
	statement := "Authorized probe completed without destructive actions."
	if probeResult.Confirmed {
		statement = "Authorized probe produced a confirmed attack path."
	}
	if err := w.store.PutFact(ctx, evidence.Fact{ID: factID, TaskID: input.TaskID, Statement: statement, EvidenceIDs: []string{probeEvidence.ID}}); err != nil {
		return AttackSurfaceReport{}, err
	}
	severity := evidence.SeverityMedium
	if probeResult.Confirmed {
		severity = evidence.SeverityHigh
	}
	if err := w.store.PutFinding(ctx, evidence.Finding{
		ID: report.FindingID, TaskID: input.TaskID, MakerID: input.MakerID, Severity: severity,
		FactIDs: []string{factID}, Recommendation: "Remediate the confirmed path and validate with an authorized retest.",
	}); err != nil {
		return AttackSurfaceReport{}, err
	}
	if err := w.store.VerifyFinding(ctx, evidence.Verification{
		FindingID: report.FindingID, TaskID: input.TaskID, CheckerID: input.CheckerID,
		Verdict: evidence.VerdictPassed, EvidenceIDs: report.EvidenceIDs,
		Reason: "signed scope, non-destructive probe, attack-path evidence, and retest evidence verified",
	}); err != nil {
		return AttackSurfaceReport{}, err
	}
	report.Verification = evidence.VerdictPassed
	return report, nil
}

func (w *AttackSurfaceWorkflow) persistProbe(ctx context.Context, id string, input AttackSurfaceInput, phase string, result ProbeResult) (evidence.Evidence, error) {
	raw := result.Raw
	if len(raw) == 0 {
		raw, _ = json.Marshal(result)
	}
	item, err := w.store.PutEvidence(ctx, evidence.Evidence{
		ID: id, TaskID: input.TaskID,
		Source:  evidence.EvidenceSource{Type: phase, Reference: fmt.Sprintf("%s:%d", input.Target.Host, input.Target.Port)},
		Summary: phase + " result", TrustLevel: evidence.TrustHigh, Completeness: evidence.CompletenessComplete,
	}, raw)
	if err != nil {
		return evidence.Evidence{}, fmt.Errorf("persist %s evidence: %w", phase, err)
	}
	return item, nil
}

func targetInScope(target AttackTarget, scope AuthorizationScope) bool {
	portAllowed := false
	for _, port := range scope.Ports {
		if port == target.Port {
			portAllowed = true
			break
		}
	}
	if !portAllowed {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(target.Host, "."))
	for _, domain := range scope.Domains {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range scope.CIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
