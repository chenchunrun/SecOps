package model

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/chenchunrun/SecOps/internal/agent"
	"github.com/chenchunrun/SecOps/internal/agent/tools/secops"
	"github.com/chenchunrun/SecOps/internal/app"
	"github.com/chenchunrun/SecOps/internal/audit"
	"github.com/chenchunrun/SecOps/internal/bootstrap"
	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/chenchunrun/SecOps/internal/investigation/scan"
	"github.com/chenchunrun/SecOps/internal/permission"
	"github.com/chenchunrun/SecOps/internal/question"
	"github.com/chenchunrun/SecOps/internal/security"
	"github.com/chenchunrun/SecOps/internal/session"
	"github.com/chenchunrun/SecOps/internal/ui/common"
	"github.com/chenchunrun/SecOps/internal/ui/dialog"
	"github.com/chenchunrun/SecOps/internal/ui/util"
	"github.com/stretchr/testify/require"
)

type scanTestCoordinator struct{ agent.Coordinator }

type scanTestSessions struct{ session.Service }

func (scanTestSessions) Create(context.Context, string) (session.Session, error) {
	return session.Session{ID: "ui-scan"}, nil
}

func (scanTestCoordinator) ActiveAgentID() string { return config.AgentSecurityExpertAgent }

type scanTestScanner struct{}

func (scanTestScanner) ExecuteContext(_ context.Context, input interface{}) (interface{}, error) {
	p := input.(*secops.SecurityScanParams)
	return &secops.ScanResult{Scanner: secops.ScannerTrivy, Target: p.TargetPath, ScanTime: time.Now(), Vulnerabilities: []*secops.Vulnerability{}}, nil
}

func TestScanCommandsEndToEnd(t *testing.T) { verifyScanCommands(t, scanTestScanner{}) }

func TestScanFormsEndToEnd(t *testing.T) { verifyScanFlow(t, scanTestScanner{}, true) }

func TestRealTrivyScanCommandsEndToEnd(t *testing.T) {
	if os.Getenv("SECOPS_TEST_TRIVY") != "1" {
		t.Skip("set SECOPS_TEST_TRIVY=1 and put trivy on PATH")
	}
	verifyScanCommands(t, secops.NewSecurityScanTool(nil))
}

// Verify the actual slash commands and scan-start callback without an LLM.
func verifyScanCommands(t *testing.T, scanner scan.Scanner) {
	verifyScanFlow(t, scanner, false)
}

func verifyScanFlow(t *testing.T, scanner scan.Scanner, forms bool) {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "project with spaces")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "requirements.txt"), []byte("Django==2.2.0\n"), 0o600))
	store, err := evidence.NewFileStore(filepath.Join(root, "evidence"))
	require.NoError(t, err)
	auditStore, err := audit.NewFileAuditStore(filepath.Join(root, "audit.jsonl"))
	require.NoError(t, err)
	audit.SetGlobalStore(auditStore)
	audit.SetGlobalWAL(nil)
	security.SetGlobalEngagementAuthorizationStore(security.NewInMemoryEngagementAuthorizationStore())
	t.Cleanup(func() {
		audit.SetGlobalStore(audit.NewInMemoryAuditStore())
		security.SetGlobalEngagementAuthorizationStore(nil)
	})
	permissions := permission.NewDefaultService()
	service, err := scan.New(filepath.Join(root, "tasks"), store, scanner, func(sessionID, subject, scope string) error {
		grant, ok := permissions.FindSessionCapability(sessionID, subject, "security:scan", scope)
		if !ok {
			return fmt.Errorf("authorization required")
		}
		return security.ValidateGlobalEngagementAuthorizationForSession(grant.AuthorizationID, "security:scan", scope, sessionID, time.Now())
	}, func(sessionID, taskID, action, target string) error {
		return audit.RecordGlobalDurable(audit.NewAuditEventBuilder(audit.EventTypeCommandExecuted).WithSession(sessionID).WithAction(action).WithResource("scan", taskID, target).Build())
	})
	require.NoError(t, err)
	defer service.Close()
	application := &app.App{Sessions: scanTestSessions{}, Scans: service, SecOpsPermissions: permissions, AgentCoordinator: scanTestCoordinator{}, ComputerRuntime: &bootstrap.ComputerRuntime{EvidenceStore: store}}
	ui := &UI{com: &common.Common{App: application}, dialog: dialog.NewOverlay()}
	command := func(input string) tea.Cmd {
		if !forms {
			return ui.applyScanCommand(input)
		}
		action, rest, _ := strings.Cut(input, " ")
		answers := question.Answers{}
		switch action {
		case "authorize", "run", "revoke":
			answers["directory"] = []string{rest}
		case "review":
			id, tail, _ := strings.Cut(rest, " ")
			verdict, reason, _ := strings.Cut(tail, " ")
			answers = question.Answers{"id": {id}, "verdict": {verdict}, "reason": {reason}}
		case "report":
			answers["id"] = []string{rest}
		default:
			return ui.applyScanCommand(input)
		}
		require.Nil(t, ui.openScanForm(action))
		r := ui.scanForm.request
		return ui.handleQuestionResponse(dialog.ActionQuestionResponse{ID: r.ID, SessionID: r.SessionID, Answers: answers})
	}
	created := ui.applyScanCommand("new")().(scanSessionCreatedMsg)
	require.Equal(t, "ui-scan", created.sessionID)
	ui.session = &session.Session{ID: created.sessionID}
	denied := command("run " + target)().(scanPreparedMsg)
	require.Error(t, denied.err)
	requireScanInfo(t, command("authorize "+target)())
	prepared := command("run " + target)().(scanPreparedMsg)
	require.NoError(t, prepared.err)
	batch := ui.handleScanPrepared(prepared)().(tea.BatchMsg)
	for _, command := range batch {
		requireScanInfo(t, command())
	}
	id := prepared.record.ID
	before := ui.applyScanCommand("show " + id)().(scanViewMsg)
	require.Contains(t, before.text, "awaiting_review")
	_, err = service.Report(t.Context(), "ui-scan", id)
	require.Error(t, err)
	requireScanInfo(t, command("review "+id+" passed Compared scanner output against dependency inventory")())
	after := ui.applyScanCommand("show " + id)().(scanViewMsg)
	require.Contains(t, after.text, "Reviewed report:")
	onlyReport := command("report " + id)().(scanViewMsg)
	require.Contains(t, onlyReport.text, "Reviewed report:")
	require.NotContains(t, onlyReport.text, "Scanner evidence:")
	report, err := service.Report(t.Context(), "ui-scan", id)
	require.NoError(t, err)
	require.NotEqual(t, report.Finding.MakerID, report.Verification.CheckerID)
	require.Len(t, report.Evidence, 1)
	if _, live := scanner.(*secops.SecurityScanTool); live {
		_, data, err := store.GetEvidence(t.Context(), report.Evidence[0].ID)
		require.NoError(t, err)
		var result secops.ScanResult
		require.NoError(t, json.Unmarshal(data, &result))
		require.Positive(t, result.TotalVulnerabilities)
		t.Logf("Stored and reviewed %d real Trivy findings", result.TotalVulnerabilities)
	}
	requireScanInfo(t, command("revoke "+target)())
	denied = command("run " + target)().(scanPreparedMsg)
	require.Error(t, denied.err)
	t.Logf("Validated TUI command lifecycle for scan %s", id)
}

func requireScanInfo(t *testing.T, msg tea.Msg) {
	t.Helper()
	info, ok := msg.(util.InfoMsg)
	require.True(t, ok)
	require.Equal(t, util.InfoTypeInfo, info.Type, info.Msg)
}
