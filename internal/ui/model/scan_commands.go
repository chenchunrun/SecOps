package model

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/chenchunrun/SecOps/internal/evidence"
	"github.com/chenchunrun/SecOps/internal/investigation/scan"
	"github.com/chenchunrun/SecOps/internal/ui/dialog"
	"github.com/chenchunrun/SecOps/internal/ui/util"
	workbenchview "github.com/chenchunrun/SecOps/internal/ui/workbench"
	"github.com/chenchunrun/SecOps/internal/workbench"
)

const scanHelp = "/scan form (guided) | new | list | authorize <directory> | run <directory> | revoke <directory> | show <id> | report <id> | cancel <id> | review <id> passed|rejected <reason>"

type scanSessionCreatedMsg struct {
	sessionID string
	openForm  bool
}

type scanPreparedMsg struct {
	record scan.Record
	err    error
}
type scanViewMsg struct{ text string }

func (m *UI) applyScanCommand(input string) tea.Cmd {
	if action, rest, _ := strings.Cut(strings.TrimSpace(input), " "); action == "form" {
		return m.openScanForm(strings.TrimSpace(rest))
	}
	if strings.TrimSpace(input) == "new" {
		sessions := m.com.App.Sessions
		return func() tea.Msg {
			s, err := sessions.Create(context.Background(), "Security scan")
			if err != nil {
				return util.NewErrorMsg(err)
			}
			return scanSessionCreatedMsg{sessionID: s.ID}
		}
	}
	if !m.hasSession() || m.com.App.Scans == nil {
		return util.ReportWarn("Use /scan new to open a scan session first")
	}
	action, rest, _ := strings.Cut(strings.TrimSpace(input), " ")
	rest = strings.TrimSpace(rest)
	if rest == "" && action != "list" {
		return util.ReportWarn(scanHelp)
	}
	app := m.com.App
	sessionID := m.session.ID
	subject := activeCapabilitySubject(app.AgentCoordinator.ActiveAgentID())
	switch action {
	case "list":
		return func() tea.Msg {
			records, err := app.Scans.List(sessionID)
			if err != nil {
				return util.NewErrorMsg(err)
			}
			text := scanHelp + "\n\n"
			for _, r := range records {
				text += fmt.Sprintf("%s  %s  %s\n", r.ID, r.State, r.Directory)
			}
			return scanViewMsg{text: text}
		}
	case "authorize", "revoke":
		return func() tea.Msg {
			_, target, err := scan.Target(rest)
			if err != nil {
				return util.NewErrorMsg(err)
			}
			command := capabilityControlCommand{capability: "security:scan", target: target, ttl: defaultCapabilityTTL}
			if action == "authorize" {
				return authorizeSessionCapability(app.SecOpsPermissions, sessionID, subject, command)
			}
			return revokeSessionCapability(app.SecOpsPermissions, sessionID, subject, command)
		}
	case "run":
		return func() tea.Msg {
			r, err := app.Scans.Prepare(context.Background(), sessionID, subject, rest)
			return scanPreparedMsg{record: r, err: err}
		}
	case "cancel":
		return func() tea.Msg {
			if err := app.Scans.Cancel(sessionID, rest); err != nil {
				return util.NewErrorMsg(err)
			}
			return util.NewInfoMsg("Scan cancellation requested: " + rest)
		}
	case "show":
		return func() tea.Msg {
			r, err := app.Scans.Get(sessionID, rest)
			if err != nil {
				return util.NewErrorMsg(err)
			}
			snapshot := workbench.Snapshot{Tasks: []workbench.Task{{ID: r.ID, Title: r.Directory, State: r.State, CurrentAgent: r.Subject, CurrentSkill: "trivy"}}}
			text := fmt.Sprintf("Target: %s\nState: %s\nError: %s\n", r.Directory, r.State, r.Error)
			if r.EvidenceID != "" {
				item, raw, err := app.ComputerRuntime.EvidenceStore.GetEvidence(context.Background(), r.EvidenceID)
				if err != nil {
					return util.NewErrorMsg(err)
				}
				snapshot.Evidence = []workbench.EvidenceItem{{ID: item.ID, TaskID: r.ID, Source: item.Source.Type, Trust: string(item.TrustLevel), Completeness: string(item.Completeness), ContentHash: item.ContentHash}}
				var out interface{}
				if err := json.Unmarshal(raw, &out); err != nil {
					return util.NewErrorMsg(err)
				}
				pretty, _ := json.MarshalIndent(out, "", "  ")
				text += "\nScanner evidence:\n" + string(pretty) + "\n"
			}
			component := workbenchview.New()
			component.SetSnapshot(snapshot)
			component.SetView(workbenchview.ViewTask)
			text = component.Render(120) + "\n" + text
			component.SetView(workbenchview.ViewEvidence)
			text += "\n" + component.Render(120)
			if r.State == "reviewed" {
				report, err := app.Scans.Report(context.Background(), sessionID, r.ID)
				if err != nil {
					return util.NewErrorMsg(err)
				}
				data, _ := json.MarshalIndent(report, "", "  ")
				text += "\nReviewed report:\n" + string(data)
			}
			text += "\n" + scanHelp
			return scanViewMsg{text: text}
		}
	case "report":
		return func() tea.Msg {
			report, err := app.Scans.Report(context.Background(), sessionID, rest)
			if err != nil {
				return util.NewErrorMsg(err)
			}
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return util.NewErrorMsg(err)
			}
			return scanViewMsg{text: "Reviewed report:\n" + string(data)}
		}
	case "review":
		id, remaining, _ := strings.Cut(rest, " ")
		verdict, reason, _ := strings.Cut(strings.TrimSpace(remaining), " ")
		return func() tea.Msg {
			_, err := app.Scans.Review(context.Background(), sessionID, id, evidence.Verdict(verdict), reason)
			if err != nil {
				return util.NewErrorMsg(err)
			}
			return util.NewInfoMsg("Review recorded. Use /scan show " + id + " to inspect the result")
		}
	default:
		return util.ReportWarn(scanHelp)
	}
}

func (m *UI) handleScanPrepared(msg scanPreparedMsg) tea.Cmd {
	if msg.err != nil {
		return util.ReportError(msg.err)
	}
	app := m.com.App
	return tea.Batch(util.ReportInfo("Scan started: "+msg.record.ID+"; /scan cancel "+msg.record.ID), func() tea.Msg {
		record, err := app.RunScan(context.Background(), msg.record.SessionID, msg.record.ID)
		if err != nil {
			return util.NewErrorMsg(fmt.Errorf("scan %s: %w", record.ID, err))
		}
		return util.NewInfoMsg("Scan awaits review: /scan show " + record.ID)
	})
}

func (m *UI) showScanView(msg scanViewMsg) { m.dialog.OpenDialog(dialog.NewScanReport(msg.text)) }
