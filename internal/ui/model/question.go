package model

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/chenchunrun/SecOps/internal/question"
	"github.com/chenchunrun/SecOps/internal/ui/dialog"
	"github.com/chenchunrun/SecOps/internal/ui/util"
	"github.com/google/uuid"
)

type scanFormBinding struct {
	request question.Request
	subject string
	action  string
}

func (m *UI) handleQuestion(request question.Request) {
	service := m.com.App.Questions
	if service == nil {
		return
	}
	if request.Closed {
		m.dialog.CloseDialog("question-" + request.ID)
		return
	}
	if !service.Active(request.ID) {
		return
	}
	if !m.hasSession() || m.session.ID != request.SessionID {
		_ = service.Respond(request.ID, request.SessionID, nil, true)
		return
	}
	if !m.dialog.ContainsDialog("question-" + request.ID) {
		m.dialog.OpenDialog(dialog.NewQuestion(request))
	}
}

func scanFormFields(action string) []question.Field {
	switch action {
	case "":
		return []question.Field{{ID: "action", Prompt: "Choose a scan operation", Kind: "single", Options: []string{"authorize", "run", "show", "review", "report", "revoke", "list", "cancel"}}}
	case "authorize", "run", "revoke":
		return []question.Field{{ID: "directory", Prompt: "Exact local directory (authorization is checked separately)", Kind: "text"}}
	case "review":
		return []question.Field{
			{ID: "id", Prompt: "Scan ID — inspect /scan show before reviewing", Kind: "text"},
			{ID: "verdict", Prompt: "Independent review decision", Kind: "single", Options: []string{"passed", "rejected"}},
			{ID: "reason", Prompt: "Review evidence and explain your decision", Kind: "text"},
		}
	case "report", "show", "cancel":
		return []question.Field{{ID: "id", Prompt: "Scan ID", Kind: "text"}}
	default:
		return nil
	}
}

func (m *UI) openScanForm(action string) tea.Cmd {
	if m.scanForm != nil {
		return util.ReportWarn("Finish or cancel the current scan form first")
	}
	if m.com.App.Scans == nil {
		return util.ReportWarn("Scan workflow unavailable")
	}
	if !m.hasSession() {
		create := m.applyScanCommand("new")
		return func() tea.Msg {
			msg := create()
			if created, ok := msg.(scanSessionCreatedMsg); ok {
				created.openForm = true
				return created
			}
			return msg
		}
	}
	fields := scanFormFields(action)
	if len(fields) == 0 {
		return util.ReportWarn("Use /scan form or /scan form authorize|run|review|report|revoke")
	}
	r := question.Request{ID: uuid.NewString(), SessionID: m.session.ID, Fields: fields}
	m.scanForm = &scanFormBinding{request: r, subject: activeCapabilitySubject(m.com.App.AgentCoordinator.ActiveAgentID()), action: action}
	m.dialog.OpenDialog(dialog.NewQuestion(r))
	return nil
}

func scanFormCommand(action string, answers question.Answers) (string, error) {
	if err := question.ValidateAnswers(scanFormFields(action), answers); err != nil {
		return "", err
	}
	switch action {
	case "authorize", "run", "revoke":
		return action + " " + answers["directory"][0], nil
	case "review", "report", "show", "cancel":
		id := strings.TrimSpace(answers["id"][0])
		if strings.ContainsAny(id, " \t\r\n") {
			return "", fmt.Errorf("scan ID cannot contain whitespace")
		}
		if action != "review" {
			return action + " " + id, nil
		}
		return "review " + id + " " + answers["verdict"][0] + " " + answers["reason"][0], nil
	default:
		return "", fmt.Errorf("unsupported scan form operation")
	}
}

func (m *UI) handleQuestionResponse(response dialog.ActionQuestionResponse) tea.Cmd {
	m.dialog.CloseDialog("question-" + response.ID)
	if binding := m.scanForm; binding != nil && binding.request.ID == response.ID {
		m.scanForm = nil
		if response.Canceled {
			return nil
		}
		if !m.hasSession() || m.session.ID != binding.request.SessionID || response.SessionID != binding.request.SessionID || activeCapabilitySubject(m.com.App.AgentCoordinator.ActiveAgentID()) != binding.subject {
			return util.ReportWarn("Session or role changed; reopen the scan form")
		}
		if err := question.ValidateAnswers(binding.request.Fields, response.Answers); err != nil {
			return util.ReportError(err)
		}
		if binding.action == "" {
			action := response.Answers["action"][0]
			if action == "list" {
				return m.applyScanCommand("list")
			}
			return m.openScanForm(action)
		}
		command, err := scanFormCommand(binding.action, response.Answers)
		if err != nil {
			return util.ReportError(err)
		}
		// Reuse the existing authorization, approval, evidence and review chain.
		return m.applyScanCommand(command)
	}
	if service := m.com.App.Questions; service != nil {
		if !m.hasSession() || m.session.ID != response.SessionID {
			response.Canceled = true
		}
		if err := service.Respond(response.ID, response.SessionID, response.Answers, response.Canceled); err != nil {
			return util.ReportError(err)
		}
	}
	return nil
}
