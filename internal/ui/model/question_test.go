package model

import (
	"testing"

	"github.com/chenchunrun/SecOps/internal/app"
	"github.com/chenchunrun/SecOps/internal/investigation/scan"
	"github.com/chenchunrun/SecOps/internal/question"
	"github.com/chenchunrun/SecOps/internal/session"
	"github.com/chenchunrun/SecOps/internal/ui/common"
	"github.com/chenchunrun/SecOps/internal/ui/dialog"
	"github.com/chenchunrun/SecOps/internal/ui/util"
	"github.com/stretchr/testify/require"
)

func TestScanFormStaleAndCanceled(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"session", "role", "cancel"} {
		ui := &UI{com: &common.Common{App: &app.App{Scans: &scan.Service{}, AgentCoordinator: scanTestCoordinator{}}}, session: &session.Session{ID: "original"}, dialog: dialog.NewOverlay()}
		require.Nil(t, ui.openScanForm("authorize"))
		r := ui.scanForm.request
		switch mode {
		case "session":
			ui.session = &session.Session{ID: "other"}
		case "role":
			ui.scanForm.subject = "different-role"
		}
		response := dialog.ActionQuestionResponse{ID: r.ID, SessionID: r.SessionID, Answers: question.Answers{"directory": {"/tmp/project"}}, Canceled: mode == "cancel"}
		cmd := ui.handleQuestionResponse(response)
		if mode == "cancel" {
			require.Nil(t, cmd)
		} else {
			require.Equal(t, util.InfoTypeWarn, cmd().(util.InfoMsg).Type)
		}
		require.Nil(t, ui.scanForm)
		require.False(t, ui.dialog.HasDialogs())
		require.Nil(t, ui.handleQuestionResponse(response), "replayed form must not trigger an operation")
	}
}

func TestScanFormCommandValidation(t *testing.T) {
	t.Parallel()
	command, err := scanFormCommand("run", question.Answers{"directory": {"/tmp/project with spaces"}})
	require.NoError(t, err)
	require.Equal(t, "run /tmp/project with spaces", command)
	_, err = scanFormCommand("review", question.Answers{"id": {"id"}, "verdict": {"approve"}, "reason": {"checked"}})
	require.Error(t, err)
	_, err = scanFormCommand("review", question.Answers{"id": {"id passed"}, "verdict": {"passed"}, "reason": {"checked"}})
	require.Error(t, err)
}
