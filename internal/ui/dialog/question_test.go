package dialog

import (
	"image"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/chenchunrun/SecOps/internal/question"
	"github.com/stretchr/testify/require"
)

func TestQuestionRequiresExplicitSelectionAndConfirmation(t *testing.T) {
	t.Parallel()
	d := NewQuestion(question.Request{ID: "q", SessionID: "s", Fields: []question.Field{{ID: "choice", Prompt: "Choose", Kind: "single", Options: []string{"yes", "no"}}}})
	require.Empty(t, d.answers)
	d.HandleMsg(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	require.False(t, d.review)
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyDown})
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter})
	require.Equal(t, []string{"no"}, d.answers["choice"])
	d.HandleMsg(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	require.True(t, d.review)
	require.Nil(t, d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter}))
	d.confirmAfter = time.Now().Add(-time.Second)
	action := d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter}).(ActionQuestionResponse)
	require.Equal(t, "s", action.SessionID)
	require.Equal(t, []string{"no"}, action.Answers["choice"])
	require.False(t, action.Canceled)
}

func TestQuestionPasteMultipleChoiceAndCancel(t *testing.T) {
	t.Parallel()
	d := NewQuestion(question.Request{Fields: []question.Field{{ID: "path", Prompt: "Directory", Kind: "text"}, {ID: "checks", Prompt: "Checks", Kind: "multiple", Options: []string{"a", "b"}}}})
	d.HandleMsg(tea.PasteMsg{Content: "/tmp/project with spaces"})
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyTab})
	require.Equal(t, []string{"/tmp/project with spaces"}, d.answers["path"])
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter})
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyDown})
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter})
	require.Equal(t, []string{"a", "b"}, d.answers["checks"])
	d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnter})
	require.Equal(t, []string{"a"}, d.answers["checks"])
	screen := uv.NewScreenBuffer(40, 12)
	require.NotPanics(t, func() { d.Draw(screen, image.Rect(0, 0, 40, 12)) })
	action := d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEscape}).(ActionQuestionResponse)
	require.True(t, action.Canceled)
	require.Nil(t, action.Answers)
}

func TestQuestionReviewPagesOnSmallTerminal(t *testing.T) {
	t.Parallel()
	d := NewQuestion(question.Request{Fields: []question.Field{{ID: "reason", Prompt: "Reason", Kind: "text"}}})
	d.input.SetValue(strings.Repeat("evidence ", 80) + "END-OF-REVIEW")
	d.HandleMsg(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	require.True(t, d.review)
	screen := uv.NewScreenBuffer(40, 10)
	d.Draw(screen, image.Rect(0, 0, 40, 10))
	require.NotContains(t, screen.Render(), "END-OF-REVIEW")
	for range 20 {
		d.HandleMsg(tea.KeyPressMsg{Code: tea.KeyPgDown})
	}
	d.Draw(screen, image.Rect(0, 0, 40, 10))
	require.Contains(t, screen.Render(), "END-OF-REVIEW")
	require.Contains(t, screen.Render(), "Esc: cancel")
	for _, line := range strings.Split(screen.Render(), "\n") {
		require.LessOrEqual(t, ansi.StringWidth(line), 40)
	}
	for _, size := range []image.Point{{1, 1}, {8, 4}, {80, 24}} {
		screen := uv.NewScreenBuffer(size.X, size.Y)
		require.NotPanics(t, func() { d.Draw(screen, image.Rect(0, 0, size.X, size.Y)) })
	}
}
