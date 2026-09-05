package dialog

import (
	"image"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/stretchr/testify/require"
)

func TestScanReportWrapsAndPages(t *testing.T) {
	t.Parallel()
	report := NewScanReport(strings.Repeat("long evidence text ", 50) + "\nLAST-LINE")
	screen := uv.NewScreenBuffer(40, 10)
	report.Draw(screen, image.Rect(0, 0, 40, 10))
	require.Greater(t, report.lines, 10)
	report.HandleMsg(tea.KeyPressMsg{Code: tea.KeyPgDown})
	require.Equal(t, 8, report.offset)
	report.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEnd})
	report.Draw(screen, image.Rect(0, 0, 40, 10))
	require.Contains(t, screen.Render(), "LAST-LINE")
	report.HandleMsg(tea.KeyPressMsg{Code: tea.KeyHome})
	require.Zero(t, report.offset)
	require.IsType(t, ActionClose{}, report.HandleMsg(tea.KeyPressMsg{Code: tea.KeyEscape}))
}
