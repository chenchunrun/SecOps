package dialog

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
)

// ScanReport displays durable scan state and evidence for explicit review.
type ScanReport struct {
	text   string
	offset int
}

func NewScanReport(text string) *ScanReport { return &ScanReport{text: ansi.Strip(text)} }
func (*ScanReport) ID() string              { return "scan-report" }
func (d *ScanReport) HandleMsg(msg tea.Msg) Action {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			return ActionClose{}
		case "down", "j":
			d.offset = min(d.offset+1, max(0, strings.Count(d.text, "\n")))
		case "up", "k":
			d.offset = max(0, d.offset-1)
		}
	}
	return nil
}

func (d *ScanReport) Draw(scr uv.Screen, area uv.Rectangle) *tea.Cursor {
	lines := strings.Split(d.text, "\n")
	lines = lines[min(d.offset, len(lines)):]
	lines = lines[:min(len(lines), max(0, area.Dy()-2))]
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], max(0, area.Dx()-2), "…")
	}
	uv.NewStyledString("Scan workbench — ↑/↓ scroll, Esc close\n"+strings.Join(lines, "\n")).Draw(scr, area)
	return nil
}
