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
	lines  int
	page   int
}

func NewScanReport(text string) *ScanReport { return &ScanReport{text: ansi.Strip(text)} }
func (*ScanReport) ID() string              { return "scan-report" }
func (d *ScanReport) HandleMsg(msg tea.Msg) Action {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		switch key.String() {
		case "esc":
			return ActionClose{}
		case "down", "j":
			d.offset = min(d.offset+1, max(0, d.lines-1))
		case "up", "k":
			d.offset = max(0, d.offset-1)
		case "pgdown", "ctrl+f":
			d.offset = min(d.offset+max(1, d.page), max(0, d.lines-1))
		case "pgup", "ctrl+b":
			d.offset = max(0, d.offset-max(1, d.page))
		case "home":
			d.offset = 0
		case "end":
			d.offset = max(0, d.lines-max(1, d.page))
		}
	}
	return nil
}

func (d *ScanReport) Draw(scr uv.Screen, area uv.Rectangle) *tea.Cursor {
	lines := strings.Split(ansi.Hardwrap(d.text, max(1, area.Dx()-2), true), "\n")
	d.lines, d.page = len(lines), max(1, area.Dy()-2)
	lines = lines[min(d.offset, len(lines)):]
	lines = lines[:min(len(lines), max(0, area.Dy()-2))]
	for i := range lines {
		lines[i] = ansi.Truncate(lines[i], max(0, area.Dx()-2), "…")
	}
	uv.NewStyledString("Scan workbench — ↑/↓ scroll, PgUp/PgDn page, Home/End, Esc close\n"+strings.Join(lines, "\n")).Draw(scr, area)
	return nil
}
