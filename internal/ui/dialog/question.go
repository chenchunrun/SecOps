package dialog

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/chenchunrun/SecOps/internal/question"
)

type ActionQuestionResponse struct {
	ID        string
	SessionID string
	Answers   question.Answers
	Canceled  bool
}

// Question collects data only; the caller decides how to process the result.
type Question struct {
	request      question.Request
	answers      question.Answers
	input        textinput.Model
	field        int
	option       int
	review       bool
	offset       int
	confirmAfter time.Time
	err          string
}

func NewQuestion(request question.Request) *Question {
	input := textinput.New()
	input.CharLimit = 4096
	input.Focus()
	return &Question{request: request, answers: question.Answers{}, input: input}
}
func (d *Question) ID() string { return "question-" + d.request.ID }
func (d *Question) saveText() {
	f := d.request.Fields[d.field]
	if f.Kind == "text" {
		d.answers[f.ID] = []string{d.input.Value()}
	}
}

func (d *Question) move(delta int) {
	d.saveText()
	d.field = (d.field + delta + len(d.request.Fields)) % len(d.request.Fields)
	d.option = 0
	d.input.SetValue("")
	f := d.request.Fields[d.field]
	if f.Kind == "text" && len(d.answers[f.ID]) > 0 {
		d.input.SetValue(d.answers[f.ID][0])
	}
}

func (d *Question) HandleMsg(msg tea.Msg) Action {
	if key, ok := msg.(tea.KeyPressMsg); ok {
		if key.String() == "esc" {
			return ActionQuestionResponse{ID: d.request.ID, SessionID: d.request.SessionID, Canceled: true}
		}
		if d.review {
			switch key.String() {
			case "down":
				d.offset++
			case "up":
				d.offset = max(0, d.offset-1)
			case "pgdown":
				d.offset += 8
			case "pgup":
				d.offset = max(0, d.offset-8)
			case "home":
				d.offset = 0
			case "tab", "shift+tab":
				d.review = false
			case "enter":
				if !time.Now().Before(d.confirmAfter) {
					return ActionQuestionResponse{ID: d.request.ID, SessionID: d.request.SessionID, Answers: d.answers}
				}
			}
			return nil
		}
		switch key.String() {
		case "tab":
			d.move(1)
			return nil
		case "shift+tab":
			d.move(-1)
			return nil
		case "ctrl+enter", "ctrl+s":
			d.saveText()
			if err := question.ValidateAnswers(d.request.Fields, d.answers); err != nil {
				d.err = err.Error()
				return nil
			}
			d.err = ""
			d.review = true
			d.offset = 0
			d.confirmAfter = time.Now().Add(350 * time.Millisecond)
			return nil
		}
		f := d.request.Fields[d.field]
		if f.Kind != "text" {
			switch key.String() {
			case "up":
				d.option = max(0, d.option-1)
			case "down":
				d.option = min(len(f.Options)-1, d.option+1)
			case "space", " ", "enter":
				value := f.Options[d.option]
				if f.Kind == "single" {
					d.answers[f.ID] = []string{value}
				} else {
					values := d.answers[f.ID]
					if i := slices.Index(values, value); i >= 0 {
						values = slices.Delete(values, i, i+1)
					} else {
						values = append(values, value)
					}
					d.answers[f.ID] = values
				}
			}
			return nil
		}
	}
	if !d.review && d.request.Fields[d.field].Kind == "text" {
		d.input, _ = d.input.Update(msg)
	}
	return nil
}

func (d *Question) Draw(scr uv.Screen, area uv.Rectangle) *tea.Cursor {
	width := max(1, area.Dx()-2)
	input := d.input
	input.SetWidth(max(1, width-3))
	header := "User input (not permission)"
	footer := "Tab: next · Shift+Tab: back\nCtrl+S: review · Esc: cancel"
	text := ""
	bodyHeight := max(1, area.Dy()-4)
	if d.review {
		header = "Review answers (not permission)"
		footer = "↑/↓/PgUp/PgDn: scroll · Tab: edit\nEnter: submit · Esc: cancel"
		for _, f := range d.request.Fields {
			text += fmt.Sprintf("%s: %s\n", f.Prompt, strings.Join(d.answers[f.ID], ", "))
		}
	} else {
		f := d.request.Fields[d.field]
		text += fmt.Sprintf("Field %d/%d: %s\n", d.field+1, len(d.request.Fields), f.Prompt)
		if f.Kind == "text" {
			text += input.View() + "\n"
		} else {
			// Keep the focused option visible even on small terminals.
			start := max(0, d.option-max(1, bodyHeight-3)+1)
			for i := start; i < len(f.Options); i++ {
				value := f.Options[i]
				cursor, selected := " ", " "
				if i == d.option {
					cursor = ">"
				}
				if slices.Contains(d.answers[f.ID], value) {
					selected = "x"
				}
				text += fmt.Sprintf("%s [%s] %s\n", cursor, selected, value)
			}
		}
		if d.err != "" {
			footer = d.err + "\n" + footer
		}
	}
	lines := strings.Split(ansi.Hardwrap(ansi.Strip(text), width, true), "\n")
	if d.review {
		start := min(d.offset, max(0, len(lines)-bodyHeight))
		lines = lines[start:]
	}
	lines = lines[:min(len(lines), bodyHeight)]
	out := []string{ansi.Truncate(header, width, "…")}
	out = append(out, lines...)
	for len(out) < max(1, area.Dy()-3) {
		out = append(out, "")
	}
	for _, line := range strings.Split(footer, "\n") {
		out = append(out, ansi.Truncate(ansi.Strip(line), width, "…"))
	}
	out = out[:min(len(out), max(0, area.Dy()))]
	uv.NewStyledString(strings.Join(out, "\n")).Draw(scr, area)
	return nil
}
