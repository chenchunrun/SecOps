package common

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
)

// ButtonOpts defines the configuration for a single button
type ButtonOpts struct {
	// Text is the button label
	Text string
	// UnderlineIndex is the 0-based index of the character to underline (-1 for none)
	UnderlineIndex int
	// Selected indicates whether this button is currently selected
	Selected bool
	// Padding inner horizontal padding defaults to 2 if this is 0
	Padding int
}

// Button creates a button with an underlined character and selection state
func Button(t *styles.Styles, opts ButtonOpts) string {
	// Select style based on selection state
	style := t.ButtonBlur
	if opts.Selected {
		style = t.ButtonFocus
	}

	text := opts.Text
	if opts.Padding == 0 {
		opts.Padding = 2
	}

	// the index is out of bound
	runes := []rune(text)
	if opts.UnderlineIndex > -1 && opts.UnderlineIndex > len(runes)-1 {
		opts.UnderlineIndex = -1
	}

	if opts.UnderlineIndex != -1 {
		prefix := string(runes[:opts.UnderlineIndex])
		target := string(runes[opts.UnderlineIndex])
		suffix := string(runes[opts.UnderlineIndex+1:])
		text = prefix + lipgloss.NewStyle().Underline(true).Render(target) + suffix
	}

	return style.Padding(0, opts.Padding).Render(text)
}

// ButtonGroup creates a row of selectable buttons
// Spacing is the separator between buttons
// Use "  " or similar for horizontal layout
// Use "\n"  for vertical layout
// Defaults to "  " (horizontal)
func ButtonGroup(t *styles.Styles, buttons []ButtonOpts, spacing string) string {
	if len(buttons) == 0 {
		return ""
	}

	if spacing == "" {
		spacing = "  "
	}

	parts := make([]string, len(buttons))
	for i, button := range buttons {
		parts[i] = Button(t, button)
	}

	// Vertical layout keeps simple string joining semantics.
	if strings.Contains(spacing, "\n") {
		return strings.Join(parts, spacing)
	}

	// Horizontal layout must join multiline button blocks line-by-line.
	joined := parts[0]
	for i := 1; i < len(parts); i++ {
		joined = lipgloss.JoinHorizontal(lipgloss.Top, joined, spacing, parts[i])
	}
	return joined
}
