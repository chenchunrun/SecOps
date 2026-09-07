package chat

import (
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
	"github.com/chenchunrun/SecOps/internal/ui/common"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
)

const (
	liveThinkingPreviewBytes     = 8 * 1024
	maxMarkdownSectionCacheBytes = 512 * 1024
)

// markdownSectionCache avoids reparsing an unchanged section when a different
// section of the same message streams. It owns at most one bounded entry.
type markdownSectionCache struct {
	source   string
	rendered string
	width    int
	sty      *styles.Styles
	plain    bool
	valid    bool
}

func (c *markdownSectionCache) render(sty *styles.Styles, source string, width int, plain bool) string {
	if c.valid && c.width == width && c.sty == sty && c.plain == plain && c.source == source {
		return c.rendered
	}
	var result string
	var err error
	if plain {
		result, err = common.PlainMarkdownRenderer(sty, width).Render(source)
	} else {
		result, err = common.MarkdownRenderer(sty, width).Render(source)
	}
	if err != nil {
		result = source
	}
	*c = markdownSectionCache{}
	if len(source)+len(result) <= maxMarkdownSectionCacheBytes {
		*c = markdownSectionCache{source: strings.Clone(source), rendered: result, width: width, sty: sty, plain: plain, valid: true}
	}
	return result
}

// liveThinkingTail is presentation-only. Strip ANSI before taking a UTF-8 safe
// suffix; never change the message stored in history or sent to the model.
func liveThinkingTail(source string) string {
	clean := ansi.Strip(source)
	start := max(0, len(clean)-liveThinkingPreviewBytes)
	for start < len(clean) && !utf8.RuneStart(clean[start]) {
		start++
	}
	return clean[start:]
}
