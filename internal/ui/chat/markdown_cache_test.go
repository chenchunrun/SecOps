package chat

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/ui/common"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
	"github.com/stretchr/testify/require"
)

func TestLiveThinkingTail(t *testing.T) {
	t.Parallel()
	source := "\x1b[31m" + strings.Repeat("中文🙂", 2000) + "END\x1b[0m"
	tail := liveThinkingTail(source)
	require.True(t, utf8.ValidString(tail))
	require.LessOrEqual(t, len(tail), liveThinkingPreviewBytes)
	require.NotContains(t, tail, "\x1b")
	require.True(t, strings.HasSuffix(tail, "END"))
	require.Equal(t, "short", liveThinkingTail("short"))
}

func TestThinkingPreviewTransitions(t *testing.T) {
	t.Parallel()
	sty := styles.DefaultStyles()
	source := "BEGIN\n\n" + strings.Repeat("中文 evidence\n", 800) + "\nEND"
	msg := &message.Message{ID: "test", Parts: []message.ContentPart{message.ReasoningContent{Thinking: source}}}
	item := NewAssistantMessageItem(&sty, msg, true).(*AssistantMessageItem)
	preview := ansi.Strip(item.RawRender(80))
	require.Contains(t, preview, "live plain-text preview")
	require.Contains(t, preview, "END")
	require.NotContains(t, preview, "BEGIN")
	require.Equal(t, source, msg.ReasoningContent().Thinking)
	item.ToggleExpanded()
	expanded := ansi.Strip(item.RawRender(80))
	require.Contains(t, expanded, "BEGIN")
	require.Contains(t, expanded, "END")
	require.NotContains(t, expanded, "live plain-text preview")
	item.ToggleExpanded()
	for _, finish := range []message.FinishReason{message.FinishReasonCanceled, message.FinishReasonError} {
		next := *msg
		next.Parts = append([]message.ContentPart{message.ReasoningContent{Thinking: source}}, message.Finish{Reason: finish})
		item.SetMessage(&next)
		require.NotContains(t, ansi.Strip(item.RawRender(80)), "live plain-text preview")
		require.Equal(t, source, next.ReasoningContent().Thinking)
	}
}

func TestThinkingFullRenderingCompatibility(t *testing.T) {
	t.Parallel()
	sty := styles.DefaultStyles()
	for _, width := range []int{12, 80} {
		for _, source := range []string{"short", strings.Repeat("- **中文 evidence**\n", 20), "```go\n" + strings.Repeat("var x = 1\n", 20) + "```", "| A | B |\n|---|---|\n" + strings.Repeat("| one | two |\n", 20)} {
			msg := &message.Message{Parts: []message.ContentPart{message.ReasoningContent{Thinking: source}, message.TextContent{Text: "Report"}}}
			item := NewAssistantMessageItem(&sty, msg, true).(*AssistantMessageItem)
			for _, expanded := range []bool{false, true} {
				item.thinkingExpanded = expanded
				full, err := common.PlainMarkdownRenderer(&sty, width).Render(source)
				require.NoError(t, err)
				lines := strings.Split(strings.TrimSpace(full), "\n")
				want := strings.Join(lines, "\n")
				if !expanded && len(lines) > maxCollapsedThinkingHeight {
					want = sty.Chat.Message.ThinkingTruncationHint.Render(fmt.Sprintf(assistantMessageTruncateFormat, len(lines)-maxCollapsedThinkingHeight)) + "\n\n" + strings.Join(lines[len(lines)-maxCollapsedThinkingHeight:], "\n")
				}
				require.Equal(t, sty.Chat.Message.ThinkingBox.Width(width).Render(want), item.renderThinking(source, width))
			}
		}
	}
}

func TestMarkdownSectionCache(t *testing.T) {
	t.Parallel()
	sty := styles.DefaultStyles()
	var cache markdownSectionCache
	first := cache.render(&sty, "**hello**", 80, true)
	require.True(t, cache.valid)
	require.Equal(t, first, cache.render(&sty, "**hello**", 80, true))
	for _, plain := range []bool{false, true} {
		got := cache.render(&sty, "new **content**", 20, plain)
		var fresh markdownSectionCache
		require.Equal(t, fresh.render(&sty, "new **content**", 20, plain), got)
		require.Equal(t, 20, cache.width)
		require.Equal(t, plain, cache.plain)
	}
	other := styles.DefaultStyles()
	cache.render(&other, "new **content**", 20, true)
	require.Same(t, &other, cache.sty)
	cache.render(&sty, strings.Repeat("x", maxMarkdownSectionCacheBytes+1), 80, true)
	require.False(t, cache.valid)
	require.Empty(t, cache.source)
	require.Empty(t, cache.rendered)
}

func TestAnswerUpdatesReuseReasoning(t *testing.T) {
	t.Parallel()
	sty := styles.DefaultStyles()
	source := strings.Repeat("Evidence verified.\n", 30)
	msg := &message.Message{ID: "test", Parts: []message.ContentPart{message.ReasoningContent{Thinking: source}, message.TextContent{Text: "Report"}}}
	item := NewAssistantMessageItem(&sty, msg, true).(*AssistantMessageItem)
	item.RawRender(80)
	require.True(t, item.thinkingMarkdown.valid)
	// A sentinel distinguishes reuse from reparsing the same source.
	item.thinkingMarkdown.rendered = "cached reasoning sentinel"
	next := *msg
	next.Parts = []message.ContentPart{message.ReasoningContent{Thinking: source}, message.TextContent{Text: "Updated report"}}
	item.SetMessage(&next)
	output := ansi.Strip(item.RawRender(80))
	require.Contains(t, output, "cached reasoning sentinel")
	require.Contains(t, output, "Updated report")
	require.NotContains(t, ansi.Strip(item.RawRender(40)), "cached reasoning sentinel")
}
