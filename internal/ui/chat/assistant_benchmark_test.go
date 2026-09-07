package chat

import (
	"strconv"
	"strings"
	"testing"

	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
)

var assistantBenchmarkOutput string

func BenchmarkAssistantCollapsedReasoning(b *testing.B) {
	for _, size := range []int{16 * 1024, 128 * 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			sty := styles.DefaultStyles()
			thinking := strings.Repeat("Reviewing package evidence and checking dependencies. ", size/53+1)
			msg := &message.Message{ID: "bench", Parts: []message.ContentPart{message.ReasoningContent{Thinking: thinking}}}
			item := NewAssistantMessageItem(&sty, msg, true).(*AssistantMessageItem)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				assistantBenchmarkOutput = item.renderThinking(thinking+strconv.Itoa(i), 100)
			}
		})
	}
}

func BenchmarkAssistantBodyAfterReasoning(b *testing.B) {
	sty := styles.DefaultStyles()
	thinking := strings.Repeat("Verified the evidence against the inventory.\n\n", 2000)
	msg := &message.Message{ID: "bench", Parts: []message.ContentPart{message.ReasoningContent{Thinking: thinking}, message.TextContent{Text: "Report"}}}
	item := NewAssistantMessageItem(&sty, msg, true).(*AssistantMessageItem)
	item.RawRender(100)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		next := *msg
		next.Parts = []message.ContentPart{message.ReasoningContent{Thinking: thinking}, message.TextContent{Text: "Report " + strconv.Itoa(i)}}
		item.SetMessage(&next)
		assistantBenchmarkOutput = item.RawRender(100)
	}
}
