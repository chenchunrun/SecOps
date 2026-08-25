package chat

import (
	"strings"
	"testing"

	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/ui/styles"
)

func TestDefaultToolRenderContextUsesGenericRenderer(t *testing.T) {
	t.Parallel()

	sty := styles.DefaultStyles()
	result := &message.ToolResult{
		ToolCallID: "tool-1",
		Name:       "custom_security_check",
		Content:    `{"status":"pass"}`,
	}
	opts := &ToolRenderOpts{
		ToolCall: message.ToolCall{
			ID:       "tool-1",
			Name:     "custom_security_check",
			Input:    `{"target":"host-1"}`,
			Finished: true,
		},
		Result: result,
		Status: ToolStatusSuccess,
	}

	rendered := (&DefaultToolRenderContext{}).RenderTool(&sty, 100, opts)
	if !strings.Contains(rendered, "Custom Security Check") {
		t.Fatalf("expected generic tool title, got %q", rendered)
	}
	if strings.Contains(rendered, "TODO") {
		t.Fatalf("expected production fallback renderer, got %q", rendered)
	}
}
