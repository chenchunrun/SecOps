package tools

import (
	"context"
	"testing"

	"charm.land/fantasy"
	"github.com/chenchunrun/SecOps/internal/question"
	"github.com/stretchr/testify/require"
)

func TestQuestionToolStrictParametersAndHeadless(t *testing.T) {
	t.Parallel()
	require.Empty(t, BuildInteractionToolSet(nil))
	tool := BuildInteractionToolSet(question.New())[0]
	require.Equal(t, QuestionToolName, tool.Info().Name)
	for _, input := range []string{`null`, `{"fields":[]}`, `{"fields":[],"approve":true}`, `{"fields":[{"id":"x","prompt":"x","kind":"text","secret":true}]}`} {
		_, err := tool.Run(t.Context(), fantasy.ToolCall{Input: input})
		require.Error(t, err)
	}
	ctx := context.WithValue(t.Context(), SessionIDContextKey, "session")
	_, err := tool.Run(ctx, fantasy.ToolCall{Input: `{"fields":[{"id":"x","prompt":"x","kind":"text"}]}`})
	require.ErrorContains(t, err, "unavailable")
}

func TestQuestionToolRoundTrip(t *testing.T) {
	t.Parallel()
	service := question.New()
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), SessionIDContextKey, "session"))
	defer cancel()
	events := service.Subscribe(ctx)
	service.Enable()
	tool := BuildInteractionToolSet(service)[0]
	go func() {
		r := (<-events).Payload
		_ = service.Respond(r.ID, r.SessionID, question.Answers{"x": {"answer"}}, false)
	}()
	response, err := tool.Run(ctx, fantasy.ToolCall{Input: `{"fields":[{"id":"x","prompt":"x","kind":"text"}]}`})
	require.NoError(t, err)
	require.JSONEq(t, `{"x":["answer"]}`, response.Content)
}
