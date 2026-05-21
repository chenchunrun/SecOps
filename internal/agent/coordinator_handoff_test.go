package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/chenchunrun/SecOps/internal/config"
	"github.com/chenchunrun/SecOps/internal/message"
	"github.com/chenchunrun/SecOps/internal/pubsub"
	"github.com/stretchr/testify/require"
)

// listOnlyMessages implements message.Service for handoff injection tests.
type listOnlyMessages struct {
	list []message.Message
}

func (l *listOnlyMessages) Subscribe(context.Context) <-chan pubsub.Event[message.Message] {
	ch := make(chan pubsub.Event[message.Message])
	close(ch)
	return ch
}

func (l *listOnlyMessages) Create(context.Context, string, message.CreateMessageParams) (message.Message, error) {
	return message.Message{}, errors.New("unimplemented")
}

func (l *listOnlyMessages) Update(context.Context, message.Message) error {
	return errors.New("unimplemented")
}

func (l *listOnlyMessages) BufferedUpdate(context.Context, message.Message, message.UpdateOptions) error {
	return errors.New("unimplemented")
}

func (l *listOnlyMessages) FlushBufferedUpdate(context.Context) error {
	return errors.New("unimplemented")
}

func (l *listOnlyMessages) Get(context.Context, string) (message.Message, error) {
	return message.Message{}, errors.New("unimplemented")
}

func (l *listOnlyMessages) List(_ context.Context, _ string) ([]message.Message, error) {
	return l.list, nil
}

func (l *listOnlyMessages) ListUserMessages(context.Context, string) ([]message.Message, error) {
	return nil, errors.New("unimplemented")
}

func (l *listOnlyMessages) ListAllUserMessages(context.Context) ([]message.Message, error) {
	return nil, errors.New("unimplemented")
}

func (l *listOnlyMessages) Delete(context.Context, string) error {
	return errors.New("unimplemented")
}

func (l *listOnlyMessages) DeleteSessionMessages(context.Context, string) error {
	return errors.New("unimplemented")
}

func TestPrependStructuredHandoff_injectsMatchingAgentOnce(t *testing.T) {
	t.Parallel()

	handoffJSON := `{"handoff_version":1,"from_agent":"coder","to_agent":"planner","summary":"ctx","followups":[],"touched_paths":[]}`
	md := "```crush-handoff\n" + handoffJSON + "\n```"

	msgs := []message.Message{
		{Role: message.User, ID: "u1"},
		{
			Role: message.Assistant,
			ID:   "a1",
			Parts: []message.ContentPart{
				message.TextContent{Text: "done\n" + md},
			},
		},
	}

	c := &coordinator{
		mainAgentID: config.AgentPlanner,
		messages:    &listOnlyMessages{list: msgs},
	}

	ctx := context.Background()
	out1 := c.prependStructuredHandoff(ctx, "s1", "hello")
	require.Contains(t, out1, "<structured_handoff>")
	require.Contains(t, out1, "hello")

	out2 := c.prependStructuredHandoff(ctx, "s1", "again")
	require.Equal(t, "again", out2)

	cCoder := &coordinator{
		mainAgentID: config.AgentCoder,
		messages:    &listOnlyMessages{list: msgs},
	}
	out3 := cCoder.prependStructuredHandoff(ctx, "s1", "x")
	require.Equal(t, "x", out3)
}
