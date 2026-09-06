package question

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testFields() []Field {
	return []Field{{ID: "scope", Prompt: "Scope", Kind: "single", Options: []string{"local", "remote"}}}
}

func TestQuestionLifecycle(t *testing.T) {
	t.Parallel()
	s := New()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := s.Ask(ctx, "session", testFields())
	require.ErrorContains(t, err, "unavailable")
	events := s.Subscribe(ctx)
	s.Enable()
	result := make(chan Answers, 1)
	errors := make(chan error, 1)
	go func() { answers, err := s.Ask(ctx, "session", testFields()); result <- answers; errors <- err }()
	r := (<-events).Payload
	require.Error(t, s.Respond(r.ID, "other", Answers{"scope": {"local"}}, false))
	require.Error(t, s.Respond(r.ID, "session", Answers{"scope": {"invented"}}, false))
	require.True(t, s.Active(r.ID))
	require.NoError(t, s.Respond(r.ID, "session", Answers{"scope": {"local"}}, false))
	require.Error(t, s.Respond(r.ID, "session", Answers{"scope": {"remote"}}, false))
	require.NoError(t, <-errors)
	require.Equal(t, Answers{"scope": {"local"}}, <-result)
	require.True(t, (<-events).Payload.Closed)
	require.False(t, s.Active(r.ID))
}

func TestQuestionCancellation(t *testing.T) {
	t.Parallel()
	for _, userCancel := range []bool{true, false} {
		s := New()
		s.Enable()
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		events := s.Subscribe(ctx)
		done := make(chan error, 1)
		go func() { _, err := s.Ask(ctx, "s", testFields()); done <- err }()
		r := (<-events).Payload
		if userCancel {
			require.NoError(t, s.Respond(r.ID, "s", nil, true))
		} else {
			cancel()
		}
		require.ErrorIs(t, <-done, context.Canceled)
		require.False(t, s.Active(r.ID))
		cancel()
	}
}

func TestValidationRejectsAmbiguousQuestions(t *testing.T) {
	t.Parallel()
	for _, fields := range [][]Field{nil, {{ID: "x", Prompt: "x", Kind: "unknown"}}, {{ID: "x", Prompt: "x", Kind: "single", Options: []string{"a", "a"}}}, {{ID: "x", Prompt: "x", Kind: "single", Options: []string{"a", "\x1b[31mb"}}}} {
		require.Error(t, ValidateFields(fields))
	}
	for _, answers := range []Answers{nil, {"scope": {"local", "local"}}, {"scope": {"local"}, "approval": {"yes"}}} {
		require.Error(t, ValidateAnswers(testFields(), answers))
	}
}
