package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/chenchunrun/SecOps/internal/egress"
	"github.com/chenchunrun/SecOps/internal/taskruntime"
)

type protectedObserver struct {
	events []egress.Event
	err    error
}

func (o *protectedObserver) Record(_ context.Context, event egress.Event) error {
	o.events = append(o.events, event)
	return o.err
}

func TestProtectedRuntimeAuditsEgressBeforeTaskPersistence(t *testing.T) {
	t.Parallel()

	computerRuntime, runtimeScheduler, _ := newProtectedTestRuntime(t, "secret")
	policy, err := egress.NewPolicy([]egress.Rule{{
		ID:             "github-api",
		Protocol:       egress.ProtocolHTTPS,
		Host:           "api.github.com",
		Ports:          []int{443},
		CredentialRefs: []string{"github/actions"},
	}})
	require.NoError(t, err)
	broker, err := egress.NewBroker(&protectedSource{value: []byte("secret")}, time.Minute)
	require.NoError(t, err)
	observer := &protectedObserver{}
	protectedRuntime, err := NewProtectedScheduledTaskRuntime(
		computerRuntime,
		runtimeScheduler,
		policy,
		broker,
		WithEgressObserver(observer),
	)
	require.NoError(t, err)

	result, err := protectedRuntime.SubmitAndRun(context.Background(), validProtectedSubmission("audited-task"))
	require.NoError(t, err)
	require.Equal(t, taskruntime.StateSucceeded, result.Task.State)
	require.Len(t, observer.events, 1)
	require.Equal(t, "audited-task", observer.events[0].RequestID)
	require.True(t, observer.events[0].Decision.Allowed)
}

func TestProtectedRuntimeFailsClosedWhenEgressAuditFails(t *testing.T) {
	t.Parallel()

	computerRuntime, runtimeScheduler, _ := newProtectedTestRuntime(t, "secret")
	policy, err := egress.NewPolicy([]egress.Rule{{
		ID:             "github-api",
		Protocol:       egress.ProtocolHTTPS,
		Host:           "api.github.com",
		Ports:          []int{443},
		CredentialRefs: []string{"github/actions"},
	}})
	require.NoError(t, err)
	source := &protectedSource{value: []byte("secret")}
	broker, err := egress.NewBroker(source, time.Minute)
	require.NoError(t, err)
	auditFailure := errors.New("audit unavailable")
	protectedRuntime, err := NewProtectedScheduledTaskRuntime(
		computerRuntime,
		runtimeScheduler,
		policy,
		broker,
		WithEgressObserver(&protectedObserver{err: auditFailure}),
	)
	require.NoError(t, err)

	submission := validProtectedSubmission("audit-failed-task")
	result, err := protectedRuntime.SubmitAndRun(context.Background(), submission)
	require.ErrorIs(t, err, auditFailure)
	require.Empty(t, result.Task.ID)
	require.Equal(t, 0, source.calls)
	_, err = computerRuntime.Tasks.Get(context.Background(), submission.Task.ID)
	require.ErrorIs(t, err, taskruntime.ErrNotFound)
}
