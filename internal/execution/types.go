package execution

import (
	"context"
	"errors"

	"github.com/chenchunrun/SecOps/internal/policy"
	"github.com/chenchunrun/SecOps/internal/shell"
)

type LocalRequest struct {
	SessionID           string
	ToolName            string
	PolicyDecision      *policy.Decision
	Command             string
	Description         string
	WorkingDir          string
	RunInBackground     bool
	AutoBackgroundAfter int
	BlockFuncs          []shell.BlockFunc
}

type LocalResult struct {
	Output           string
	WorkingDirectory string
	Background       bool
	ShellID          string
}

type LocalExecutor interface {
	Execute(ctx context.Context, req LocalRequest) (LocalResult, error)
}

type RemoteRequest struct {
	SessionID        string
	ToolName         string
	Command          string
	Description      string
	TargetHost       string
	TargetUser       string
	TargetPort       int
	KeyPath          string
	ProxyJump        string
	RemoteWorkingDir string
	RemoteEnv        string
}

type RemoteResult struct {
	Output           string
	WorkingDirectory string
	RemoteTarget     string
}

type RemoteExecutor interface {
	Execute(ctx context.Context, req RemoteRequest) (RemoteResult, error)
}

type LocalHandler func(ctx context.Context, req LocalRequest) (LocalResult, error)

type LocalMiddleware func(next LocalHandler) LocalHandler

type RemoteHandler func(ctx context.Context, req RemoteRequest) (RemoteResult, error)

type RemoteMiddleware func(next RemoteHandler) RemoteHandler

type LocalErrorKind string

const (
	LocalErrorKindStart     LocalErrorKind = "start"
	LocalErrorKindPolicy    LocalErrorKind = "policy"
	LocalErrorKindCancelled LocalErrorKind = "cancelled"
	LocalErrorKindTimeout   LocalErrorKind = "timeout"
	LocalErrorKindExecution LocalErrorKind = "execution"
)

type LocalExecutionError struct {
	Kind  LocalErrorKind
	Cause error
}

func (e *LocalExecutionError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause == nil {
		return string(e.Kind)
	}
	return e.Cause.Error()
}

func (e *LocalExecutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func IsLocalErrorKind(err error, kind LocalErrorKind) bool {
	var target *LocalExecutionError
	if !errors.As(err, &target) {
		return false
	}
	return target.Kind == kind
}
