package execution

import (
	"context"
	"errors"

	"github.com/chenchunrun/SecOps/internal/shell"
)

type LocalRequest struct {
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

type LocalHandler func(ctx context.Context, req LocalRequest) (LocalResult, error)

type LocalMiddleware func(next LocalHandler) LocalHandler

type LocalErrorKind string

const (
	LocalErrorKindStart     LocalErrorKind = "start"
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
