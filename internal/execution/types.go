package execution

import (
	"context"

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
